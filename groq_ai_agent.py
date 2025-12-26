import os
import json
import subprocess
import nmap
from groq import Groq

# --- CONFIGURATION ---
# Get your free key at: https://console.groq.com/keys
os.environ["GROQ_API_KEY"] = "$GROQ"

client = Groq(
    api_key=os.environ.get("GROQ_API_KEY"),
)

# Use Llama 3.3 for best tool-use performance
MODEL_ID = "llama-3.3-70b-versatile"

# ==========================================
#  1. DEFINE THE PYTHON FUNCTIONS
# ==========================================

def run_nmap_scan(target, scan_type="quick"):
    """
    Executes an Nmap scan. 
    scan_type: 'quick' (Top 100 ports) or 'full' (Service Version detection).
    """
    print(f"\n[Tool] Running Nmap ({scan_type}) on {target}...")
    nm = nmap.PortScanner()
    try:
        if scan_type == "quick":
            nm.scan(hosts=target, arguments='-F')
        else:
            nm.scan(hosts=target, arguments='-sV -p 21,22,80,443,3306,8080')
        return nm.csv()
    except Exception as e:
        return f"Nmap Error: {e}"

def run_nuclei_scan(target_url):
    """
    Runs Nuclei vulnerability scanner on a URL.
    """
    print(f"\n[Tool] Running Nuclei on {target_url}...")
    command = ["nuclei", "-u", target_url, "-t", "cves/,vulnerabilities/", "-json", "-silent"]
    try:
        # Timeout set to 2 minutes for demo purposes
        result = subprocess.run(command, capture_output=True, text=True, timeout=120)
        output = result.stdout
        # Summarize output if it's too huge
        if not output: return "Nuclei finished. No critical vulnerabilities found in default template."
        return output[:4000] # Limit tokens
    except Exception as e:
        return f"Nuclei Error: {e}"

def run_gobuster(target_url):
    """
    Runs Gobuster to find hidden directories.
    """
    print(f"\n[Tool] Running Gobuster on {target_url}...")
    command = [
        "gobuster", "dir", "-u", target_url, 
        "-w", "/usr/share/wordlists/dirb/common.txt", 
        "-z", "--no-error", "-q"
    ]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=60)
        return result.stdout if result.stdout else "No hidden directories found."
    except Exception as e:
        return f"Gobuster Error: {e} (Check if wordlist exists)"

# ==========================================
#  2. DEFINE THE TOOLS SCHEMA (JSON)
# ==========================================
# Groq requires us to define tools explicitly in JSON format.

tools_schema = [
    {
        "type": "function",
        "function": {
            "name": "run_nmap_scan",
            "description": "Scan a network IP for open ports.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "IP or Domain (e.g. 192.168.1.1)"},
                    "scan_type": {"type": "string", "enum": ["quick", "full"]}
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "run_nuclei_scan",
            "description": "Scan a web URL for vulnerabilities (CVEs). Use this if port 80/443 is open.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target_url": {"type": "string", "description": "The full URL (http://...)"}
                },
                "required": ["target_url"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "run_gobuster",
            "description": "Brute-force directory search to find hidden paths.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target_url": {"type": "string", "description": "The full URL"}
                },
                "required": ["target_url"]
            }
        }
    }
]

# Map string names to actual python functions
available_functions = {
    "run_nmap_scan": run_nmap_scan,
    "run_nuclei_scan": run_nuclei_scan,
    "run_gobuster": run_gobuster
}

# ==========================================
#  3. THE AGENT LOGIC (LOOP)
# ==========================================

def run_agent(user_prompt):
    # 1. System Context
    messages = [
        {
            "role": "system",
            "content": "You are 'Argus', an authorized security auditing assistant. You have access to Nmap, Nuclei, and Gobuster. Use them to investigate targets provided by the user. Always summarize findings technically."
        },
        {
            "role": "user",
            "content": user_prompt
        }
    ]

    # 2. First API Call (Does AI want to use a tool?)
    print(f"[*] Argus (Llama 3) is thinking...")
    response = client.chat.completions.create(
        model=MODEL_ID,
        messages=messages,
        tools=tools_schema,
        tool_choice="auto",
        max_tokens=4096
    )

    response_message = response.choices[0].message
    tool_calls = response_message.tool_calls

    # 3. If Tool Called -> Run Code -> Send Back Result
    if tool_calls:
        # Add the AI's "intent" to history
        messages.append(response_message)

        for tool_call in tool_calls:
            function_name = tool_call.function.name
            function_args = json.loads(tool_call.function.arguments)
            
            # Execute the function
            function_to_call = available_functions.get(function_name)
            if function_to_call:
                function_response = function_to_call(**function_args)
                
                # Append result to history
                messages.append(
                    {
                        "tool_call_id": tool_call.id,
                        "role": "tool",
                        "name": function_name,
                        "content": str(function_response),
                    }
                )

        # 4. Final Response (AI reads tool output and summarizes)
        print("[*] Analyzing tool output...")
        final_response = client.chat.completions.create(
            model=MODEL_ID,
            messages=messages
        )
        return final_response.choices[0].message.content
    
    else:
        # No tool needed, just text
        return response_message.content

# ==========================================
#  MAIN ENTRY
# ==========================================
if __name__ == "__main__":
    print("--- ARGUS: Groq-Powered Security Agent ---")
    while True:
        target = input("\nEnter command (or 'quit'): ")
        if target.lower() in ["quit", "exit"]: break
        
        try:
            result = run_agent(target)
            print(f"\n[REPORT]:\n{result}")
        except Exception as e:
            print(f"Error: {e}")