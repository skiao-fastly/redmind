import os
import subprocess
import nmap
import google.generativeai as genai
from google.generativeai.types import FunctionDeclaration, Tool

# --- CONFIGURATION ---
# Get your free API key from https://aistudio.google.com/
os.environ["GEMINI_API_KEY"] = "YOUR_GEMINI_API_KEY_HERE"
genai.configure(api_key=os.environ["GEMINI_API_KEY"])

# ==========================================
#  TOOL DEFINITIONS
# ==========================================

def run_nmap_scan(target: str, scan_type: str = "quick"):
    """
    Executes an Nmap network scan to find open ports.
    
    Args:
        target: The IP or domain to scan (e.g., '192.168.1.5').
        scan_type: 'quick' (Top 100 ports) or 'full' (Service Version detection -sV).
    """
    print(f"\n[+] AI is running Nmap ({scan_type}) on {target}...")
    nm = nmap.PortScanner()
    try:
        if scan_type == "quick":
            nm.scan(hosts=target, arguments='-F')
        else:
            nm.scan(hosts=target, arguments='-sV -p 21,22,80,443,3306,8080')
        return nm.csv()
    except Exception as e:
        return f"Nmap Error: {e}"

def run_nuclei_scan(target_url: str):
    """
    Runs the Nuclei Vulnerability Scanner against a web target.
    Use this when you find a running web server (port 80/443).
    """
    print(f"\n[+] AI is running Nuclei on {target_url}...")
    # Note: We use subprocess because Nuclei doesn't have an official Python lib
    command = [
        "nuclei",
        "-u", target_url, 
        "-t", "cves/,vulnerabilities/",  # Only scan for CVEs and Vulns
        "-json", "-silent"
    ]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=120)
        if not result.stdout:
            return "Nuclei finished but found no critical vulnerabilities."
        return result.stdout[:5000] # Truncate to prevent token overflow
    except Exception as e:
        return f"Nuclei Failed: {e}"

def run_directory_buster(target_url: str):
    """
    Runs a Directory/File brute-force scan (Replaces Dirbuster).
    Use this to find hidden paths like /admin, /backup, etc.
    """
    print(f"\n[+] AI is running Gobuster on {target_url}...")
    # We use Gobuster because Dirbuster is a GUI tool and hard to automate
    command = [
        "gobuster", "dir",
        "-u", target_url,
        "-w", "/usr/share/wordlists/dirb/common.txt", # Standard Kali wordlist
        "-z", "--no-error", "-q"
    ]
    try:
        # Timeout after 60s to keep the demo fast
        result = subprocess.run(command, capture_output=True, text=True, timeout=60)
        return result.stdout if result.stdout else "No hidden directories found."
    except FileNotFoundError:
        return "Error: Gobuster not installed. Please install it (sudo apt install gobuster)."
    except Exception as e:
        return f"Gobuster Error: {e}"

# ==========================================
#  AI SETUP
# ==========================================

# 1. Register the tools
tools_list = [run_nmap_scan, run_nuclei_scan, run_directory_buster]

# 2. Create the Model
model = genai.GenerativeModel(
    model_name='gemini-1.5-flash', # Flash is faster/cheaper for tools
    tools=tools_list,
    system_instruction="""
    You are an Autonomous Penetration Testing Agent named 'Py-Ligant'.
    
    YOUR WORKFLOW:
    1. Always start with Nmap to find open ports.
    2. If you see Port 80/443, AUTOMATICALLY run 'run_directory_buster' to find hidden paths.
    3. If the user asks for a vulnerability check, run 'run_nuclei_scan'.
    4. Summarize all findings into a clean report.

    SAFETY:
    You are authorized to scan the targets provided by the user. 
    Do not simulate attacks, only discovery.
    """
)

# 3. Start the Chat (Automatic Function Calling Enabled)
chat = model.start_chat(enable_automatic_function_calling=True)

def main():
    print("==================================================")
    print("   PY-LIGANT: AI Pentest Agent (Gemini Powered)")
    print("==================================================")
    print("Tools Loaded: Nmap, Nuclei, Gobuster")
    print("Type 'quit' to exit.\n")

    while True:
        user_input = input("COMMAND > ")
        if user_input.lower() in ["quit", "exit"]:
            break
        
        try:
            # The Magic: Send text -> Gemini decides tool -> Runs Tool -> Gemini analyzes output
            print("Thinking...")
            response = chat.send_message(user_input)
            print(f"\n[AI REPORT]:\n{response.text}")
            
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    main()