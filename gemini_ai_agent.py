import os
import subprocess
import google.generativeai as genai
from google.generativeai.types import FunctionDeclaration, Tool

# --- CONFIGURATION ---
# Get your key: https://aistudio.google.com/
os.environ["GEMINI_API_KEY"] = "$GEMINI"
genai.configure(api_key=os.environ["GEMINI_API_KEY"])

# ==========================================
#  1. DEFINE THE TOOLS
# ==========================================
# (We keep these the same, but the AI will use them better now)

def run_nmap_scan(target: str, scan_type: str = "quick"):
    """
    Executes an Nmap network scan to find open ports.
    Args:
        target: The IP or domain to scan (e.g., '192.168.1.5').
        scan_type: 'quick' (Top 100 ports) or 'full' (Service Version detection -sV).
    """
    print(f"\n[Tool] Running Nmap ({scan_type}) on {target}...")
    # Simulating a scan for safety if you don't have nmap installed
    # Remove the 'return' below to run the real nmap command
    # return "Port 80 (HTTP) Open, Port 443 (HTTPS) Open, Port 22 (SSH) Closed." 
    
    import nmap # Lazy import to avoid errors if not installed
    nm = nmap.PortScanner()
    try:
        if scan_type == "quick":
            nm.scan(hosts=target, arguments='-F')
        else:
            nm.scan(hosts=target, arguments='-sV -p 21,22,80,443')
        return nm.csv()
    except Exception as e:
        return f"Nmap Error: {e}"

def run_gobuster(target_url: str):
    """
    Runs Gobuster to find hidden directories (e.g. /admin, /backup).
    """
    print(f"\n[Tool] Running Gobuster on {target_url}...")
    command = ["gobuster", "dir", "-u", target_url, "-w", "/usr/share/wordlists/dirb/common.txt", "-z", "--no-error", "-q"]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=60)
        return result.stdout if result.stdout else "No hidden directories found."
    except Exception as e:
        return f"Gobuster Error: {e} (Ensure gobuster is installed)"

# ==========================================
#  2. INITIALIZE GEMINI 2.0
# ==========================================

tools_list = [run_nmap_scan, run_gobuster]

# ERROR FIX: 
# 1. We use 'gemini-2.0-flash-exp' (The new model)
# 2. We add 'models/' prefix which solves the "unexpected format" error.
model_name = "models/gemini-2.0-flash-exp" 

try:
    model = genai.GenerativeModel(
        model_name=model_name,
        tools=tools_list,
        system_instruction="""
        You are 'Argus', an advanced security agent.
        Your goal is to audit the user's infrastructure using the provided tools.
        1. Start with Nmap.
        2. If you find web ports, use Gobuster.
        3. Summarize all vulnerabilities found.
        """
    )
    
    # Enable automatic tool use
    chat = model.start_chat(enable_automatic_function_calling=True)
    print(f"SUCCESS: Connected to {model_name}")

except Exception as e:
    print(f"Setup Error: {e}")
    print("Tip: Ensure you ran 'pip install --upgrade google-generativeai'")
    exit()

def main():
    print("-----------------------------------------")
    print("   ARGUS 2.0 (Powered by Gemini 2.0)     ")
    print("-----------------------------------------")
    
    while True:
        user_input = input("\nTarget > ")
        if user_input.lower() in ["quit", "exit"]: break
        
        try:
            print("Thinking...")
            response = chat.send_message(user_input)
            print(f"\n[Analysis]:\n{response.text}")
        except Exception as e:
            print(f"Runtime Error: {e}")

if __name__ == "__main__":
    main()