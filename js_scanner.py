import requests
import re
import sys
import time
import subprocess # Added subprocess for running external commands
from typing import Dict, Optional, List

# --- Configuration ---
# File containing one URL per line (Used as default if no argument is passed)
URL_FILE = "js_urls.txt"
# Maximum number of lines/characters to print around a match for context
CONTEXT_CHARS = 50
# User-Agent to use for requests (helps avoid being blocked)
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"

# A comprehensive dictionary of regular expressions to search for sensitive data.
# The keys are descriptive names, and the values are the regex patterns.
# NOTE: These patterns are heuristic and may produce false positives.
PATTERNS: Dict[str, str] = {
    # Generic Tokens/Keys (look for common keywords followed by key-like characters)
    "Generic API Key/Secret": r"(secret|key|token|password|auth|client_id|client_secret)[\s\"'=]{0,5}([a-zA-Z0-9_\-./!@#$%^&*+=]{16,})",
    
    # AWS Access Key IDs (AKIA, ASIA, etc.)
    "AWS Access Key ID": r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16,20}",
    
    # Firebase/Google API Key
    "Firebase/GCP API Key": r"AIza[0-9A-Za-z\-_]{35}",
    
    # Private SSH Key Header
    "Private SSH Key Header": r"-----BEGIN\s(?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----",

    # JSON Web Token (JWT) - looks for three base64 segments
    "JWT Token (Base64)": r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
    
    # Generic Bearer Token
    "Generic Bearer Token": r"Bearer\s[A-Za-z0-9\-\._~+/]{20,}",
    
    # Basic Auth in URL (user:pass@host)
    "Basic Auth URL Segment": r"[a-zA-Z0-9_\-]+\:[a-zA-Z0-9_\-]+@\S+",

    # Stripe Secret Key (sk_live_ or rk_live_)
    "Stripe Secret Key": r"(sk_live_|rk_live_)[0-9a-zA-Z]{24,}",

    # GitHub/GitLab Personal Access Tokens (often start with ghp/glp)
    "GitHub/GitLab Token": r"(ghp_|glp_)[a-zA-Z0-9_]{36,}",
}

def get_js_content(url: str, is_silent: bool) -> Optional[str]:
    """Fetches the content of a given URL."""
    try:
        headers = {'User-Agent': USER_AGENT}
        # Set a short timeout to prevent the script from hanging on bad connections
        response = requests.get(url, headers=headers, timeout=10)
        
        # Check for successful status codes
        if response.status_code == 200:
            return response.text
        else:
            if not is_silent:
                print(f"[-] HTTP Error: {url} returned status code {response.status_code}")
            return None
            
    except requests.exceptions.RequestException as e:
        if not is_silent:
            print(f"[-] Connection Error for {url}: {e}")
        return None
    except Exception as e:
        if not is_silent:
            print(f"[-] An unexpected error occurred for {url}: {e}")
        return None

def scan_content(url: str, content: str) -> List[Dict[str, str]]:
    """Scans the content using defined regex patterns and returns matches."""
    found_secrets = []
    
    for name, pattern in PATTERNS.items():
        # Compile the regex once for efficiency
        compiled_pattern = re.compile(pattern, re.IGNORECASE)
        
        # Find all matches in the content
        for match in compiled_pattern.finditer(content):
            
            # Get the exact match string
            match_string = match.group(0)
            
            # Find context around the match
            start_index = max(0, match.start() - CONTEXT_CHARS)
            end_index = min(len(content), match.end() + CONTEXT_CHARS)
            
            # Highlight the match in the context
            context_snippet = (
                content[start_index:match.start()]
                + " [!!! MATCH !!!] " + match_string + " [!!! END MATCH !!!] "
                + content[match.end():end_index]
            )
            
            found_secrets.append({
                "type": name,
                "url": url,
                "snippet": match_string,
                "context": context_snippet.replace('\n', ' ').strip()
            })
            
    return found_secrets

def run_gau(domain: str, is_silent: bool) -> List[str]:
    """
    Runs the 'gau' command, filters for .js files, and returns a list of URLs.
    Requires 'gau' and 'grep' to be installed on the system.
    """
    # Use '--subs' flag for gau to include subdomains, matching the functionality of popular tools.
    command = f"gau --subs {domain} | grep '\\.js$'"
    
    if not is_silent:
        print(f"[INFO] Running external command to fetch URLs: {command}")

    try:
        # Use shell=True to handle the pipe (|) and run the command string directly
        # capture_output=True captures stdout and stderr
        # text=True decodes the output as a string (default is bytes)
        process = subprocess.run(
            command, 
            shell=True, 
            capture_output=True, 
            text=True, 
            check=False # Do not raise exception on non-zero exit (e.g., grep finds nothing)
        )
        
        # Check for command failure (gau/grep not found, permission denied, etc.)
        if process.returncode != 0 and process.stderr and "not found" in process.stderr:
            if not is_silent:
                print(f"\n[FATAL] Error running external command. Please ensure 'gau' and 'grep' are installed and in your PATH.")
                print(f"Subprocess Error Output:\n{process.stderr.strip()}")
            return []
            
        # Extract and clean up the URLs from stdout
        urls = [line.strip() for line in process.stdout.splitlines() if line.strip()]
        return urls

    except FileNotFoundError:
        if not is_silent:
            print("\n[FATAL] Python could not find the necessary command utilities ('sh' or underlying tools).")
        return []
    except Exception as e:
        if not is_silent:
            print(f"\n[FATAL] An unexpected error occurred during URL fetching: {e}")
        return []

def main():
    """Main function to orchestrate the scanning process, now handling command-line arguments."""
    
    # Initialize variables
    input_file_path = URL_FILE
    target_domain = None
    is_silent = False
    mode = 'default_file' # 'default_file', 'file', or 'domain'
    
    # 1. Check for silent flag (-s) first
    if '-s' in sys.argv:
        is_silent = True
        sys.argv.remove('-s')

    # 2. Parse remaining arguments for mode (-l or -d)
    if '-l' in sys.argv:
        try:
            l_index = sys.argv.index('-l')
            input_file_path = sys.argv[l_index + 1]
            mode = 'file'
        except (IndexError, ValueError):
            if not is_silent:
                print("Error: -l option requires a file path argument.")
            sys.exit(1)
            
    elif '-d' in sys.argv:
        try:
            d_index = sys.argv.index('-d')
            target_domain = sys.argv[d_index + 1]
            mode = 'domain'
        except (IndexError, ValueError):
            if not is_silent:
                print("Error: -d option requires a target domain argument (e.g., example.com).")
            sys.exit(1)
    
    # 3. Handle Usage/Help message
    if len(sys.argv) > 1 and sys.argv[1] in ('-h', '--help'):
        print(f"Usage: python {sys.argv[0]} [-l <file_path> | -d <domain>] [-s]")
        print("  -l <file_path> : Read URLs from a specified file (e.g., js_urls.txt).")
        print("  -d <domain>    : Automatically run 'gau <domain> | grep .js$' to fetch URLs.")
        print("  -s             : Silent mode (suppress all progress output, only show summary).")
        print("Default: Reads URLs from 'js_urls.txt'.")
        sys.exit(0)

    # 4. Get URLs based on mode
    urls = []
    if mode == 'domain':
        urls = run_gau(target_domain, is_silent)
        if not urls:
            if not is_silent:
                print(f"\n[INFO] 'gau' found 0 JavaScript URLs for {target_domain}. Exiting scan.")
            sys.exit(0)
    
    else: # mode is 'file' or 'default_file'
        if not is_silent:
            print(f"--- JS Secret Scanner Initialized ---")
            print(f"Attempting to read URLs from: {input_file_path}")
        
        try:
            with open(input_file_path, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"\n[FATAL] Error: The file '{input_file_path}' was not found.")
            print("Please ensure the file path is correct.")
            sys.exit(1)

    if not urls and mode != 'domain':
        print("\n[INFO] No URLs found in the input file. Exiting scan.")
        sys.exit(0)
        
    if not is_silent:
        print(f"Found {len(urls)} URLs to scan. Starting scan...\n")

    # 5. Begin Scanning Process
    all_results = []
    
    for i, url in enumerate(urls, 1):
        if not is_silent:
            print(f"[{i}/{len(urls)}] Processing: {url}")
        
        content = get_js_content(url, is_silent)
        
        if content:
            results = scan_content(url, content)
            if results:
                if not is_silent:
                    print(f"[SUCCESS] Found {len(results)} potential secret(s) in {url}")
                all_results.extend(results)
            # Be polite to the server
            time.sleep(0.5)

    # 6. Summary Output
    # The summary block should always run, regardless of is_silent
    print("\n\n#################################################")
    print("             SCANNING SUMMARY")
    print("#################################################\n")

    if all_results:
        print(f"TOTAL POTENTIAL SECRETS FOUND: {len(all_results)}\n")
        
        for result in all_results:
            print("-" * 50)
            print(f"Type:      {result['type']}")
            print(f"URL:       {result['url']}")
            print(f"Snippet:   {result['snippet']}")
            print(f"Context:   {result['context'][:1000]}...") # Truncate context for cleaner output
            print("-" * 50)
    else:
        print("No potential secrets or juicy info found based on defined patterns.")

if __name__ == "__main__":
    # Ensure you have the 'requests' library installed: pip install requests
    # If using the -d option, ensure 'gau' and 'grep' are installed and in your system PATH.
    main()
