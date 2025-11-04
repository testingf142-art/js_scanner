#
# JS Scanner: A Python script to automate URL gathering and scan JavaScript files
#             for hardcoded secrets, tokens, and keys.
#
# Dependencies: requests, gau (for the -d option)
#
import re
import argparse
import sys
import requests
import subprocess
from urllib.parse import urlparse

# --- Configuration ---

# Comprehensive list of regex patterns for finding secrets.
# Pattern names are used in the final report.
PATTERNS = {
    # Generic Tokens/Keys
    "Generic API Key": r'(?:api|token|key|secret|password|passwd|auth)[\s:=]*["\']?([a-zA-Z0-9_-]{16,64})["\']?',
    "JWT": r'ey[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}',
    "Password/Credential": r'(?:password|passwd|pwd|pass)[\s:=]*["\']?([a-zA-Z0-9!@#$%^&*()_+]{8,})["\']?',
    
    # Cloud Providers
    "AWS Access Key ID": r'(A3T[A-Z0-9]|AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASTU)[\w]{16,}',
    "AWS Secret Access Key": r'(?i)aws_secret_access_key["\']?[\s:=]*["\']?([a-zA-Z0-9+/]{40})["\']?',
    "Azure Client Secret": r'(?i)client_secret["\']?[\s:=]*["\']?([a-zA-Z0-9-~_]{27,64})["\']?',
    "Google API Key (AI/Maps)": r'AIza[0-9A-Za-z-_]{35}',
    "Google OAuth Client Secret": r'(?i)client_secret["\']?[\s:=]*["\']?([0-9a-zA-Z\s\-_]{24})["\']?',

    # Service Specific
    "Stripe Publishable Key": r'(?:pk|sk)_(?:live|test)_[0-9a-z]{24,32}',
    "GitHub Personal Access Token": r'(?:github|ghp|gho|ghu|ghs|ght)_[0-9a-zA-Z]{36}',
    "Slack Token": r'xox[baprsd]-[0-9a-zA-Z]{10,48}',
    "Twilio Auth Token": r'AC[a-z0-9]{32}',
    "Firebase Config URL": r'(?i)firebaseUrl["\']?[\s:=]*["\']?(https://[\w-]+\.firebaseio\.com)["\']?',
    "Sentry DSN": r'https?:\/\/[0-9a-f]{32}@sentry\.[a-z\._-]+\/[0-9]+',
}

# Maximum number of characters to show around a match for context
CONTEXT_WINDOW = 50

# --- Helper Functions ---

def run_gau(domain, silent=False):
    """
    Executes the 'gau' command on the target domain and extracts JS URLs.
    Includes performance optimizations and filters for '.js' files in Python.
    """
    if not silent:
        print(f"[*] Running gau (with --subs --threads 10) on {domain}...")

    # Command to run: gau --subs --threads 10 domain.com
    # Removed | grep to use native Python filtering for performance.
    command = ['gau', '--subs', '--threads', '10', domain]

    try:
        # Execute gau and capture output
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True,
            timeout=120  # Set a 2-minute timeout for gau execution
        )
        
        # Process the output lines
        all_urls = result.stdout.splitlines()
        
        # Filter URLs for .js files using native Python
        js_urls = [url.strip() for url in all_urls if url.strip().endswith('.js')]
        
        if not silent:
            print(f"[+] Found {len(js_urls)} unique JavaScript URLs.")
        return js_urls

    except subprocess.CalledProcessError as e:
        print(f"[!] Error: 'gau' command failed with return code {e.returncode}.")
        if "No such file or directory" in e.stderr:
             print("[!] Suggestion: Make sure 'gau' is installed and in your system PATH.")
        return []
    except FileNotFoundError:
        print("[!] Fatal Error: 'gau' tool not found. Please install it to use the -d option.")
        sys.exit(1)
    except subprocess.TimeoutExpired:
        print("[!] Error: 'gau' command timed out after 120 seconds.")
        return []

def get_js_content(url, session, only_ok, silent):
    """
    Fetches the content of a single JavaScript file.
    """
    try:
        response = session.get(url, timeout=10)
        
        # Print status message based on verbosity and status code
        status_code = response.status_code
        status_message = f"[{status_code} {response.reason}] Processing: {url}"

        if not silent:
            if status_code == 200:
                print(f"[+] {status_message}")
            elif not only_ok:
                # Only print non-200 errors if not in 'only_ok' mode
                print(f"[-] {status_message}")

        if status_code == 200:
            return response.text
        return None

    except requests.exceptions.RequestException as e:
        if not silent and not only_ok:
            # Print network-level errors if not in 'only_ok' mode
            print(f"[!] Connection Error for {url}: {e.__class__.__name__}")
        return None

def scan_content(url, content):
    """
    Scans the content of the file for known secret patterns.
    Returns a list of dictionaries containing found secrets.
    """
    found_secrets = []

    for name, pattern in PATTERNS.items():
        # Using finditer for efficiency to find all matches
        for match in re.finditer(pattern, content):
            full_match = match.group(0)  # The entire string that matched the regex
            
            # Use group(1) if available, otherwise use the full match.
            # This handles patterns where the secret itself is captured in group 1.
            secret_value = match.group(1) if len(match.groups()) > 0 else full_match
            
            # Determine start/end indices for context window
            start_index = max(0, match.start() - CONTEXT_WINDOW)
            end_index = min(len(content), match.end() + CONTEXT_WINDOW)
            
            # Extract context and clean up the secret value for display
            context_snippet = content[start_index:end_index].strip().replace('\n', ' ').replace('\r', '')

            # Heuristics: Skip common false positives if the secret is too short or generic
            if len(secret_value) < 16 and name in ["Generic API Key", "Password/Credential"]:
                continue 

            found_secrets.append({
                "url": url,
                "type": name,
                "value": secret_value,
                "snippet": context_snippet
            })
            
    return found_secrets

def print_summary(results):
    """
    Prints the final, formatted summary of all found secrets.
    """
    if not results:
        print("\n[+] Scan finished. No secrets found.")
        return

    print(f"\n{'='*80}")
    print(f"| SECRETS FOUND: {len(results)} potential credentials/keys")
    print(f"{'='*80}")

    for i, secret in enumerate(results):
        print(f"\n--- MATCH {i+1}: {secret['type']} ---")
        print(f"URL:     {secret['url']}")
        print(f"Value:   {secret['value']}")
        print(f"Context: {secret['snippet']}")

# --- Main Execution ---

def main():
    parser = argparse.ArgumentParser(
        description="JavaScript Scanner for Hardcoded Secrets. Use either -l or -d.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    # Argument group for input source (mutually exclusive)
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('-l', '--list', help='File path containing list of JS URLs (one per line).')
    input_group.add_argument('-d', '--domain', help='Target domain to run gau on (e.g., example.com). Requires "gau" to be installed.')

    # Optional flags for output control
    parser.add_argument('-s', '--silent', action='store_true', help='Suppress all progress output; only prints the final summary of found secrets.')
    parser.add_argument('-ok', '--only-ok', action='store_true', help='Only display processing messages for URLs that return HTTP 200 OK. Requires -s to be False.')

    args = parser.parse_args()
    
    urls_to_scan = []

    if args.domain:
        # Gather URLs using gau
        urls_to_scan = run_gau(args.domain, args.silent)
    elif args.list:
        # Read URLs from file
        try:
            with open(args.list, 'r') as f:
                urls_to_scan = [line.strip() for line in f if line.strip().endswith('.js')]
            if not args.silent:
                print(f"[*] Loaded {len(urls_to_scan)} JavaScript URLs from {args.list}")
        except FileNotFoundError:
            print(f"[!] Fatal Error: Input file '{args.list}' not found.")
            sys.exit(1)

    if not urls_to_scan:
        if not args.silent:
            print("[!] No valid JavaScript URLs found to scan. Exiting.")
        sys.exit(0)

    # Use a single session for connection pooling and efficiency
    session = requests.Session()
    all_results = []
    total_urls = len(urls_to_scan)

    for i, url in enumerate(urls_to_scan, 1):
        if not args.silent:
            # Print progress indicator if not silent
            sys.stdout.write(f"\r[{i}/{total_urls}] ")
            sys.stdout.flush()

        content = get_js_content(url, session, args.only_ok, args.silent)
        
        if content:
            secrets = scan_content(url, content)
            if secrets:
                all_results.extend(secrets)

    # Final output is always the summary, unless fully silent mode (-s) is active and nothing was found
    if not args.silent or all_results:
        print_summary(all_results)
    
if __name__ == "__main__":
    main()
