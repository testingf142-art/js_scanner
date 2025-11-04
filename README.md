JS-Secret-Harvester (js_scanner.py)

Automated JavaScript Source Code Analysis for Exposed Secrets and API Keys

Overview

js_scanner.py is a Python utility designed to automatically fetch and analyze JavaScript files from a list of URLs or directly from a target domain's historical archive (using gau). It employs a comprehensive set of regular expressions to quickly identify potential hardcoded secrets, API keys, tokens, and credentials that may have been mistakenly committed to public repositories or deployed in production.

This tool is optimized for speed and efficiency, incorporating multithreading for URL gathering via gau.

Features

File Input (-l): Scan a list of URLs provided in a text file.

Domain Input (-d): Automatically use the powerful gau (Gather All URLs) tool to collect historical and current JS links for a target domain, including subdomains (--subs).

Performance: Uses gau with a thread count of 10 for fast URL collection, and filters results using native Python for maximum efficiency.

Silent Mode (-s): Suppresses all progress messages and only prints the final summary of detected secrets ("juicy info").

Comprehensive Patterns: Includes regular expressions for generic tokens, AWS keys, JWTs, Stripe keys, GitHub tokens, and more.

Prerequisites

To run this script effectively, you need:

Python 3: The script is written in Python 3.

requests library: For fetching the content of JavaScript files.

gau (Gather All URLs): Mandatory if you plan to use the domain-based scanning option (-d). This is an external command-line tool.

Installation

1. Install Python Dependencies

You can install the required Python library using pip:

pip install requests


2. Install the gau Tool

The gau tool must be installed and available in your system's PATH. It is typically installed using go:

# If you have Go installed
go install [github.com/lc/gau/v2/cmd/gau@latest](https://github.com/lc/gau/v2/cmd/gau@latest)


Note: If you don't use the -d option, you do not need to install gau.

Usage

Save the script as js_scanner.py. You can run it in three different modes:

1. Scanning a URL List (File Input)

Use the -l flag followed by your file path. This file should contain one URL per line.

python js_scanner.py -l js_urls.txt


2. Scanning a Target Domain (Automatic gau Integration)

Use the -d flag followed by the target domain. The script will automatically run gau against the domain, filter the results for .js files, and begin scanning.

python js_scanner.py -d rumble.cloud 


3. Silent Mode

Add the -s flag to any of the above commands to suppress progress output and only show the final summary report.

# Silent mode with domain input
python js_scanner.py -d target.com -s

# Silent mode with file input
python js_scanner.py -l my_links.txt -s


Security & Ethical Hacking Disclaimer

This tool is intended for ethical security research, bug bounty hunting, and penetration testing on systems and domains for which you have explicit, written authorization. Scanning or probing systems without explicit permission is illegal and unethical. The author and distributor of this script are not responsible for any misuse of this program.
