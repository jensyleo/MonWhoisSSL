import subprocess
import ssl
import socket
import datetime
import sys
import os
import re
import requests
import shutil
import time
import tty
import termios
import select
import threading
import queue
import json

try:
    from colorama import Fore, Style, init
except ImportError:
    print("Error: Missing dependency 'colorama'.\nPlease run:\npip install colorama")
    sys.exit(1)

# Initialize colorama
init(autoreset=True)

# Standard colorama colors used globally (same palette as WebMonitor)
RGB_GREEN = Fore.GREEN                # Green for the frame
RGB_SUCCESS = Fore.GREEN              # Specific green for success messages
RGB_BLUE = Fore.CYAN                  # Blue elements
RGB_YELLOW = Fore.YELLOW              # Yellow elements
RGB_RED = Fore.RED                    # Errors
RGB_LABEL = Fore.LIGHTRED_EX          # Orange for DOM: and SSL: labels
RGB_ASCII_GREEN = Fore.LIGHTGREEN_EX  # ASCII art
RESET_COLOR = Fore.RESET

# ANSI color codes (kept for compatibility)
class Colors:
    RED = RGB_RED
    GREEN = RGB_GREEN
    YELLOW = RGB_YELLOW
    BLUE = RGB_BLUE
    PURPLE = Fore.WHITE
    CYAN = Fore.CYAN
    WHITE = Fore.WHITE
    BOLD = Style.BRIGHT
    UNDERLINE = ''  # colorama has no standard underline; kept for API compatibility
    END = RESET_COLOR
    ASCII_GREEN = RGB_ASCII_GREEN

# Timeout constants for network and subprocess operations
TIMEOUT_DNS = 1              # Timeout for DNS verification (requests)
TIMEOUT_SSL = 3              # Timeout for SSL connection
TIMEOUT_WHOIS = 10           # Timeout for WHOIS query
TIMEOUT_RDAP = 15            # Timeout for RDAP query
TIMEOUT_THREAD_DNS = 10      # Timeout for DNS verification threads
TIMEOUT_THREAD_SSL = 15      # Timeout for SSL verification threads
TIMEOUT_THREAD_WHOIS = 15    # Timeout for WHOIS verification threads
TIMEOUT_THREAD_RDAP = 20     # Timeout for RDAP verification threads
TIMEOUT_THREAD_COMBINED = 30 # Timeout for combined verification threads
SLEEP_BETWEEN_BATCHES = 1.0  # Wait time between WHOIS batches
SLEEP_ERROR_DISPLAY = 3      # Wait time to display errors
SLEEP_VERIFICATION = 2       # Wait time after verification
SLEEP_COUNTDOWN = 0.1        # Polling interval for countdown
SLEEP_SHORT = 1              # Short wait time (1 second)
MONITORING_INTERVAL_SECONDS = 28800  # Automatic verification interval (8 hours in seconds)

# Threshold constants for evaluating remaining days
DAYS_CRITICAL_THRESHOLD = 30  # Critical days: less than 30 days = CRITICAL (RED)
DAYS_WARNING_THRESHOLD = 90   # Warning days: between 30 and 90 days = WARNING (YELLOW), >= 90 days = SAFE (GREEN)

# Format and UI constants
SEPARATOR_LENGTH = 60  # Length of the line separator ('=' * 60)
MENU_WIDTH = 52        # Menu width in characters
MAX_DOMAINS = 20      # Maximum number of domains to process

# Text message constants
MSG_NO_INFO = "No information"           # Message when no information is available
MSG_DOMAIN_NOT_EXISTS = "DOMAIN DOES NOT EXIST"  # Message when the domain does not exist
MSG_NOT_AVAILABLE = "N/A"                 # Message for unavailable values
MSG_METHOD_NONE = "NONE"                  # Default method when it cannot be determined

# Error message constants
MSG_ERROR = "Error"                       # Generic error message
MSG_ERROR_FORMAT = "Format error"       # Error in data format
MSG_ERROR_SSL = "SSL Error"               # Error in SSL verification
MSG_ERROR_RDAP = "RDAP Error"             # Error in RDAP verification
MSG_ERROR_WHOIS = "WHOIS Error"          # Error in WHOIS verification
MSG_TLD_NOT_SUPPORTED = "TLD not supported"  # TLD not supported by RDAP

# Matrix and UI configuration constants
MATRIX_COLUMNS = 4              # Number of columns in the results matrix
MATRIX_STRUCTURE_WIDTH = 14     # Width in characters of the matrix structure (separators and spaces)
MATRIX_BORDER_WIDTH = 2         # Width of the matrix border (for internal width calculation)

# Processing constants
WHOIS_BATCH_SIZE = 2            # Batch size for WHOIS processing (avoids overloading servers)
ERROR_MSG_MAX_LENGTH = 30       # Maximum length to truncate error messages
TEXT_TRUNCATE_SUFFIX_LENGTH = 3 # Length of the suffix when truncating text (e.g.: "...")

def get_terminal_width():
    """Get the terminal width"""
    try:
        return shutil.get_terminal_size().columns
    except Exception:
        return 80  # Default width if it cannot be obtained

def calculate_matrix_column_width(terminal_width):
    """
    Calculate the column width for the 4-column matrix.

    Args:
        terminal_width: Total terminal width

    Returns:
        int: Width of each column in the matrix
    """
    # Calculate dynamic width to use the entire screen
    # MATRIX_COLUMNS columns with separators: │ col1 │ col2 │ col3 │ col4 │
    # Total separators: 5 (start, 3 between columns, end) = 5 characters
    # Space for separators: 5 * 2 = 10 characters (│ │ │ │ │)
    # Space for spaces: 4 spaces between separators = 4 characters
    # Total structure characters: MATRIX_STRUCTURE_WIDTH
    matrix_total_width = terminal_width
    column_width = (matrix_total_width - MATRIX_STRUCTURE_WIDTH) // MATRIX_COLUMNS
    return column_width

def disable_input():
    """Disable keyboard input"""
    try:
        if not sys.stdin.isatty():
            return None
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        tty.setraw(fd)
        return old_settings
    except Exception:
        return None

def enable_input(old_settings):
    """Re-enable keyboard input"""
    try:
        if old_settings:
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
    except Exception:
        pass

def check_for_ctrl_c():
    """Check if CONTROL-C or CONTROL-R was pressed without blocking"""
    try:
        if not sys.stdin.isatty():
            return False, False
        # Drain the entire available buffer and look for \x03 (CONTROL-C)
        ctrl_c_detected = False
        ctrl_r_detected = False
        # Non-blocking read loop: consumes all ready keys
        while True:
            ready, _, _ = select.select([sys.stdin], [], [], 0)
            if not ready:
                break
            char = sys.stdin.read(1)
            if char == '\x03':  # CONTROL-C
                ctrl_c_detected = True
            elif char == '\x12':  # CONTROL-R
                ctrl_r_detected = True
                # Keep draining in case there are more bytes queued
                continue
        return ctrl_c_detected, ctrl_r_detected
    except Exception:
        return False, False






def print_colored(text, color=Colors.WHITE, end="\n"):
    print(f"{color}{text}{Colors.END}", end=end)

def get_display_width(text):
    """
    Calculate the visual width (in terminal columns) of a string, treating
    emoji as double-width like most terminal emulators render them.
    """
    width = 0
    for ch in text:
        code = ord(ch)
        if code in (0xFE0F, 0x200D):  # variation selector-16, zero-width joiner: no extra width
            continue
        if (0x1F300 <= code <= 0x1FAFF) or (0x2600 <= code <= 0x27BF) or (0x2B00 <= code <= 0x2BFF):
            width += 2
        else:
            width += 1
    return width

def pad_menu_line(text, width):
    """Right-pad text with spaces so its visual width matches the target column width"""
    padding = max(width - get_display_width(text), 0)
    return text + (' ' * padding)

def truncate_to_width(text, width):
    """Truncate text with an ellipsis if it exceeds the target column width, to avoid breaking matrix alignment"""
    if len(text) > width:
        return f"{text[:width - TEXT_TRUNCATE_SUFFIX_LENGTH]}..."
    return text

def show_ascii_art():
    """Display the banner ASCII art with dynamic centering"""
    # Banner with dynamically centered ASCII art (same block-letter style as WebMonitor)
    terminal_width = get_terminal_width()

    ascii_art = [
        r" __  __          __        ___           _     ____ ____  _     ",
        r"|  \/  | ___  _ _\ \      / / |__   ___ (_)___/ ___/ ___|| |    ",
        r"| |\/| |/ _ \| '_ \ \ /\ / /| '_ \ / _ \| / __\___ \___ \| |    ",
        r"| |  | | (_) | | | \ V  V / | | | | (_) | \__ \___) |__) | |___ ",
        r"|_|  |_|\___/|_| |_|\_/\_/  |_| |_|\___/|_|___/____/____/|_____|",
    ]
    ascii_margin = max((terminal_width - max(len(line) for line in ascii_art)) // 2, 0)

    print()
    for line in ascii_art:
        print(f"{RGB_ASCII_GREEN}{' ' * ascii_margin}{line}{RESET_COLOR}")

def show_status_explanation():
    """Display the security status explanation with dynamic centering"""
    # Calculate dynamic centering
    terminal_width = get_terminal_width()
    menu_width = MENU_WIDTH
    margin = (terminal_width - menu_width) // 2

    print(f"\n{RGB_GREEN}{' ' * margin}╔{'═' * menu_width}╗{RESET_COLOR}")
    print(f"{RGB_GREEN}{' ' * margin}║{RGB_BLUE}{'SECURITY STATUS EXPLANATION':^52}{RGB_GREEN}║{RESET_COLOR}")
    print(f"{RGB_GREEN}{' ' * margin}╠{'═' * menu_width}╣{RESET_COLOR}")
    print(f"{RGB_GREEN}{' ' * margin}║ {RGB_SUCCESS}{pad_menu_line('🟢 SAFE (>90 days):       No action required', menu_width - 1)}{RGB_GREEN}║{RESET_COLOR}")
    print(f"{RGB_GREEN}{' ' * margin}║ {RGB_YELLOW}{pad_menu_line('🟡 WARNING (30-90 days):  Plan renewal', menu_width - 1)}{RGB_GREEN}║{RESET_COLOR}")
    print(f"{RGB_GREEN}{' ' * margin}║ {RGB_RED}{pad_menu_line('🔴 CRITICAL (<30 days):   RENEW IMMEDIATELY!', menu_width - 1)}{RGB_GREEN}║{RESET_COLOR}")
    print(f"{RGB_GREEN}{' ' * margin}╚{'═' * menu_width}╝{RESET_COLOR}")

def check_dns_existence(domain):
    """Check if the domain exists in DNS using requests"""
    try:
        response = requests.get(f"http://{domain}", timeout=TIMEOUT_DNS, allow_redirects=False)
        return True
    except requests.exceptions.ConnectionError as e:
        error_msg = str(e).lower()
        if "name or service not known" in error_msg or "nodename nor servname provided" in error_msg:
            return False
        else:
            return True
    except requests.exceptions.Timeout:
        return True
    except requests.exceptions.RequestException:
        return True
    except Exception as e:
        # Log error for debugging (optional, can be commented out in production)
        # print(f"Unexpected error in check_dns_existence for {domain}: {e}", file=sys.stderr)
        return True

def perform_domain_verification(domains_file):
    """Perform full domain verification and return results"""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    domains_file_path = os.path.join(script_dir, domains_file)

    if not os.path.isfile(domains_file_path):
        return None

    domains = load_domains_from_file(domains_file_path)
    if not domains:
        return None

    # FIRST: Check DNS for all domains in parallel
    dns_results = check_dns_existence_batch(domains)

    # Filter only domains that exist
    existing_domains = filter_existing_domains(domains, dns_results)

    # SECOND: Process domains keeping the original order of the list
    results = []

    # THIRD: Check WHOIS, RDAP and SSL for all existing domains IN FULL PARALLEL SIMULTANEOUSLY
    whois_results, rdap_results, ssl_results = execute_combined_verification_threads(existing_domains)

    # FOURTH: Build results keeping the original order
    for domain in domains:
        if domain in existing_domains:
            # Get WHOIS and RDAP results
            whois_result = whois_results.get(domain)
            rdap_result = rdap_results.get(domain)

            # Prioritize the first positive result (WHOIS first, then RDAP)
            domain_result = None
            domain_method = MSG_METHOD_NONE

            if whois_result and whois_result.get("expiry") not in [MSG_DOMAIN_NOT_EXISTS, MSG_NO_INFO, MSG_ERROR, MSG_ERROR_FORMAT, MSG_ERROR_WHOIS]:
                domain_result = whois_result
                domain_method = "WHOIS"
            elif rdap_result and rdap_result.get("expiry") not in [MSG_DOMAIN_NOT_EXISTS, MSG_NO_INFO, MSG_ERROR, MSG_ERROR_FORMAT, MSG_ERROR_RDAP, MSG_TLD_NOT_SUPPORTED]:
                domain_result = rdap_result
                domain_method = "RDAP"

            # Prepare domain result
            if domain_result:
                domain_expiry = domain_result.get("expiry", MSG_NO_INFO)
                domain_days = domain_result.get("days", MSG_NOT_AVAILABLE)
                domain_color = domain_result.get("color", Colors.WHITE)
            else:
                domain_expiry = MSG_NO_INFO
                domain_days = MSG_NOT_AVAILABLE
                domain_color = Colors.YELLOW

            # Get SSL result
            ssl_result = ssl_results.get(domain)
            if ssl_result and ssl_result.get("expiry") not in [MSG_DOMAIN_NOT_EXISTS, MSG_ERROR_SSL]:
                ssl_expiry = ssl_result.get("expiry", MSG_NO_INFO)
                ssl_days = ssl_result.get("days", MSG_NOT_AVAILABLE)
                ssl_color = ssl_result.get("color", Colors.WHITE)
            else:
                ssl_expiry = MSG_NO_INFO
                ssl_days = MSG_NOT_AVAILABLE
                ssl_color = Colors.YELLOW

            # Determine colors according to the established logic
            domain_color = get_color_from_days(domain_days)
            ssl_color = get_color_from_days(ssl_days)

            # Build combined result
            result = {
                "domain": domain,
                "domain_expiry": domain_expiry,
                "domain_days": domain_days,
                "domain_color": domain_color,
                "ssl_expiry": ssl_expiry,
                "ssl_days": ssl_days,
                "ssl_color": ssl_color,
                "status": "INFO" if domain_result else "WARNING",
                "method": domain_method
            }

            results.append(result)
        else:
            # Add result for a domain that does not exist
            results.append({
                "domain": domain,
                "domain_expiry": MSG_DOMAIN_NOT_EXISTS,
                "domain_days": MSG_NOT_AVAILABLE,
                "domain_color": Colors.RED,
                "ssl_expiry": MSG_NOT_AVAILABLE,
                "ssl_days": MSG_NOT_AVAILABLE,
                "ssl_color": Colors.RED,
                "status": "ERROR",
                "method": "DNS"
            })

    return results

def execute_combined_verification_threads(existing_domains):
    """
    Run combined WHOIS, RDAP and SSL verification in parallel using threads.

    Args:
        existing_domains: List of existing domains to verify

    Returns:
        tuple: (whois_results, rdap_results, ssl_results) - Three dictionaries with the results
    """
    # Variables to store results
    whois_results = {}
    rdap_results = {}
    ssl_results = {}

    # Function to run WHOIS in parallel
    def run_whois_batch():
        nonlocal whois_results
        whois_results = check_whois_expiry_batch(existing_domains)

    # Function to run RDAP in parallel
    def run_rdap_batch():
        nonlocal rdap_results
        rdap_results = check_rdap_expiry_batch(existing_domains)

    # Function to run SSL in parallel
    def run_ssl_batch():
        nonlocal ssl_results
        ssl_results = check_ssl_expiry_batch(existing_domains)

    # Create and run the 3 threads simultaneously
    whois_thread = threading.Thread(target=run_whois_batch)
    rdap_thread = threading.Thread(target=run_rdap_batch)
    ssl_thread = threading.Thread(target=run_ssl_batch)

    whois_thread.start()
    rdap_thread.start()
    ssl_thread.start()

    # Wait for all threads to finish
    whois_thread.join(timeout=TIMEOUT_THREAD_COMBINED)
    rdap_thread.join(timeout=TIMEOUT_THREAD_COMBINED)
    ssl_thread.join(timeout=TIMEOUT_THREAD_COMBINED)

    # Check if any thread is still alive after the timeout
    if whois_thread.is_alive() or rdap_thread.is_alive() or ssl_thread.is_alive():
        # Some threads did not finish in time, continue with the available results
        pass

    return whois_results, rdap_results, ssl_results

def check_dependencies():
    """Check that all required dependencies are installed"""
    dependencies = {
        'whois': 'WHOIS command for domain verification',
        'curl': 'curl command for RDAP queries',
        'jq': 'JSON processor to parse RDAP responses'
    }

    # Check Python requests dependency
    try:
        import requests
    except ImportError:
        print_colored(f"\n{'='*SEPARATOR_LENGTH}", Colors.RED)
        print_colored("❌ MISSING DEPENDENCY", Colors.BOLD + Colors.RED)
        print_colored(f"{'='*SEPARATOR_LENGTH}", Colors.RED)
        print_colored("❌ requests: Not found", Colors.RED)
        print_colored("💡 To install, run:", Colors.CYAN)
        print_colored("   pip install requests", Colors.WHITE)
        print_colored("   If it doesn't work, try: pip3 install requests", Colors.WHITE)
        print_colored(f"{'='*SEPARATOR_LENGTH}", Colors.RED)
        return False

    missing_deps = []

    for cmd, description in dependencies.items():
        try:
            result = subprocess.run(['which', cmd], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if result.returncode != 0:
                missing_deps.append(cmd)
        except Exception:
            missing_deps.append(cmd)

    if missing_deps:
        print_colored(f"\n{'='*SEPARATOR_LENGTH}", Colors.RED)
        print_colored("⚠️  MISSING DEPENDENCIES", Colors.BOLD + Colors.RED)
        print_colored(f"{'='*SEPARATOR_LENGTH}", Colors.RED)

        for cmd in missing_deps:
            print_colored(f"❌ {cmd}: Not found - {dependencies[cmd]}", Colors.RED)

        print_colored("\n📦 To install the missing dependencies:", Colors.YELLOW)

        # Installation instructions by operating system
        print_colored("\n🐧 Ubuntu/Debian:", Colors.CYAN)
        if 'whois' in missing_deps:
            print_colored("   sudo apt update && sudo apt install whois", Colors.WHITE)
        if 'curl' in missing_deps:
            print_colored("   sudo apt update && sudo apt install curl", Colors.WHITE)
        if 'jq' in missing_deps:
            print_colored("   sudo apt update && sudo apt install jq", Colors.WHITE)

        print_colored("\n🍎 macOS:", Colors.CYAN)
        if 'whois' in missing_deps:
            print_colored("   brew install whois", Colors.WHITE)
        if 'curl' in missing_deps:
            print_colored("   curl comes pre-installed on macOS", Colors.GREEN)
        if 'jq' in missing_deps:
            print_colored("   brew install jq", Colors.WHITE)

        print_colored("\n🟦 CentOS/RHEL/Fedora:", Colors.CYAN)
        if 'whois' in missing_deps:
            print_colored("   sudo yum install whois  # or sudo dnf install whois", Colors.WHITE)
        if 'curl' in missing_deps:
            print_colored("   sudo yum install curl   # or sudo dnf install curl", Colors.WHITE)
        if 'jq' in missing_deps:
            print_colored("   sudo yum install jq     # or sudo dnf install jq", Colors.WHITE)

        print_colored(f"\n{'='*SEPARATOR_LENGTH}", Colors.RED)
        print_colored("❌ Please install the missing dependencies and run the program again.", Colors.RED)
        print_colored(f"{'='*SEPARATOR_LENGTH}", Colors.RED)

        return False
    else:
        return True

def check_rdap_expiry(domain, return_result=False, skip_dns_check=False):
    """Check expiration date using RDAP (Registration Data Access Protocol)"""
    try:
        # FIRST: Check if the domain exists in DNS (only if not skipped)
        if not skip_dns_check and not check_dns_existence(domain):
            if not return_result:
                print_colored(f"\n{'='*SEPARATOR_LENGTH}", Colors.CYAN)
                print_colored(f"🌐 DOMAIN: {domain}", Colors.BOLD + Colors.WHITE)
                print_colored(f"📡 METHOD: RDAP", Colors.CYAN)
                print_colored(f"❌ STATUS: DOMAIN DOES NOT EXIST", Colors.RED)
                print_colored(f"💡 SUGGESTION: Check the domain", Colors.YELLOW)
                print_colored(f"{'='*SEPARATOR_LENGTH}", Colors.CYAN)
            return {"domain": domain, "expiry": MSG_DOMAIN_NOT_EXISTS, "days": MSG_NOT_AVAILABLE, "status": "ERROR", "color": Colors.RED}

        # NEW: If it's a subdomain, use the main domain for RDAP
        main_domain = get_main_domain(domain)
        rdap_domain = main_domain if main_domain != domain else domain

        # SECOND: If the domain exists, proceed with RDAP
        # Extract the TLD from the main domain to determine the RDAP server
        tld = rdap_domain.split('.')[-1].lower()

        # Most common RDAP servers
        rdap_servers = {
            'com': 'https://rdap.verisign.com/com/v1/domain/',
            'net': 'https://rdap.verisign.com/net/v1/domain/',
            'org': 'https://rdap.publicinterestregistry.org/rdap/domain/',
            'info': 'https://rdap.identitydigital.services/rdap/domain/',
            'biz': 'https://rdap.identitydigital.services/rdap/domain/',
            'energy': 'https://rdap.identitydigital.services/rdap/domain/',
            'tech': 'https://rdap.identitydigital.services/rdap/domain/',
            'online': 'https://rdap.identitydigital.services/rdap/domain/',
            'site': 'https://rdap.identitydigital.services/rdap/domain/',
            'club': 'https://rdap.identitydigital.services/rdap/domain/',
            'xyz': 'https://rdap.centralnic.com/xyz/domain/',
            'io': 'https://rdap.centralnic.com/io/domain/',
            'ai': 'https://rdap.centralnic.com/ai/domain/',
            'co': 'https://rdap.centralnic.com/co/domain/',
            'me': 'https://rdap.centralnic.com/me/domain/',
            'uk': 'https://rdap.nominet.uk/uk/domain/',
            'de': 'https://rdap.denic.de/domain/',
            'fr': 'https://rdap.nic.fr/domain/',
            'es': 'https://rdap.nic.es/domain/',
            'it': 'https://rdap.nic.it/domain/',
            'nl': 'https://rdap.sidn.nl/domain/',
            'eu': 'https://rdap.eu/domain/',
            'ca': 'https://rdap.ca/domain/',
            'au': 'https://rdap.auda.org.au/domain/',
            'br': 'https://rdap.registro.br/domain/',
            'mx': 'https://rdap.nic.mx/domain/',
            'ar': 'https://rdap.nic.ar/domain/',
            'cl': 'https://rdap.nic.cl/domain/',
            'pe': 'https://rdap.nic.pe/domain/',
            've': 'https://rdap.nic.ve/domain/',
            'uy': 'https://rdap.nic.uy/domain/',
            'py': 'https://rdap.nic.py/domain/',
            'bo': 'https://rdap.nic.bo/domain/',
            'ec': 'https://rdap.nic.ec/domain/',
        }

        # Determine RDAP server
        rdap_url = rdap_servers.get(tld)
        if not rdap_url:
            # Use ARIN as a fallback for unsupported TLDs
            rdap_url = 'https://rdap.arin.net/registry/domain/'
            if not return_result:
                print_colored(f"\n{'='*SEPARATOR_LENGTH}", Colors.CYAN)
                print_colored(f"🌐 DOMAIN: {domain}", Colors.BOLD + Colors.WHITE)
                print_colored(f"📡 METHOD: RDAP (ARIN fallback)", Colors.CYAN)
                print_colored(f"⚠️  STATUS: Using ARIN server as fallback", Colors.YELLOW)
                print_colored(f"💡 SUGGESTION: TLD '{tld}' is not in the main list, trying ARIN", Colors.YELLOW)
                print_colored(f"{'='*SEPARATOR_LENGTH}", Colors.CYAN)

        # Build the curl command safely
        full_url = f"{rdap_url}{rdap_domain}"
        # Validate that the domain does not contain dangerous characters for shell injection
        if not re.match(r'^[a-zA-Z0-9.-]+$', rdap_domain):
            raise ValueError(f"Invalid domain: {rdap_domain}")
        curl_cmd = f'curl -s "{full_url}" | jq -r \'.events // [] | .[] | select(.eventAction == "expiration") | .eventDate\''

        # Run the curl command with jq (silent)
        result = subprocess.run(curl_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=TIMEOUT_RDAP)

        if result.returncode != 0:
            error_msg = result.stderr.strip()
            if "jq: command not found" in error_msg:
                if not return_result:
                    print_colored(f"\n{'='*SEPARATOR_LENGTH}", Colors.CYAN)
                    print_colored(f"🌐 DOMAIN: {domain}", Colors.BOLD + Colors.WHITE)
                    print_colored(f"📡 METHOD: RDAP", Colors.CYAN)
                    print_colored(f"❌ STATUS: jq not installed", Colors.RED)
                    print_colored(f"💡 SUGGESTION: Install jq to process JSON data", Colors.YELLOW)
                    print_colored(f"{'='*SEPARATOR_LENGTH}", Colors.CYAN)
                return {"domain": domain, "expiry": "jq not installed", "days": MSG_NOT_AVAILABLE, "status": "ERROR", "color": Colors.RED}
            elif "curl: command not found" in error_msg:
                if not return_result:
                    print_colored(f"\n{'='*SEPARATOR_LENGTH}", Colors.CYAN)
                    print_colored(f"🌐 DOMAIN: {domain}", Colors.BOLD + Colors.WHITE)
                    print_colored(f"📡 METHOD: RDAP", Colors.CYAN)
                    print_colored(f"❌ STATUS: curl not installed", Colors.RED)
                    print_colored(f"💡 SUGGESTION: Install curl to perform HTTP queries", Colors.YELLOW)
                    print_colored(f"{'='*SEPARATOR_LENGTH}", Colors.CYAN)
                return {"domain": domain, "expiry": "curl not installed", "days": MSG_NOT_AVAILABLE, "status": "ERROR", "color": Colors.RED}
            else:
                # Try ARIN as a fallback if it's not the main server
                if rdap_url != 'https://rdap.arin.net/registry/domain/':
                    if not return_result:
                        print_colored(f"\n{'='*SEPARATOR_LENGTH}", Colors.CYAN)
                        print_colored(f"🌐 DOMAIN: {domain}", Colors.BOLD + Colors.WHITE)
                        print_colored(f"📡 METHOD: RDAP (ARIN fallback)", Colors.CYAN)
                        print_colored(f"⚠️  STATUS: Main server failed, trying ARIN", Colors.YELLOW)
                        print_colored(f"💡 SUGGESTION: Trying ARIN server as fallback", Colors.YELLOW)
                        print_colored(f"{'='*SEPARATOR_LENGTH}", Colors.CYAN)

                    # Try ARIN
                    arin_url = 'https://rdap.arin.net/registry/domain/'
                    # Validate domain before using it in a shell command
                    main_domain = get_main_domain(domain)
                    if not re.match(r'^[a-zA-Z0-9.-]+$', main_domain):
                        raise ValueError(f"Invalid domain: {main_domain}")
                    arin_full_url = f"{arin_url}{main_domain}"
                    arin_curl_cmd = f'curl -s "{arin_full_url}" | jq -r \'.events // [] | .[] | select(.eventAction == "expiration") | .eventDate\''

                    arin_result = subprocess.run(arin_curl_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=15)

                    if arin_result.returncode == 0 and arin_result.stdout.strip() and arin_result.stdout.strip() != "null":
                        # ARIN worked, use its result
                        expiry_date_str = arin_result.stdout.strip()
                        # Continue with normal processing
                    else:
                        # ARIN also failed
                        if not return_result:
                            print_colored(f"\n{'='*SEPARATOR_LENGTH}", Colors.CYAN)
                            print_colored(f"🌐 DOMAIN: {domain}", Colors.BOLD + Colors.WHITE)
                            print_colored(f"📡 METHOD: RDAP", Colors.CYAN)
                            print_colored(f"❌ STATUS: RDAP error (both servers)", Colors.RED)
                            print_colored(f"💡 SUGGESTION: Error in RDAP query", Colors.YELLOW)
                            print_colored(f"{'='*SEPARATOR_LENGTH}", Colors.CYAN)
                        return {"domain": domain, "expiry": f"{MSG_ERROR_RDAP}: {error_msg[:ERROR_MSG_MAX_LENGTH]}...", "days": MSG_NOT_AVAILABLE, "status": "ERROR", "color": Colors.RED}
                else:
                    # Already using ARIN and it failed
                    if not return_result:
                        print_colored(f"\n{'='*SEPARATOR_LENGTH}", Colors.CYAN)
                        print_colored(f"🌐 DOMAIN: {domain}", Colors.BOLD + Colors.WHITE)
                        print_colored(f"📡 METHOD: RDAP", Colors.CYAN)
                        print_colored(f"❌ STATUS: RDAP error", Colors.RED)
                        print_colored(f"💡 SUGGESTION: Error in RDAP query", Colors.YELLOW)
                        print_colored(f"{'='*SEPARATOR_LENGTH}", Colors.CYAN)
                    return {"domain": domain, "expiry": f"{MSG_ERROR_RDAP}: {error_msg[:ERROR_MSG_MAX_LENGTH]}...", "days": MSG_NOT_AVAILABLE, "status": "ERROR", "color": Colors.RED}
        else:
            expiry_date_str = result.stdout.strip()

        # Check if the response indicates an error or there is no expiration date
        if not expiry_date_str or expiry_date_str == "null":
            # Try to get the full JSON response to check whether it is an error
            # Validate domain before using it (already validated above, but for safety)
            if not re.match(r'^[a-zA-Z0-9.-]+$', rdap_domain):
                raise ValueError(f"Invalid domain: {rdap_domain}")
            curl_raw_cmd = f'curl -s "{full_url}"'
            raw_result = subprocess.run(curl_raw_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=15)

            if raw_result.returncode == 0 and raw_result.stdout.strip():
                try:
                    data = json.loads(raw_result.stdout)

                    # Check whether it is an error response
                    if data.get('objectClassName') == 'error' or 'errorCode' in data:
                        if not return_result:
                            print_colored(f"\n{'='*SEPARATOR_LENGTH}", Colors.CYAN)
                            print_colored(f"🌐 DOMAIN: {domain}", Colors.BOLD + Colors.WHITE)
                            print_colored(f"📡 METHOD: RDAP", Colors.CYAN)
                            print_colored(f"📊 STATUS: No RDAP information", Colors.YELLOW)
                            print_colored(f"💡 SUGGESTION: The domain exists but RDAP has no information", Colors.YELLOW)
                            print_colored(f"{'='*SEPARATOR_LENGTH}", Colors.CYAN)
                        return {"domain": domain, "expiry": "No RDAP info", "days": MSG_NOT_AVAILABLE, "status": "INFO", "color": Colors.YELLOW}

                    # If it is not an error but there are no expiration events
                    if 'events' not in data or not data['events']:
                        if not return_result:
                            print_colored(f"\n{'='*SEPARATOR_LENGTH}", Colors.CYAN)
                            print_colored(f"🌐 DOMAIN: {domain}", Colors.BOLD + Colors.WHITE)
                            print_colored(f"📡 METHOD: RDAP", Colors.CYAN)
                            print_colored(f"📊 STATUS: No expiration events", Colors.YELLOW)
                            print_colored(f"💡 SUGGESTION: The domain exists but has no expiration events", Colors.YELLOW)
                            print_colored(f"{'='*SEPARATOR_LENGTH}", Colors.CYAN)
                        return {"domain": domain, "expiry": "No RDAP events", "days": MSG_NOT_AVAILABLE, "status": "INFO", "color": Colors.YELLOW}

                except json.JSONDecodeError:
                    pass  # If it is not valid JSON, continue with the generic message

            # If we did not find expiration information
            if not return_result:
                print_colored(f"\n{'='*SEPARATOR_LENGTH}", Colors.CYAN)
                print_colored(f"🌐 DOMAIN: {domain}", Colors.BOLD + Colors.WHITE)
                print_colored(f"📡 METHOD: RDAP", Colors.CYAN)
                print_colored(f"📊 STATUS: No information", Colors.YELLOW)
                print_colored(f"💡 SUGGESTION: The domain exists but there is no expiration information", Colors.YELLOW)
                print_colored(f"{'='*SEPARATOR_LENGTH}", Colors.CYAN)
            return {"domain": domain, "expiry": MSG_NO_INFO, "days": MSG_NOT_AVAILABLE, "status": "INFO", "color": Colors.YELLOW}

        # Parse ISO 8601 date (e.g.: 2025-10-29T23:59:59Z)
        try:
            # Remove 'Z' and parse
            clean_date = expiry_date_str.replace('Z', '').replace('T', ' ')
            if '.' in clean_date:
                # Handle microseconds if present
                clean_date = clean_date.split('.')[0]

            expiry_date = datetime.datetime.strptime(clean_date, "%Y-%m-%d %H:%M:%S")
            days = calculate_days_remaining(expiry_date)
            color, status = get_status_from_days(days)

            result_data = {
                "domain": domain,
                "expiry": expiry_date.strftime('%d/%m/%Y'),
                "days": days,
                "status": status,
                "color": color
            }

            if not return_result:
                # Improved display format
                print_colored(f"\n{'='*SEPARATOR_LENGTH}", Colors.CYAN)
                print_colored(f"🌐 DOMAIN: {domain}", Colors.BOLD + Colors.WHITE)
                print_colored(f"📡 METHOD: RDAP", Colors.CYAN)
                print_colored(f"📅 EXPIRATION DATE: {expiry_date.strftime('%d/%m/%Y')}", color)
                print_colored(f"⏰ TIME: {expiry_date.strftime('%H:%M:%S')}", color)
                print_colored(f"📊 DAYS REMAINING: {days} days", color)
                print_colored(f"🚨 STATUS: {status}", color)
                print_colored(f"{'='*SEPARATOR_LENGTH}", Colors.CYAN)

                # Show status explanation
                # show_status_explanation()

            return result_data

        except ValueError as e:
            if not return_result:
                print_colored(f"\n{'='*SEPARATOR_LENGTH}", Colors.CYAN)
                print_colored(f"❌ ERROR: {domain}", Colors.BOLD + Colors.RED)
                print_colored(f"🔍 Unrecognized date format: {expiry_date_str}", Colors.RED)
                print_colored(f"{'='*SEPARATOR_LENGTH}", Colors.CYAN)
            return {"domain": domain, "expiry": MSG_ERROR_FORMAT, "days": MSG_NOT_AVAILABLE, "status": "ERROR", "color": Colors.RED}

    except subprocess.TimeoutExpired:
        if not return_result:
            print_colored(f"\n{'='*SEPARATOR_LENGTH}", Colors.CYAN)
            print_colored(f"❌ ERROR: {domain}", Colors.BOLD + Colors.RED)
            print_colored(f"⏰ Timeout while querying RDAP", Colors.RED)
            print_colored(f"{'='*SEPARATOR_LENGTH}", Colors.CYAN)
        return {"domain": domain, "expiry": "Timeout", "days": MSG_NOT_AVAILABLE, "status": "ERROR", "color": Colors.RED}
    except Exception as e:
        if not return_result:
            print_colored(f"\n{'='*SEPARATOR_LENGTH}", Colors.CYAN)
            print_colored(f"❌ ERROR: {domain}", Colors.BOLD + Colors.RED)
            print_colored(f"🔍 Error querying RDAP: {e}", Colors.RED)
            print_colored(f"{'='*SEPARATOR_LENGTH}", Colors.CYAN)
        return {"domain": domain, "expiry": MSG_ERROR, "days": MSG_NOT_AVAILABLE, "status": "ERROR", "color": Colors.RED}

def get_main_domain(domain):
    """Extract the main domain from a subdomain"""
    parts = domain.split('.')
    if len(parts) >= 3:
        # It's a subdomain, return the last 2 parts (domain.tld)
        return '.'.join(parts[-2:])
    return domain

def check_whois_expiry(domain, return_result=False, skip_dns_check=False):
    # FIRST: Check if the domain exists in DNS (only if not skipped)
    if not skip_dns_check and not check_dns_existence(domain):
        if not return_result:
            print_colored(f"\n{'='*SEPARATOR_LENGTH}", Colors.CYAN)
            print_colored(f"🌐 DOMAIN: {domain}", Colors.BOLD + Colors.WHITE)
            print_colored(f"📡 METHOD: WHOIS", Colors.CYAN)
            print_colored(f"❌ STATUS: DOMAIN DOES NOT EXIST", Colors.RED)
            print_colored(f"💡 SUGGESTION: Check the domain", Colors.YELLOW)
            print_colored(f"{'='*SEPARATOR_LENGTH}", Colors.CYAN)
        return {"domain": domain, "expiry": MSG_DOMAIN_NOT_EXISTS, "days": MSG_NOT_AVAILABLE, "status": "ERROR", "color": Colors.RED}

    # NEW: If it's a subdomain, use the main domain for WHOIS
    main_domain = get_main_domain(domain)
    whois_domain = main_domain if main_domain != domain else domain

    # SECOND: If the domain exists, proceed with WHOIS
    try:
        result = subprocess.run(["whois", whois_domain], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=TIMEOUT_WHOIS)
        lines = result.stdout.splitlines()

        expiry_patterns = [
            "Expiry", "Expiration", "Expires", "Registry Expiry", "Domain Expiration",
            "Expiration Date", "Expiry Date", "Expires On", "Expiration Time",
            "Fecha de vencimiento", "Fecha de expiración", "Vencimiento"
        ]

        expiry_line = None
        for pattern in expiry_patterns:
            expiry_line = next((line for line in lines if pattern.lower() in line.lower()), None)
            if expiry_line:
                break

        # If we don't find a standard pattern, look for lines that contain dates
        if not expiry_line:
            date_pattern = r'\d{4}-\d{2}-\d{2}|\d{2}/\d{2}/\d{4}|\d{2}-\d{2}-\d{4}'
            for line in lines:
                if re.search(date_pattern, line) and any(keyword in line.lower() for keyword in ['expir', 'venc', 'end']):
                    expiry_line = line
                    break

        if not expiry_line:
            # Look for any line containing a date and related words
            for line in lines:
                if any(word in line.lower() for word in ['expir', 'venc', 'end', 'until', 'until:']) and any(char.isdigit() for char in line):
                    return {"domain": domain, "expiry": "Info found", "days": MSG_NOT_AVAILABLE, "status": "INFO", "color": Colors.GREEN}

            # If we don't find information, report no info
            if not return_result:
                print_colored(f"\n{'='*SEPARATOR_LENGTH}", Colors.CYAN)
                print_colored(f"🌐 DOMAIN: {domain}", Colors.BOLD + Colors.WHITE)
                print_colored(f"📡 METHOD: WHOIS", Colors.CYAN)
                print_colored(f"📊 STATUS: No information", Colors.YELLOW)
                print_colored(f"💡 SUGGESTION: The domain exists but there is no expiration information", Colors.YELLOW)
                print_colored(f"{'='*SEPARATOR_LENGTH}", Colors.CYAN)
            return {"domain": domain, "expiry": MSG_NO_INFO, "days": MSG_NOT_AVAILABLE, "status": "INFO", "color": Colors.YELLOW}

        # Extract the date from the found line
        try:
            # Try different date formats

            # Look for date in ISO format (YYYY-MM-DD)
            iso_match = re.search(r'(\d{4}-\d{2}-\d{2})', expiry_line)
            if iso_match:
                date_str = iso_match.group(1)
                expiry_date = datetime.datetime.strptime(date_str, "%Y-%m-%d")
            else:
                # Look for date in common format (DD-MM-YYYY or MM/DD/YYYY)
                date_match = re.search(r'(\d{1,2})[/-](\d{1,2})[/-](\d{4})', expiry_line)
                if date_match:
                    day, month, year = date_match.groups()
                    expiry_date = datetime.datetime.strptime(f"{year}-{month.zfill(2)}-{day.zfill(2)}", "%Y-%m-%d")
                else:
                    # Try to parse the whole line
                    if not return_result:
                        print_colored(f"\n{'='*SEPARATOR_LENGTH}", Colors.CYAN)
                        print_colored(f"🌐 DOMAIN: {domain}", Colors.BOLD + Colors.WHITE)
                        print_colored(f"📡 METHOD: WHOIS", Colors.CYAN)
                        print_colored(f"❌ STATUS: Unrecognized date format", Colors.RED)
                        print_colored(f"💡 SUGGESTION: Invalid date format in: {expiry_line.strip()}", Colors.YELLOW)
                        print_colored(f"{'='*SEPARATOR_LENGTH}", Colors.CYAN)
                    return {"domain": domain, "expiry": "Format error", "days": MSG_NOT_AVAILABLE, "status": "ERROR", "color": Colors.RED}

            days = calculate_days_remaining(expiry_date)
            color, status = get_status_from_days(days)

            result_data = {
                "domain": domain,
                "expiry": expiry_date.strftime('%d/%m/%Y'),
                "days": days,
                "status": status,
                "color": color
            }

            if not return_result:
                # Improved display format
                print_colored(f"\n{'='*SEPARATOR_LENGTH}", Colors.CYAN)
                print_colored(f"🌐 DOMAIN: {domain}", Colors.BOLD + Colors.WHITE)
                print_colored(f"📅 EXPIRATION DATE: {expiry_date.strftime('%d/%m/%Y')}", color)
                print_colored(f"⏰ TIME: {expiry_date.strftime('%H:%M:%S')}", color)
                print_colored(f"📊 DAYS REMAINING: {days} days", color)
                print_colored(f"🚨 STATUS: {status}", color)
                print_colored(f"{'='*SEPARATOR_LENGTH}", Colors.CYAN)

                # Show status explanation
                # show_status_explanation()

            return result_data

        except ValueError as e:
            if not return_result:
                print_colored(f"\n{'='*SEPARATOR_LENGTH}", Colors.CYAN)
                print_colored(f"❌ ERROR: {domain}", Colors.BOLD + Colors.RED)
                print_colored(f"🔍 Unrecognized date format in: {expiry_line.strip()}", Colors.RED)
                print_colored(f"{'='*SEPARATOR_LENGTH}", Colors.CYAN)
            return {"domain": domain, "expiry": MSG_ERROR_FORMAT, "days": MSG_NOT_AVAILABLE, "status": "ERROR", "color": Colors.RED}

    except Exception as e:
        if not return_result:
            print_colored(f"\n{'='*SEPARATOR_LENGTH}", Colors.CYAN)
            print_colored(f"❌ ERROR: {domain}", Colors.BOLD + Colors.RED)
            print_colored(f"🔍 Error querying WHOIS: {e}", Colors.RED)
            print_colored(f"{'='*SEPARATOR_LENGTH}", Colors.CYAN)
        return {"domain": domain, "expiry": MSG_ERROR, "days": MSG_NOT_AVAILABLE, "status": "ERROR", "color": Colors.RED}

def check_ssl_expiry(domain, return_result=False, skip_dns_check=False):
    # FIRST: Check if the domain exists in DNS (only if not skipped)
    if not skip_dns_check and not check_dns_existence(domain):
        if not return_result:
            print_colored(f"\n{'='*SEPARATOR_LENGTH}", Colors.CYAN)
            print_colored(f"🔒 SSL CERTIFICATE: {domain}", Colors.BOLD + Colors.WHITE)
            print_colored(f"❌ STATUS: DOMAIN DOES NOT EXIST", Colors.RED)
            print_colored(f"💡 SUGGESTION: Check the domain", Colors.YELLOW)
            print_colored(f"{'='*SEPARATOR_LENGTH}", Colors.CYAN)
        return {"domain": domain, "expiry": MSG_DOMAIN_NOT_EXISTS, "days": MSG_NOT_AVAILABLE, "status": "ERROR", "color": Colors.RED}

    # SECOND: If the domain exists, proceed with SSL
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=TIMEOUT_SSL) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                expiry_str = cert['notAfter']  # e.g.: 'Oct 29 23:59:59 2025 GMT'
                expiry_date = datetime.datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
                days = calculate_days_remaining(expiry_date)
                color, status = get_status_from_days(days)

                result_data = {
                    "domain": domain,
                    "expiry": expiry_date.strftime('%d/%m/%Y'),
                    "days": days,
                    "status": status,
                    "color": color
                }

                if not return_result:
                    # Improved display format
                    print_colored(f"\n{'='*SEPARATOR_LENGTH}", Colors.CYAN)
                    print_colored(f"🔒 SSL CERTIFICATE: {domain}", Colors.BOLD + Colors.WHITE)
                    print_colored(f"📅 EXPIRATION DATE: {expiry_date.strftime('%d/%m/%Y')}", color)
                    print_colored(f"⏰ TIME: {expiry_date.strftime('%H:%M:%S')}", color)
                    print_colored(f"📊 DAYS REMAINING: {days} days", color)
                    print_colored(f"🚨 STATUS: {status}", color)
                    print_colored(f"{'='*SEPARATOR_LENGTH}", Colors.CYAN)

                    # Show status explanation
                    # show_status_explanation()

                return result_data

    except Exception as e:
        # If there is an SSL error but the domain exists
        if not return_result:
            print_colored(f"\n{'='*SEPARATOR_LENGTH}", Colors.CYAN)
            print_colored(f"🔒 SSL CERTIFICATE: {domain}", Colors.BOLD + Colors.WHITE)
            print_colored(f"❌ STATUS: SSL Error", Colors.RED)
            print_colored(f"💡 SUGGESTION: Validate the site's certificate", Colors.YELLOW)
            print_colored(f"{'='*SEPARATOR_LENGTH}", Colors.CYAN)
        return {"domain": domain, "expiry": MSG_ERROR_SSL, "days": MSG_NOT_AVAILABLE, "status": "ERROR", "color": Colors.RED}

def load_domains_from_file(path, max_domains=MAX_DOMAINS):
    try:
        with open(path, "r") as f:
            domains = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
            # Limit to the maximum number of domains per MAX_DOMAINS
            return domains[:max_domains]
    except FileNotFoundError:
        print_colored(f"File not found: {path}", Colors.RED)
        return []

def check_dns_existence_batch(domains):
    """Check DNS existence of multiple domains in parallel"""
    results = {}

    def check_single_domain(domain, result_queue):
        exists = check_dns_existence(domain)
        result_queue.put((domain, exists))

    # Create threads for each domain
    threads = []
    result_queue = queue.Queue()

    for domain in domains:
        thread = threading.Thread(target=check_single_domain, args=(domain, result_queue))
        threads.append(thread)
        thread.start()

    # Wait for all threads to finish
    for thread in threads:
        thread.join(timeout=TIMEOUT_THREAD_DNS)
        # Check if the thread is still alive after the timeout
        if thread.is_alive():
            # Thread did not finish in time, continue with the available results
            pass

    # Collect results
    while not result_queue.empty():
        try:
            domain, exists = result_queue.get_nowait()
            results[domain] = exists
        except queue.Empty:
            break

    return results

def calculate_days_remaining(expiry_date):
    """
    Calculate the days remaining until the expiration date.

    Args:
        expiry_date: datetime.datetime with the expiration date

    Returns:
        int: Number of days remaining (can be negative if already expired)
    """
    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    delta = expiry_date - now
    return delta.days

def get_status_from_days(days):
    """
    Determine color and status based on remaining days.
    Used for individual results (WHOIS, RDAP, SSL).

    Args:
        days: int with remaining days

    Returns:
        tuple: (color, status) where color is Colors.* and status is a string
    """
    if days < DAYS_CRITICAL_THRESHOLD:
        return (Colors.RED, "🔴 CRITICAL")
    elif days < DAYS_WARNING_THRESHOLD:
        return (Colors.YELLOW, "🟡 WARNING")
    else:
        return (Colors.GREEN, "🟢 SAFE")

def get_color_from_days(days):
    """
    Determine color based on remaining days.
    Handles both int values and other types (returns YELLOW for non-int).
    Used for domain_days and ssl_days in combined results.

    Args:
        days: int with remaining days, or any other type

    Returns:
        str: Color (Colors.RED, Colors.YELLOW, or Colors.GREEN)
    """
    if isinstance(days, int):
        if days < DAYS_CRITICAL_THRESHOLD:
            return Colors.RED
        elif days < DAYS_WARNING_THRESHOLD:
            return Colors.YELLOW
        else:
            return Colors.GREEN
    else:
        return Colors.YELLOW

def filter_existing_domains(domains, dns_results):
    """
    Filter domains that exist in DNS based on the DNS verification results.

    Args:
        domains: List of domains to filter
        dns_results: Dictionary with DNS verification results (domain -> bool)

    Returns:
        List of domains that exist in DNS, keeping the original order
    """
    return [domain for domain in domains if dns_results.get(domain, False)]

def check_ssl_expiry_batch(domains):
    """Check SSL certificates for multiple domains in parallel"""
    results = {}

    def check_single_ssl(domain, result_queue):
        try:
            result = check_ssl_expiry(domain, return_result=True, skip_dns_check=True)
            result_queue.put((domain, result))
        except Exception:
            result_queue.put((domain, None))

    # Create threads for each domain
    threads = []
    result_queue = queue.Queue()

    for domain in domains:
        thread = threading.Thread(target=check_single_ssl, args=(domain, result_queue))
        threads.append(thread)
        thread.start()

    # Wait for all threads to finish
    for thread in threads:
        thread.join(timeout=TIMEOUT_THREAD_SSL)
        # Check if the thread is still alive after the timeout
        if thread.is_alive():
            # Thread did not finish in time, continue with the available results
            pass

    # Collect results
    while not result_queue.empty():
        try:
            domain, result = result_queue.get_nowait()
            results[domain] = result
        except queue.Empty:
            break

    return results

def check_whois_expiry_batch(domains):
    """Check WHOIS for multiple domains in parallel (maximum 2 simultaneous)"""
    results = {}

    def check_single_whois(domain, result_queue):
        try:
            result = check_whois_expiry(domain, return_result=True, skip_dns_check=True)
            result_queue.put((domain, result))
        except Exception:
            result_queue.put((domain, None))

    # Process domains in groups to avoid overloading WHOIS servers
    batch_size = WHOIS_BATCH_SIZE
    for i in range(0, len(domains), batch_size):
        batch_domains = domains[i:i + batch_size]

        # Create threads for the current batch
        threads = []
        result_queue = queue.Queue()

        for domain in batch_domains:
            thread = threading.Thread(target=check_single_whois, args=(domain, result_queue))
            threads.append(thread)
            thread.start()

        # Wait for all threads in the batch to finish
        for thread in threads:
            thread.join(timeout=TIMEOUT_THREAD_WHOIS)
            # Check if the thread is still alive after the timeout
            if thread.is_alive():
                # Thread did not finish in time, continue with the available results
                pass

        # Collect results for the batch
        while not result_queue.empty():
            try:
                domain, result = result_queue.get_nowait()
                results[domain] = result
            except queue.Empty:
                break

        # Pause between batches to avoid rate limiting
        if i + batch_size < len(domains):
            time.sleep(SLEEP_BETWEEN_BATCHES)

    return results

def check_rdap_expiry_batch(domains):
    """Check RDAP for multiple domains in parallel"""
    results = {}

    def check_single_rdap(domain, result_queue):
        try:
            result = check_rdap_expiry(domain, return_result=True, skip_dns_check=True)
            result_queue.put((domain, result))
        except Exception:
            result_queue.put((domain, None))

    # Create threads for each domain
    threads = []
    result_queue = queue.Queue()

    for domain in domains:
        thread = threading.Thread(target=check_single_rdap, args=(domain, result_queue))
        threads.append(thread)
        thread.start()

    # Wait for all threads to finish
    for thread in threads:
        thread.join(timeout=TIMEOUT_THREAD_RDAP)
        # Check if the thread is still alive after the timeout
        if thread.is_alive():
            # Thread did not finish in time, continue with the available results
            pass

    # Collect results
    while not result_queue.empty():
        try:
            domain, result = result_queue.get_nowait()
            results[domain] = result
        except queue.Empty:
            break

    return results



def display_results_matrix(results_data, title, check_type):
    """Display results in a 4x5 matrix format with all the data"""
    # Calculate dynamic centering for the title and the matrix
    terminal_width = get_terminal_width()
    title_text = f"📊 {title}"
    title_margin = (terminal_width - len(title_text)) // 2

    # Create a matrix of 4 columns and 5 rows
    matrix = []
    for i in range(0, len(results_data), MATRIX_COLUMNS):
        row = results_data[i:i+MATRIX_COLUMNS]
        # Fill with empty spaces if the row is not complete
        while len(row) < MATRIX_COLUMNS:
            row.append({"domain": "", "expiry": "", "days": "", "status": "", "color": Colors.WHITE})
        matrix.append(row)

    # Calculate column width using the helper function
    matrix_total_width = terminal_width
    column_width = calculate_matrix_column_width(terminal_width)

    # No margin since we use the full width
    matrix_margin = 0

    print_colored(f"{' ' * title_margin}{title_text}", Colors.WHITE)

    # Show the top frame of the matrix (no header)
    print_colored(f"{' ' * matrix_margin}╔" + "═" * (matrix_total_width - MATRIX_BORDER_WIDTH) + "╗", Colors.CYAN)

    # Show data rows
    for i, row in enumerate(matrix):
        # First row with domains
        print_colored(f"{' ' * matrix_margin}║ ", Colors.CYAN, end="")
        for j, result in enumerate(row):
            if result["domain"]:
                domain_text = f"{truncate_to_width(result['domain'], column_width):^{column_width}}"
                print_colored(domain_text, Colors.WHITE, end="")
            else:
                print_colored(" " * column_width, end="")

            if j < len(row) - 1:
                print_colored(" ║ ", Colors.CYAN, end="")

        print_colored(" ║", Colors.CYAN)
        # Second row with expiration data
        print_colored(f"{' ' * matrix_margin}║ ", Colors.CYAN, end="")
        for j, result in enumerate(row):
            if result["expiry"]:
                expiry_text = f"{truncate_to_width(result['expiry'], column_width):^{column_width}}"
                print_colored(expiry_text, result["color"], end="")
            else:
                print_colored(" " * column_width, end="")

            if j < len(row) - 1:
                print_colored(" ║ ", Colors.CYAN, end="")

        print_colored(" ║", Colors.CYAN)
        # Third row with days and status
        print_colored(f"{' ' * matrix_margin}║ ", Colors.CYAN, end="")
        for j, result in enumerate(row):
            if result["days"] != "" and result["days"] != MSG_NOT_AVAILABLE:
                days_text = f"{result['days']} days"
                # Adjust the width so the full text fits
                if len(days_text) > column_width:
                    days_text = f"{days_text[:column_width-TEXT_TRUNCATE_SUFFIX_LENGTH]}..."
                days_text = f"{days_text:^{column_width}}"
                print_colored(days_text, result["color"], end="")
            else:
                print_colored(" " * column_width, end="")

            if j < len(row) - 1:
                print_colored(" ║ ", Colors.CYAN, end="")

        print_colored(" ║", Colors.CYAN)
        # Add separator line between domain groups (except the last one)
        if i < len(matrix) - 1:
            print_colored(f"{' ' * matrix_margin}╟" + "═" * (matrix_total_width - MATRIX_BORDER_WIDTH) + "╢", Colors.CYAN)

    # Show the bottom frame of the matrix
    print_colored(f"{' ' * matrix_margin}╚" + "═" * (matrix_total_width - MATRIX_BORDER_WIDTH) + "╝", Colors.CYAN)

def check_combined_expiry(domain, return_result=False, skip_ssl_check=False):
    """Check expiration combining WHOIS, RDAP and SSL with optimized fallback logic"""
    # FIRST: Check if the domain exists in DNS (fast)
    if not check_dns_existence(domain):
        if not return_result:
            print_colored(f"\n{'='*SEPARATOR_LENGTH}", Colors.CYAN)
            print_colored(f"🌐 DOMAIN: {domain}", Colors.BOLD + Colors.WHITE)
            print_colored(f"❌ STATUS: DOMAIN DOES NOT EXIST", Colors.RED)
            print_colored(f"💡 SUGGESTION: Check the domain", Colors.YELLOW)
            print_colored(f"{'='*SEPARATOR_LENGTH}", Colors.CYAN)
        return {
            "domain": domain,
            "domain_expiry": MSG_DOMAIN_NOT_EXISTS,
            "domain_days": MSG_NOT_AVAILABLE,
            "domain_color": Colors.RED,
            "ssl_expiry": MSG_NOT_AVAILABLE,
            "ssl_days": MSG_NOT_AVAILABLE,
            "ssl_color": Colors.RED,
            "status": "ERROR",
            "method": "DNS"
        }

    # SECOND: Get domain information (WHOIS or RDAP) - optimized with a single DNS check
    domain_result = None
    domain_method = MSG_METHOD_NONE

    # Try WHOIS first (skip DNS check since it was already done)
    try:
        whois_result = check_whois_expiry(domain, return_result=True, skip_dns_check=True)
        if whois_result and whois_result.get("expiry") not in [MSG_DOMAIN_NOT_EXISTS, MSG_NO_INFO, MSG_ERROR, MSG_ERROR_FORMAT]:
            domain_result = whois_result
            domain_method = "WHOIS"
        else:
            # If WHOIS fails, try RDAP (skip DNS check since it was already done)
            rdap_result = check_rdap_expiry(domain, return_result=True, skip_dns_check=True)
            if rdap_result and rdap_result.get("expiry") not in [MSG_DOMAIN_NOT_EXISTS, MSG_NO_INFO, MSG_ERROR, MSG_ERROR_FORMAT, MSG_TLD_NOT_SUPPORTED]:
                domain_result = rdap_result
                domain_method = "RDAP"
    except Exception:
        # If there's an error, continue without domain information
        pass

    # THIRD: Get SSL information whenever the domain exists (skip DNS check since it was already done)
    ssl_result = None
    if not skip_ssl_check:
        try:
            ssl_result = check_ssl_expiry(domain, return_result=True, skip_dns_check=True)
        except Exception:
            # If there's an error, continue without SSL information
            pass

    # FOURTH: Prepare combined result
    if domain_result:
        domain_expiry = domain_result.get("expiry", MSG_NO_INFO)
        domain_days = domain_result.get("days", MSG_NOT_AVAILABLE)
        domain_color = domain_result.get("color", Colors.WHITE)
        domain_status = domain_result.get("status", "INFO")
    else:
        domain_expiry = MSG_NO_INFO
        domain_days = MSG_NOT_AVAILABLE
        domain_color = Colors.YELLOW
        domain_status = "INFO"

    if ssl_result and ssl_result.get("expiry") not in [MSG_DOMAIN_NOT_EXISTS, MSG_ERROR_SSL]:
        ssl_expiry = ssl_result.get("expiry", MSG_NO_INFO)
        ssl_days = ssl_result.get("days", MSG_NOT_AVAILABLE)
        ssl_color = ssl_result.get("color", Colors.WHITE)
    else:
        ssl_expiry = MSG_NO_INFO
        ssl_days = MSG_NOT_AVAILABLE
        ssl_color = Colors.YELLOW

    # Determine individual colors according to the established logic
    domain_color = get_color_from_days(domain_days)
    ssl_color = get_color_from_days(ssl_days)

    if not return_result:
        print_colored(f"\n{'='*SEPARATOR_LENGTH}", Colors.CYAN)
        print_colored(f"🌐 DOMAIN: {domain}", Colors.BOLD + Colors.WHITE)
        print_colored(f"📡 DOMAIN METHOD: {domain_method}", Colors.CYAN)
        print_colored(f"📅 DOM: {domain_expiry}", domain_color)
        print_colored(f"🔒 SSL: {ssl_expiry}", ssl_color)
        print_colored(f"📊 DOM DAYS: {domain_days} | SSL: {ssl_days}", Colors.WHITE)
        print_colored(f"{'='*SEPARATOR_LENGTH}", Colors.CYAN)

    return {
        "domain": domain,
        "domain_expiry": domain_expiry,
        "domain_days": domain_days,
        "domain_color": domain_color,
        "ssl_expiry": ssl_expiry,
        "ssl_days": ssl_days,
        "ssl_color": ssl_color,
        "status": domain_status,
        "method": domain_method
    }

def display_combined_results_matrix(results_data, title):
    """Display combined results in matrix format with DOM and SSL"""
    # Calculate dynamic centering for the title and the matrix
    terminal_width = get_terminal_width()
    title_text = f"📊 {title}"
    title_margin = (terminal_width - len(title_text)) // 2

    # Create a matrix of 4 columns
    matrix = []
    for i in range(0, len(results_data), MATRIX_COLUMNS):
        row = results_data[i:i+MATRIX_COLUMNS]
        # Fill with empty spaces if the row is not complete
        while len(row) < MATRIX_COLUMNS:
            row.append({
                "domain": "",
                "domain_expiry": "",
                "domain_days": "",
                "domain_color": Colors.WHITE,
                "ssl_expiry": "",
                "ssl_days": "",
                "ssl_color": Colors.WHITE
            })
        matrix.append(row)

    # Calculate column width using the helper function
    matrix_total_width = terminal_width
    column_width = calculate_matrix_column_width(terminal_width)
    matrix_margin = 0  # The matrix uses the full width, no margin needed

    print_colored(f"{' ' * title_margin}{title_text}", Colors.WHITE)

    # Show the top frame of the matrix
    print_colored(f"{' ' * matrix_margin}╔" + "═" * (matrix_total_width - MATRIX_BORDER_WIDTH) + "╗", Colors.CYAN)

    # Show data rows
    for i, row in enumerate(matrix):
        # First row with domains
        print_colored(f"{' ' * matrix_margin}║ ", Colors.CYAN, end="")
        for j, result in enumerate(row):
            if result["domain"]:
                domain_text = f"{truncate_to_width(result['domain'], column_width):^{column_width}}"
                print_colored(domain_text, Colors.WHITE, end="")
            else:
                print_colored(" " * column_width, end="")

            if j < len(row) - 1:
                print_colored(" ║ ", Colors.CYAN, end="")

        print_colored(" ║", Colors.CYAN)
        # Second row with DOM: date
        print_colored(f"{' ' * matrix_margin}║ ", Colors.CYAN, end="")
        for j, result in enumerate(row):
            if result["domain_expiry"]:
                # If it's MSG_DOMAIN_NOT_EXISTS, don't show "DOM:"
                if result["domain_expiry"] == MSG_DOMAIN_NOT_EXISTS:
                    dom_text = f"{result['domain_expiry']}"
                else:
                    dom_text = f"DOM: {result['domain_expiry']}"

                if len(dom_text) > column_width:
                    dom_text = f"{dom_text[:column_width-TEXT_TRUNCATE_SUFFIX_LENGTH]}..."
                dom_text = f"{dom_text:^{column_width}}"

                # Apply color after the width calculation
                if result["domain_expiry"] != MSG_DOMAIN_NOT_EXISTS:
                    # Print each part separately to preserve colors
                    # Find the position of "DOM:"
                    dom_pos = dom_text.find("DOM:")
                    if dom_pos != -1:
                        # Print spaces before DOM:
                        print_colored(dom_text[:dom_pos], end="")
                        # Print DOM: in orange
                        print_colored("DOM:", RGB_LABEL, end="")
                        # Print the rest in the date's color
                        print_colored(dom_text[dom_pos+4:], result.get("domain_color", Colors.WHITE), end="")
                    else:
                        print_colored(dom_text, result.get("domain_color", Colors.WHITE), end="")
                else:
                    print_colored(dom_text, result.get("domain_color", Colors.WHITE), end="")
            else:
                print_colored(" " * column_width, end="")

            if j < len(row) - 1:
                print_colored(" ║ ", Colors.CYAN, end="")

        print_colored(" ║", Colors.CYAN)
        # Third row with SSL: date (only if the domain exists)
        print_colored(f"{' ' * matrix_margin}║ ", Colors.CYAN, end="")
        for j, result in enumerate(row):
            if result["ssl_expiry"] and result["ssl_expiry"] != MSG_NOT_AVAILABLE:
                ssl_text = f"SSL: {result['ssl_expiry']}"
                if len(ssl_text) > column_width:
                    ssl_text = f"{ssl_text[:column_width-TEXT_TRUNCATE_SUFFIX_LENGTH]}..."
                ssl_text = f"{ssl_text:^{column_width}}"

                # Apply color after the width calculation
                # Find the position of "SSL:"
                ssl_pos = ssl_text.find("SSL:")
                if ssl_pos != -1:
                    # Print spaces before SSL:
                    print_colored(ssl_text[:ssl_pos], end="")
                    # Print SSL: in orange
                    print_colored("SSL:", RGB_LABEL, end="")
                    # Print the rest in the date's color
                    print_colored(ssl_text[ssl_pos+4:], result.get("ssl_color", Colors.WHITE), end="")
                else:
                    print_colored(ssl_text, result.get("ssl_color", Colors.WHITE), end="")
            else:
                print_colored(" " * column_width, end="")

            if j < len(row) - 1:
                print_colored(" ║ ", Colors.CYAN, end="")

        print_colored(" ║", Colors.CYAN)
        # Fourth row with days (separate colors)
        print_colored(f"{' ' * matrix_margin}║ ", Colors.CYAN, end="")
        for j, result in enumerate(row):
            # Check if there is valid information to display
            has_domain_days = result["domain_days"] != "" and result["domain_days"] != MSG_NOT_AVAILABLE
            has_ssl_days = result["ssl_days"] != "" and result["ssl_days"] != MSG_NOT_AVAILABLE

            if has_domain_days or has_ssl_days:
                # Build the text with separate colors
                if has_domain_days:
                    dom_part = f"DOM:{result['domain_days']}"
                else:
                    dom_part = "DOM:N/A"

                if has_ssl_days:
                    ssl_part = f" SSL:{result['ssl_days']}"
                else:
                    ssl_part = " SSL:N/A"

                total_width = len(dom_part) + len(ssl_part)

                # Center the full text
                padding = max(0, column_width - total_width)
                left_padding = padding // 2
                right_padding = padding - left_padding

                # Print with separate colors
                print_colored(" " * left_padding, end="")
                # Print DOM: in orange, days in the domain's color
                print_colored("DOM:", RGB_LABEL, end="")
                if has_domain_days:
                    print_colored(f"{result['domain_days']}", result.get("domain_color", Colors.WHITE), end="")
                else:
                    print_colored(MSG_NOT_AVAILABLE, Colors.YELLOW, end="")
                # Print SSL: in orange, days in the SSL's color
                print_colored(" SSL:", RGB_LABEL, end="")
                if has_ssl_days:
                    print_colored(f"{result['ssl_days']}", result.get("ssl_color", Colors.WHITE), end="")
                else:
                    print_colored(MSG_NOT_AVAILABLE, Colors.YELLOW, end="")
                print_colored(" " * right_padding, end="")
            else:
                print_colored(" " * column_width, end="")

            if j < len(row) - 1:
                print_colored(" ║ ", Colors.CYAN, end="")

        print_colored(" ║", Colors.CYAN)
        # Add separator line between domain groups (except the last one)
        if i < len(matrix) - 1:
            print_colored(f"{' ' * matrix_margin}╟" + "═" * (matrix_total_width - MATRIX_BORDER_WIDTH) + "╢", Colors.CYAN)

    # Show the bottom frame of the matrix
    print_colored(f"{' ' * matrix_margin}╚" + "═" * (matrix_total_width - MATRIX_BORDER_WIDTH) + "╝", Colors.CYAN)

def update_matrix_character_by_character(old_results, new_results):
    """
    Updates the existing matrix character by character without destroying it.
    Replaces only the fields that have changed, keeping the structure.
    """
    try:
        # Get terminal dimensions
        terminal_width = get_terminal_width()

        # Calculate column width using the helper function
        matrix_total_width = terminal_width
        column_width = calculate_matrix_column_width(terminal_width)



        # For each domain in the results
        for i, (old_result, new_result) in enumerate(zip(old_results, new_results)):
            if old_result["domain"] != new_result["domain"]:
                continue  # Skip if the domain changed (shouldn't happen)

            # Calculate the row position in the matrix
            row_in_matrix = i // MATRIX_COLUMNS  # Each domain occupies 4 rows (domain, DOM, SSL, days)
            domain_column = i % MATRIX_COLUMNS   # Column within the row (0-3)

            # Calculate the absolute position on the screen
            # Each domain occupies 4 rows + 1 separator line (except the last one)
            base_row = 3 + (row_in_matrix * 5)  # 3 = title + top frame

            # Column position (accounting for margins and separators)
            column_start = 1 + (domain_column * (column_width + 3))  # +3 for " ║ "



            # UPDATE ROW 2: DOM: date
            if (old_result["domain_expiry"] != new_result["domain_expiry"] or
                old_result["domain_color"] != new_result["domain_color"]):

                # Build new DOM text
                if new_result["domain_expiry"] == MSG_DOMAIN_NOT_EXISTS:
                    dom_text = f"{new_result['domain_expiry']}"
                else:
                    dom_text = f"DOM: {new_result['domain_expiry']}"

                # Adjust exact length for character-by-character replacement
                if len(dom_text) > column_width:
                    dom_text = f"{dom_text[:column_width-TEXT_TRUNCATE_SUFFIX_LENGTH]}..."
                elif len(dom_text) < column_width:
                    # FILL WITH SPACES if shorter (main rule)
                    dom_text = dom_text.ljust(column_width)

                # Center the text
                padding = max(0, column_width - len(dom_text))
                left_padding = padding // 2
                dom_text = f"{' ' * left_padding}{dom_text}"
                if len(dom_text) < column_width:
                    dom_text = dom_text.ljust(column_width)



                # Move cursor and replace EXACTLY at the position
                print(f"\033[{base_row + 1};{column_start}H{dom_text}", end="", flush=True)

            # UPDATE ROW 3: SSL: date
            if (old_result["ssl_expiry"] != new_result["ssl_expiry"] or
                old_result["ssl_color"] != new_result["ssl_color"]):

                # Build new SSL text
                if new_result["ssl_expiry"] and new_result["ssl_expiry"] != MSG_NOT_AVAILABLE:
                    ssl_text = f"SSL: {new_result['ssl_expiry']}"
                else:
                    ssl_text = MSG_NOT_AVAILABLE

                # Adjust exact length for character-by-character replacement
                if len(ssl_text) > column_width:
                    ssl_text = f"{ssl_text[:column_width-TEXT_TRUNCATE_SUFFIX_LENGTH]}..."
                elif len(ssl_text) < column_width:
                    # FILL WITH SPACES if shorter (main rule)
                    ssl_text = ssl_text.ljust(column_width)

                # Center the text
                padding = max(0, column_width - len(ssl_text))
                left_padding = padding // 2
                ssl_text = f"{' ' * left_padding}{ssl_text}"
                if len(ssl_text) < column_width:
                    ssl_text = ssl_text.ljust(column_width)



                # Move cursor and replace EXACTLY at the position
                print(f"\033[{base_row + 2};{column_start}H{ssl_text}", end="", flush=True)

            # UPDATE ROW 4: Days (DOM: X SSL: Y)
            if (old_result["domain_days"] != new_result["domain_days"] or
                old_result["ssl_days"] != new_result["ssl_days"] or
                old_result["domain_color"] != new_result["domain_color"] or
                old_result["ssl_color"] != new_result["ssl_color"]):

                # Build new days text
                has_domain_days = new_result["domain_days"] != "" and new_result["domain_days"] != MSG_NOT_AVAILABLE
                has_ssl_days = new_result["ssl_days"] != "" and new_result["ssl_days"] != MSG_NOT_AVAILABLE

                if has_domain_days or has_ssl_days:
                    if has_domain_days:
                        dom_part = f"DOM:{new_result['domain_days']}"
                    else:
                        dom_part = "DOM:N/A"

                    if has_ssl_days:
                        ssl_part = f" SSL:{new_result['ssl_days']}"
                    else:
                        ssl_part = " SSL:N/A"

                    days_text = dom_part + ssl_part
                else:
                    days_text = "DOM:N/A SSL:N/A"

                # Adjust exact length for character-by-character replacement
                if len(days_text) > column_width:
                    days_text = f"{days_text[:column_width-TEXT_TRUNCATE_SUFFIX_LENGTH]}..."
                elif len(days_text) < column_width:
                    # FILL WITH SPACES if shorter (main rule)
                    days_text = days_text.ljust(column_width)

                # Center the text
                padding = max(0, column_width - len(days_text))
                left_padding = padding // 2
                days_text = f"{' ' * left_padding}{days_text}"
                if len(days_text) < column_width:
                    days_text = days_text.ljust(column_width)



                # Move cursor and replace EXACTLY at the position
                print(f"\033[{base_row + 3};{column_start}H{days_text}", end="", flush=True)

        return True

    except Exception as e:
        print(f"\n❌ Error updating matrix: {e}")
        return False

def get_domains_file_path():
    """Get the path of the domains.txt file"""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(script_dir, "domains.txt")

def load_and_validate_domains_file():
    """Load and validate the domains.txt file. Returns (domains, domains_file, script_dir) or (None, None, None) on error"""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    domains_file = os.path.join(script_dir, "domains.txt")

    if not os.path.isfile(domains_file):
        print_colored(f"❌ domains.txt file not found in: {script_dir}", Colors.RED)
        print_colored(f"💡 Create the domains.txt file in the same folder as the script", Colors.YELLOW)
        return None, None, None

    print_colored(f"\n📁 Processing file: {domains_file}", Colors.GREEN)
    domains = load_domains_from_file(domains_file)

    if not domains:
        print_colored(f"❌ No valid domains found in the file", Colors.RED)
        return None, None, None

    print_colored(f"📊 Processing {len(domains)} domains (maximum 20)...", Colors.CYAN)
    return domains, domains_file, script_dir

def build_error_result(domain, error_type=MSG_DOMAIN_NOT_EXISTS):
    """Build an error result dictionary"""
    error_messages = {
        MSG_DOMAIN_NOT_EXISTS: MSG_DOMAIN_NOT_EXISTS,
        MSG_ERROR_WHOIS: MSG_ERROR_WHOIS,
        MSG_ERROR_RDAP: MSG_ERROR_RDAP,
        MSG_ERROR_SSL: MSG_ERROR_SSL
    }
    return {
        "domain": domain,
        "expiry": error_messages.get(error_type, MSG_ERROR),
        "days": MSG_NOT_AVAILABLE,
        "status": "ERROR",
        "color": Colors.RED
    }

def process_single_check(domains, check_function, check_name, matrix_title):
    """Process verification of a single type (WHOIS, RDAP or SSL)"""
    # Check DNS for all domains in parallel
    dns_results = check_dns_existence_batch(domains)

    # Filter domains that exist
    existing_domains = filter_existing_domains(domains, dns_results)

    # Check using the specified function
    check_results = check_function(existing_domains)

    # Build results keeping the original order
    results = []
    for domain in domains:
        if domain in existing_domains:
            check_result = check_results.get(domain)
            if check_result:
                results.append(check_result)
            else:
                results.append(build_error_result(domain, f"Error {check_name}"))
        else:
            results.append(build_error_result(domain, MSG_DOMAIN_NOT_EXISTS))

    return results

def check_domains_file_integrity(domains_file, original_domains):
    """
    Verifies that the domains.txt file has not changed during execution.
    Returns True if the file is valid, False if it has changed.
    """
    try:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        domains_file_path = os.path.join(script_dir, domains_file)

        if not os.path.isfile(domains_file_path):
            return False, "domains.txt file not found"

        # Read current domains from the file
        current_domains = load_domains_from_file(domains_file_path)

        if not current_domains:
            return False, "domains.txt file is empty or corrupted"

        # Check that the number of domains is the same
        if len(current_domains) != len(original_domains):
            return False, f"Change in number of domains: {len(original_domains)} → {len(current_domains)}"

        # Check that the domains are the same (in the same order)
        for i, (original, current) in enumerate(zip(original_domains, current_domains)):
            if original != current:
                return False, f"Domain #{i+1} changed: '{original}' → '{current}'"

        return True, "Valid file"

    except Exception as e:
        return False, f"Error checking integrity: {e}"

def menu():
    while True:
        # Show ASCII art
        show_ascii_art()

        # Options menu dynamically centered
        terminal_width = get_terminal_width()

        menu_width = MENU_WIDTH
        margin = (terminal_width - menu_width) // 2

        menu_options = [
            ("1", "🔍", "Check domain expiration (WHOIS)"),
            ("2", "📡", "Check domain expiration (RDAP)"),
            ("3", "🔒", "Check SSL certificate expiration"),
            ("4", "🔄", "Combined check (WHOIS/RDAP + SSL)"),
            ("5", "🔁", "Continuous monitoring (WHOIS/RDAP + SSL)"),
            ("Q", "❌", "Exit"),
        ]

        print(f"\n{RGB_GREEN}{' ' * margin}╔{'═' * menu_width}╗{RESET_COLOR}")
        print(f"{RGB_GREEN}{' ' * margin}║{RGB_BLUE}{'DOMAINS & SSL VERIFIER':^52}{RGB_GREEN}║{RESET_COLOR}")
        print(f"{RGB_GREEN}{' ' * margin}║{Colors.WHITE}{'Version 1.0':^52}{RGB_GREEN}║{RESET_COLOR}")
        print(f"{RGB_GREEN}{' ' * margin}╠{'═' * menu_width}╣{RESET_COLOR}")
        for key, icon, label in menu_options:
            plain_row = f"[{key}] {icon} {label}"
            padding = ' ' * (menu_width - 1 - get_display_width(plain_row))
            print(f"{RGB_GREEN}{' ' * margin}║ {RGB_YELLOW}[{key}]{RGB_BLUE} {icon} {Colors.WHITE}{label}{padding}{RGB_GREEN}║{RESET_COLOR}")
        print(f"{RGB_GREEN}{' ' * margin}╚{'═' * menu_width}╝{RESET_COLOR}")

        # Show status explanation once on the main menu
        show_status_explanation()

        option = input(f"\n{RGB_BLUE}[?] {Colors.WHITE}Select an option {RGB_YELLOW}(1-5 or Q){Colors.WHITE}: ").strip()

        if option == "1":
            domains, domains_file, script_dir = load_and_validate_domains_file()
            if domains:
                results = process_single_check(domains, check_whois_expiry_batch, "WHOIS", "WHOIS VERIFICATION RESULTS")
                if results:
                    display_results_matrix(results, "WHOIS VERIFICATION RESULTS", "🌐")
                    input(f"\n{RGB_BLUE}[*] {Colors.WHITE}Press ENTER to return to the main menu...")
                else:
                    print_colored("❌ No valid results were obtained", Colors.RED)

        elif option == "2":
            domains, domains_file, script_dir = load_and_validate_domains_file()
            if domains:
                results = process_single_check(domains, check_rdap_expiry_batch, "RDAP", "RDAP VERIFICATION RESULTS")
                if results:
                    display_results_matrix(results, "RDAP VERIFICATION RESULTS", "📡")
                    input(f"\n{RGB_BLUE}[*] {Colors.WHITE}Press ENTER to return to the main menu...")
                else:
                    print_colored("❌ No valid results were obtained", Colors.RED)

        elif option == "3":
            domains, domains_file, script_dir = load_and_validate_domains_file()
            if domains:
                results = process_single_check(domains, check_ssl_expiry_batch, "SSL", "SSL VERIFICATION RESULTS")
                if results:
                    display_results_matrix(results, "SSL VERIFICATION RESULTS", "🔒")
                    input(f"\n{RGB_BLUE}[*] {Colors.WHITE}Press ENTER to return to the main menu...")
                else:
                    print_colored("❌ No valid results were obtained", Colors.RED)

        elif option == "4":
            domains, domains_file, script_dir = load_and_validate_domains_file()
            if domains:
                print_colored(f"🔄 Using combined check: WHOIS/RDAP + SSL", Colors.CYAN)

                results = perform_domain_verification("domains.txt")

                # Show only the final matrix
                if results:
                    display_combined_results_matrix(results, "COMBINED VERIFICATION RESULTS (WHOIS/RDAP + SSL)")

                    # Show centered message at the end
                    terminal_width = get_terminal_width()
                    message = "💡 The expiration time is expressed in days"
                    message_margin = (terminal_width - len(message)) // 2
                    print_colored(f"\n{' ' * message_margin}{message}", Colors.YELLOW)

                    input(f"\n{RGB_BLUE}[*] {Colors.WHITE}Press ENTER to return to the main menu...")
                else:
                    print_colored("❌ No valid results were obtained", Colors.RED)

        elif option == "5":
            domains, domains_file, script_dir = load_and_validate_domains_file()
            if domains:
                # Load original domains for integrity verification
                original_domains = domains.copy()

                # Perform initial verification
                results = perform_domain_verification("domains.txt")

                if results:
                    print_colored(f"📊 Processing {len(results)} domains (maximum 20)...", Colors.CYAN)
                    print_colored(f"🔁 Using continuous monitoring: WHOIS/RDAP + SSL", Colors.CYAN)

                    # Show initial matrix
                    display_combined_results_matrix(results, "CONTINUOUS MONITORING RESULTS (WHOIS/RDAP + SSL)")

                    # Show 8-hour countdown
                    terminal_width = get_terminal_width()

                    # Show CONTROL-R instructions message
                    ctrl_r_message = "💡 Press CONTROL-R to check immediately"
                    ctrl_r_margin = (terminal_width - len(ctrl_r_message)) // 2
                    print_colored(f"{' ' * ctrl_r_margin}{ctrl_r_message}", Colors.BLUE)

                    # Show centered message right after the countdown
                    message = "💡 The expiration time is expressed in days"
                    message_margin = (terminal_width - len(message)) // 2
                    print_colored(f"{' ' * message_margin}{message}", Colors.YELLOW)

                    # 8-hour countdown
                    total_seconds = MONITORING_INTERVAL_SECONDS

                    # Disable keyboard input
                    old_settings = disable_input()

                    try:
                        remaining_seconds = total_seconds
                        while remaining_seconds >= 0:
                            # Dynamically recalculate width and margins in case the terminal size changes
                            terminal_width = get_terminal_width()
                            ctrl_r_margin = (terminal_width - len(ctrl_r_message)) // 2
                            message_margin = (terminal_width - len(message)) // 2

                            hours = remaining_seconds // 3600
                            minutes = (remaining_seconds % 3600) // 60
                            seconds = remaining_seconds % 60

                            if remaining_seconds > 0:
                                countdown_message = f"⏰ NEXT CHECK IN: {hours:02d}:{minutes:02d}:{seconds:02d}"
                            else:
                                countdown_message = "🔄 CHECKING DOMAINS..."
                            countdown_margin = (terminal_width - len(countdown_message)) // 2

                            # Clear the previous line and show the new countdown
                            print(f"\r{' ' * countdown_margin}{Colors.RED}{countdown_message}{Colors.END}", end="", flush=True)

                            if remaining_seconds > 0:
                                # Fine polling: 10 times per second for better responsiveness
                                for _ in range(10):
                                    # Check domains.txt file integrity every 10 polls
                                    if _ == 0:  # Only on the first poll of each cycle
                                        integrity_valid, integrity_message = check_domains_file_integrity("domains.txt", original_domains)
                                        if not integrity_valid:
                                            # domains.txt file changed during execution
                                            error_message = f"❌ ERROR: {integrity_message}"
                                            error_margin = (terminal_width - len(error_message)) // 2
                                            print(f"\r{' ' * error_margin}{Colors.RED}{error_message}{Colors.END}", end="", flush=True)
                                            time.sleep(SLEEP_ERROR_DISPLAY)
                                            raise KeyboardInterrupt  # Return to the main menu

                                    ctrl_c, ctrl_r = check_for_ctrl_c()
                                    if ctrl_c:
                                        raise KeyboardInterrupt
                                    elif ctrl_r:
                                        # Perform immediate check
                                        # Clear the current countdown line to avoid \r leftovers
                                        print("\r\033[2K", end="", flush=True)
                                        print(f"\r{' ' * countdown_margin}{Colors.BLUE}🔄 Checking domains...{Colors.END}", end="", flush=True)

                                                                                # CHECK DOMAINS.TXT FILE INTEGRITY
                                        integrity_valid, integrity_message = check_domains_file_integrity("domains.txt", original_domains)

                                        if not integrity_valid:
                                            # domains.txt file changed during execution
                                            error_message = f"❌ ERROR: {integrity_message}"
                                            error_margin = (terminal_width - len(error_message)) // 2
                                            print(f"\r{' ' * error_margin}{Colors.RED}{error_message}{Colors.END}", end="", flush=True)
                                            time.sleep(SLEEP_ERROR_DISPLAY)
                                            # FULLY CLEAR BEFORE EXITING
                                            print("\r\033[2K", end="", flush=True)
                                            raise KeyboardInterrupt  # Return to the main menu

                                        # Perform new verification
                                        new_results = perform_domain_verification("domains.txt")

                                        # UPDATE THE MATRIX CHARACTER BY CHARACTER WITHOUT DESTROYING IT
                                        print(f"\r{' ' * countdown_margin}{Colors.GREEN}✅ Verification completed{Colors.END}", end="", flush=True)

                                        # Update the matrix visually without destroying it
                                        if update_matrix_character_by_character(results, new_results):
                                            # Update results internally
                                            results = new_results

                                        else:
                                            # If the visual update fails, keep the previous results
                                            print(f"\r{' ' * countdown_margin}{Colors.RED}⚠️ Error updating matrix, keeping previous data{Colors.END}", end="", flush=True)
                                            time.sleep(SLEEP_SHORT)

                                        # Wait 2 seconds so the message is visible
                                        time.sleep(SLEEP_VERIFICATION)

                                        # FULLY CLEAR THE LINE AFTER VERIFICATION
                                        print("\r\033[2K", end="", flush=True)

                                        # ADDITIONAL CLEANUP: make sure no leftovers remain
                                        print("\r", end="", flush=True)

                                        # Reset countdown to 8 hours
                                        remaining_seconds = total_seconds + 1
                                        break
                                    time.sleep(SLEEP_COUNTDOWN)
                            else:
                                # Countdown reached zero - RUN AUTOMATIC VERIFICATION
                                try:
                                    # Run automatic verification (same logic as CONTROL-R)
                                    results, success = execute_automatic_verification(results, original_domains, countdown_margin, terminal_width)

                                    if success:
                                        # Reset countdown to 8 hours
                                        remaining_seconds = total_seconds + 1
                                    else:
                                        # If automatic verification failed, keep countdown at 0
                                        remaining_seconds = 0

                                except KeyboardInterrupt:
                                    raise  # Re-raise for handling at the upper level

                            remaining_seconds -= 1

                        print()  # New line after the countdown
                    except KeyboardInterrupt:
                        print()  # New line after interrupting
                        terminal_width = get_terminal_width()

                        # Check whether it was due to a file change or CONTROL-C
                        try:
                            integrity_valid, integrity_message = check_domains_file_integrity("domains.txt", original_domains)
                            if not integrity_valid:
                                message = f"🛑 Monitoring interrupted: {integrity_message}"
                                message_color = Colors.RED
                            else:
                                message = "🛑 Countdown interrupted by the user"
                                message_color = Colors.YELLOW
                        except Exception:
                            message = "🛑 Countdown interrupted by the user"
                            message_color = Colors.YELLOW

                        message_margin = (terminal_width - len(message)) // 2
                        print_colored(f"\n{' ' * message_margin}{message}", message_color)
                    finally:
                        # Re-enable keyboard input
                        enable_input(old_settings)

                    input(f"\n{RGB_BLUE}[*] {Colors.WHITE}Press ENTER to return to the main menu...")
                else:
                    print_colored("❌ No valid results were obtained", Colors.RED)
            else:
                print_colored(f"❌ domains.txt file not found in: {script_dir}", Colors.RED)
                print_colored(f"💡 Create the domains.txt file in the same folder as the script", Colors.YELLOW)

        elif option.upper() == "Q":
            print(f"\n{RGB_BLUE}[*] {Colors.WHITE}Thank you for using Domains & SSL Verifier")
            print(f"{RGB_YELLOW}{'═' * 54}")
            sys.exit(0)
        else:
            print_colored(f"\n{RGB_RED}[!] Invalid option. Please select 1-5 or Q.", Colors.RED)



def clear_screen_and_home():
    try:
        # Clear scrollback (3J) and visible buffer (2J), move cursor home (H)
        sys.stdout.write("\033[3J\033[2J\033[H")
        sys.stdout.flush()
    except Exception:
        try:
            os.system('clear' if os.name == 'posix' else 'cls')
        except Exception:
            pass

def execute_automatic_verification(results, original_domains, countdown_margin, terminal_width):
    """
    Runs the automatic verification when the countdown reaches zero.
    Same logic as CONTROL-R but automatic.
    """
    try:
        # Clear the current countdown line to avoid \r leftovers
        print("\r\033[2K", end="", flush=True)
        print(f"\r{' ' * countdown_margin}{Colors.BLUE}🔄 Checking domains...{Colors.END}", end="", flush=True)

        # CHECK DOMAINS.TXT FILE INTEGRITY
        integrity_valid, integrity_message = check_domains_file_integrity("domains.txt", original_domains)

        if not integrity_valid:
            # domains.txt file changed during execution
            error_message = f"❌ ERROR: {integrity_message}"
            error_margin = (terminal_width - len(error_message)) // 2
            print(f"\r{' ' * error_margin}{Colors.RED}{error_message}{Colors.END}", end="", flush=True)
            time.sleep(SLEEP_ERROR_DISPLAY)
            # FULLY CLEAR BEFORE EXITING
            print("\r\033[2K", end="", flush=True)
            raise KeyboardInterrupt  # Return to the main menu

        # Perform new verification
        new_results = perform_domain_verification("domains.txt")

        # UPDATE THE MATRIX CHARACTER BY CHARACTER WITHOUT DESTROYING IT
        print(f"\r{' ' * countdown_margin}{Colors.GREEN}✅ Verification completed{Colors.END}", end="", flush=True)

        # Update the matrix visually without destroying it
        if update_matrix_character_by_character(results, new_results):
            # Update results internally
            results = new_results
        else:
            # If the visual update fails, keep the previous results
            time.sleep(SLEEP_SHORT)

        # Wait 2 seconds so the message is visible
        time.sleep(SLEEP_VERIFICATION)

        # FULLY CLEAR THE LINE AFTER VERIFICATION
        print("\r\033[2K", end="", flush=True)

        # ADDITIONAL CLEANUP: make sure no leftovers remain
        print("\r", end="", flush=True)

        return results, True  # Return new results and success

    except KeyboardInterrupt:
        raise  # Re-raise the exception for handling at the upper level
    except Exception as e:
        print(f"\r{' ' * countdown_margin}{Colors.RED}❌ Error in automatic verification: {e}{Colors.END}", end="", flush=True)
        time.sleep(SLEEP_VERIFICATION)
        return results, False  # Return previous results and failure

if __name__ == "__main__":
    # Check dependencies before starting
    if check_dependencies():
        menu()

