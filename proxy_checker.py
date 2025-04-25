import json
import logging
import os
import sys
import random
import requests
import time # Added import
from concurrent.futures import ThreadPoolExecutor, as_completed # Added import
import threading # Added import
import warnings # To suppress InsecureRequestWarning

# Suppress only the InsecureRequestWarning from urllib3 needed for verify=False
from requests.packages.urllib3.exceptions import InsecureRequestWarning
warnings.simplefilter('ignore', InsecureRequestWarning)


# --- Configuration Loading ---
# [ Function load_config remains the same ]
def load_config(config_path='config.json'):
    """Loads configuration from a JSON file."""
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
            logging.info(f"Configuration loaded successfully from {config_path}")
            required_keys = [
                "proxy_sources", "initial_check_url", "websites_to_test",
                "request_timeout_initial", "request_timeout_website",
                "parallel_workers", "initial_check_batch_size",
                "website_check_retries", "output_directory", "user_agent_list"
            ]
            for key in required_keys:
                if key not in config:
                    raise ValueError(f"Missing required key in config: '{key}'")
            if not config.get("user_agent_list"):
                 raise ValueError("Config 'user_agent_list' cannot be empty.")
            return config
    except FileNotFoundError:
        logging.error(f"ERROR: Configuration file not found at {config_path}")
        sys.exit(1)
    except json.JSONDecodeError:
        logging.error(f"ERROR: Configuration file {config_path} contains invalid JSON.")
        sys.exit(1)
    except ValueError as ve:
         logging.error(f"ERROR: Invalid configuration: {ve}")
         sys.exit(1)
    except Exception as e:
        logging.error(f"An unexpected error occurred while loading config: {e}")
        sys.exit(1)

# --- Logging Setup ---
# [ Function setup_logging remains the same ]
def setup_logging():
    """Configures basic logging for the application."""
    log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    logger = logging.getLogger()
    logger.setLevel(logging.INFO) # Set the default logging level
    # Clear previous handlers
    if logger.hasHandlers():
        logger.handlers.clear()

    # Console Handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(log_formatter)
    logger.addHandler(console_handler)

    logging.info("Logging configured")


# --- Output Directory ---
# [ Function ensure_output_directory remains the same ]
def ensure_output_directory(config):
    """Creates the output directory if it doesn't exist."""
    output_dir = config.get('output_directory', 'results') # Default to 'results'
    try:
        os.makedirs(output_dir, exist_ok=True)
        logging.info(f"Output directory '{output_dir}' ensured.")
    except OSError as e:
        logging.error(f"Error creating output directory '{output_dir}': {e}")
        sys.exit(1)

# --- Utility Functions ---
# [ Function get_random_user_agent remains the same ]
def get_random_user_agent(config):
    """Selects a random User-Agent string from the config list."""
    user_agents = config.get("user_agent_list", [])
    if not user_agents:
        return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36"
    return random.choice(user_agents)

# --- Data Acquisition ---
# [ Function fetch_proxy_lists remains the same ]
def fetch_proxy_lists(config):
    """Fetches raw proxy data from the configured list of URLs."""
    source_urls = config.get('proxy_sources', [])
    raw_proxy_data = {} # Dictionary to store {url: content_string}
    if not source_urls:
        logging.warning("No proxy sources defined in configuration.")
        return raw_proxy_data

    logging.info(f"Attempting to fetch proxy data from {len(source_urls)} sources...")
    fetch_timeout = config.get('request_timeout_initial', 10)
    successful_fetches = 0

    for url in source_urls:
        logging.info(f"Fetching: {url}")
        try:
            headers = {'User-Agent': get_random_user_agent(config)}
            response = requests.get(url, timeout=fetch_timeout, headers=headers)
            response.raise_for_status()
            raw_proxy_data[url] = response.text
            logging.info(f"Successfully fetched data from {url} ({len(response.text)} bytes)")
            successful_fetches += 1
        except requests.exceptions.Timeout:
            logging.error(f"Timeout error while fetching {url} after {fetch_timeout} seconds.")
            raw_proxy_data[url] = None
        except requests.exceptions.RequestException as e:
            logging.error(f"Error fetching {url}: {e}")
            raw_proxy_data[url] = None
        except Exception as e:
            logging.error(f"An unexpected error occurred fetching {url}: {e}")
            raw_proxy_data[url] = None

    logging.info(f"Finished fetching. Successfully retrieved data from {successful_fetches}/{len(source_urls)} sources.")
    return raw_proxy_data


# --- Parsing & Normalization ---
# [ Function parse_text_ip_port remains the same ]
def parse_text_ip_port(content, proxy_type):
    """Parses proxies from text content with 'ip:port' format per line."""
    proxies = []
    lines = content.strip().split('\n')
    for line in lines:
        line = line.strip()
        if not line or ':' not in line: # Skip empty lines or lines without a colon
            continue
        try:
            ip, port_str = line.split(':', 1)
            # Basic validation (can be improved with regex for IP)
            if ip and port_str.isdigit():
                port = int(port_str)
                if 1 <= port <= 65535:
                    proxies.append({'ip': ip, 'port': str(port), 'type': proxy_type.lower()})
                else:
                    logging.warning(f"Invalid port number '{port_str}' in line: {line}")
            else:
                logging.warning(f"Skipping malformed line: {line}")
        except ValueError:
            logging.warning(f"Skipping malformed line (ValueError): {line}")
        except Exception as e:
            logging.warning(f"Skipping line due to unexpected error: {line} - {e}")
    return proxies

# [ Function parse_json_proxifly - use the UPDATED version from previous step ]
def parse_json_proxifly(content):
    """Parses proxies from the proxifly JSON structure (based on user-provided example)."""
    proxies = []
    try:
        data = json.loads(content)
        if not isinstance(data, list):
            logging.error("Proxifly JSON content is not a list.")
            return proxies
        for item in data:
            if not isinstance(item, dict):
                logging.warning(f"Skipping non-dictionary item in proxifly JSON: {item}")
                continue
            ip = item.get('ip')
            port = item.get('port')
            protocol = item.get('protocol')
            if not ip or port is None or not protocol:
                logging.warning(f"Skipping item with missing 'ip', 'port', or 'protocol' in proxifly JSON: {item}")
                continue
            try:
                port_int = int(port)
                if not (1 <= port_int <= 65535):
                    logging.warning(f"Invalid port number '{port}' for IP '{ip}' in proxifly data. Skipping.")
                    continue
            except (ValueError, TypeError):
                 logging.warning(f"Invalid port format '{port}' for IP '{ip}' in proxifly data. Skipping.")
                 continue
            proxy_type = str(protocol).lower()
            if proxy_type not in ["http", "https", "socks4", "socks5"]:
                 logging.warning(f"Uncommon proxy type '{proxy_type}' found for {ip}:{port_int}. Still adding.")
            proxies.append({'ip': str(ip), 'port': str(port_int), 'type': proxy_type})
    except json.JSONDecodeError:
        logging.error("Failed to decode JSON content from proxifly source.")
    except Exception as e:
        logging.error(f"An unexpected error occurred during proxifly JSON parsing: {e}")
    return proxies

# [ Function parse_json_vakhov - use the UPDATED version from previous step ]
def parse_json_vakhov(content):
    """Parses proxies from the vakhov JSON structure."""
    proxies = []
    try:
        data = json.loads(content)
        if not isinstance(data, list):
            logging.error("Vakhov JSON content is not a list.")
            return proxies
        for item in data:
            if not isinstance(item, dict):
                logging.warning(f"Skipping non-dictionary item in vakhov JSON: {item}")
                continue
            ip = item.get('ip')
            port = item.get('port')
            if not ip or not port:
                logging.warning(f"Skipping item with missing 'ip' or 'port' in vakhov JSON: {item}")
                continue
            try:
                port_int = int(port)
                if not (1 <= port_int <= 65535):
                    logging.warning(f"Invalid port number '{port}' for IP '{ip}' in vakhov data. Skipping.")
                    continue
            except (ValueError, TypeError):
                 logging.warning(f"Invalid port format '{port}' for IP '{ip}' in vakhov data. Skipping.")
                 continue
            proxy_type = None
            if item.get('socks5') == "1":
                proxy_type = "socks5"
            elif item.get('socks4') == "1":
                proxy_type = "socks4"
            elif item.get('ssl') == "1":
                proxy_type = "https"
            elif item.get('http') == "1":
                proxy_type = "http"
            else:
                 logging.warning(f"Could not determine proxy type for {ip}:{port} from vakhov flags: {item}. Skipping.")
                 continue
            proxies.append({'ip': str(ip), 'port': str(port_int), 'type': proxy_type})
    except json.JSONDecodeError:
        logging.error("Failed to decode JSON content from vakhov source.")
    except Exception as e:
        logging.error(f"An unexpected error occurred during vakhov JSON parsing: {e}")
    return proxies

# [ Function parse_and_normalize remains the same ]
def parse_and_normalize(successful_sources):
    """Parses data from various sources, normalizes, and deduplicates."""
    all_proxies = []
    unique_proxies = set()
    logging.info("Starting parsing and normalization...")
    for url, content in successful_sources.items():
        logging.info(f"Parsing source: {url}")
        source_proxies = []
        if url.endswith(".json"):
            if "proxifly" in url:
                source_proxies = parse_json_proxifly(content)
            elif "vakhov" in url:
                source_proxies = parse_json_vakhov(content)
            else:
                logging.warning(f"Unknown JSON source structure for URL: {url}. Skipping.")
        elif url.endswith(".txt"):
            proxy_type = "unknown"
            if "https" in url.lower(): proxy_type = "https"
            elif "socks5" in url.lower(): proxy_type = "socks5"
            elif "http" in url.lower(): proxy_type = "http"
            else: logging.warning(f"Could not determine proxy type from TXT URL: {url}. Assigning 'unknown'.")
            source_proxies = parse_text_ip_port(content, proxy_type)
        else:
            logging.warning(f"Skipping source with unrecognized format (not .json or .txt): {url}")

        added_from_source = 0
        for proxy in source_proxies:
            proxy_tuple = (proxy['ip'], proxy['port'])
            if proxy_tuple not in unique_proxies:
                unique_proxies.add(proxy_tuple)
                all_proxies.append(proxy)
                added_from_source += 1
        logging.info(f"Parsed {len(source_proxies)} proxies from {url}. Added {added_from_source} new unique proxies.")

    total_parsed = len(all_proxies)
    logging.info(f"Parsing complete. Total unique proxies found: {total_parsed}")
    return all_proxies

# --- Core Checking Utilities --- ADDED THIS SECTION ---

def format_proxy_url(proxy_info):
    """Formats proxy details into a URL string for requests."""
    ip = proxy_info['ip']
    port = proxy_info['port']
    proxy_type = proxy_info['type'].lower()

    if proxy_type not in ['http', 'https', 'socks4', 'socks5']:
         if proxy_type == 'https': scheme = 'http'
         elif proxy_type == 'socks4': scheme = 'socks4'
         elif proxy_type == 'socks5': scheme = 'socks5'
         else:
             logging.debug(f"Unsupported or unknown proxy type '{proxy_type}' for {ip}:{port}. Defaulting scheme to http.")
             scheme = 'http'
    elif proxy_type == 'https': # Special handling for 'https' type
        scheme = 'http' # Connect TO the proxy via HTTP, it handles the HTTPS to target
    else:
         scheme = proxy_type # Use http, socks4, socks5 directly

    return f"{scheme}://{ip}:{port}"


def check_proxy_basic(proxy_info, config):
    """Performs a basic connectivity check on a single proxy."""
    check_url = config['initial_check_url']
    timeout = config['request_timeout_initial']
    proxy_url_formatted = format_proxy_url(proxy_info)

    proxies_dict = { 'http': proxy_url_formatted, 'https': proxy_url_formatted }
    headers = {'User-Agent': get_random_user_agent(config)}
    start_time = time.time()
    error_message = None
    status_code = None

    try:
        response = requests.get(check_url, proxies=proxies_dict, timeout=timeout, headers=headers, verify=False)
        status_code = response.status_code
        response.raise_for_status()
        latency = (time.time() - start_time) * 1000
        return { 'proxy': proxy_info, 'status': 'working', 'latency_ms': int(latency) }
    except requests.exceptions.Timeout: error_message = "Timeout"
    except requests.exceptions.ProxyError as e: error_message = f"ProxyError: {e}"
    except requests.exceptions.SSLError as e: error_message = f"SSLError: {e}"
    except requests.exceptions.ConnectionError as e: error_message = f"ConnectionError: {e}"
    except requests.exceptions.RequestException as e: error_message = f"RequestException: {e}"
    except Exception as e: error_message = f"GenericError: {e}"

    logging.debug(f"Proxy check failed for {proxy_info['ip']}:{proxy_info['port']} ({proxy_info['type']}) - {error_message} (Status code: {status_code})")
    return { 'proxy': proxy_info, 'status': 'failed', 'error': error_message }


# --- Initial Verification Orchestrator --- ADDED THIS SECTION ---

def check_proxy_advanced(working_proxy_details, website_config, config):
    """
    Checks a working proxy against a specific website with advanced checks.

    Args:
        working_proxy_details (dict): Dict for a working proxy {'proxy_string': 'ip:port', 'type': '...'}
        website_config (dict): Config for the target website {'name': ..., 'url': ..., 'success_keywords': [], 'failure_keywords': []}
        config (dict): The main loaded configuration.

    Returns:
        bool: True if the proxy works for the site according to rules, False otherwise.
    """
    proxy_string = working_proxy_details['proxy_string']
    proxy_type = working_proxy_details['type'].lower()
    target_url = website_config['url']
    success_keywords = website_config.get('success_keywords', [])
    failure_keywords = website_config.get('failure_keywords', [])
    retries = config['website_check_retries']
    timeout = config['request_timeout_website']

    # Reconstruct the proxy URL format needed by requests
    # Note: We need the scheme based on proxy type (http, socks4, socks5) for the connection *to the proxy*
    if proxy_type == 'socks4':
        scheme = 'socks4'
    elif proxy_type == 'socks5':
        scheme = 'socks5'
    else: # Default to http for 'http' and 'https' type proxies
        scheme = 'http'
    proxy_url_formatted = f"{scheme}://{proxy_string}" # proxy_string is already ip:port

    proxies_dict = {
        'http': proxy_url_formatted,
        'https': proxy_url_formatted
    }

    for attempt in range(retries):
        attempt_num = attempt + 1
        logging.debug(f"Attempt {attempt_num}/{retries} for {proxy_string} on {website_config['name']}")
        headers = {'User-Agent': get_random_user_agent(config)}
        try:
            response = requests.get(target_url, proxies=proxies_dict, timeout=timeout, headers=headers, verify=False) # verify=False inherited

            if response.status_code == 200:
                content = response.text.lower() # Case-insensitive check

                # 1. Check for failure keywords first
                found_failure_keyword = False
                for keyword in failure_keywords:
                    if keyword.lower() in content:
                        logging.debug(f"Failed {proxy_string} on {website_config['name']}: Found failure keyword '{keyword}'.")
                        found_failure_keyword = True
                        break # No need to check other failure keywords
                if found_failure_keyword:
                    continue # Move to the next retry attempt if failure keyword found

                # 2. Check for success keywords (if any are defined)
                if not success_keywords:
                    # If no success keywords are defined, 200 OK without failure keywords is sufficient
                    logging.debug(f"Success: {proxy_string} worked for {website_config['name']} (200 OK, no failure keywords).")
                    return True
                else:
                    found_success_keyword = False
                    for keyword in success_keywords:
                        if keyword.lower() in content:
                            logging.debug(f"Success: {proxy_string} worked for {website_config['name']} (Found success keyword '{keyword}').")
                            found_success_keyword = True
                            return True # Success!
                    # If loop finishes without finding a success keyword
                    logging.debug(f"Failed {proxy_string} on {website_config['name']}: No success keywords found in content.")
                    # Continue to next retry attempt

            else:
                logging.debug(f"Failed {proxy_string} on {website_config['name']}: Status code {response.status_code} (Attempt {attempt_num})")
                # Continue to next retry attempt

        except requests.exceptions.Timeout:
            logging.debug(f"Failed {proxy_string} on {website_config['name']}: Timeout (Attempt {attempt_num})")
        except requests.exceptions.ProxyError as e:
             logging.debug(f"Failed {proxy_string} on {website_config['name']}: ProxyError {e} (Attempt {attempt_num})")
        except requests.exceptions.SSLError as e:
             logging.debug(f"Failed {proxy_string} on {website_config['name']}: SSLError {e} (Attempt {attempt_num})")
        except requests.exceptions.ConnectionError as e:
             logging.debug(f"Failed {proxy_string} on {website_config['name']}: ConnectionError {e} (Attempt {attempt_num})")
        except requests.exceptions.RequestException as e:
            logging.debug(f"Failed {proxy_string} on {website_config['name']}: RequestException {e} (Attempt {attempt_num})")
        except Exception as e:
            logging.debug(f"Failed {proxy_string} on {website_config['name']}: Generic Error {e} (Attempt {attempt_num})")

        # Optional: Add a small delay between retries?
        # time.sleep(0.5)

    # If all retries fail
    logging.debug(f"Proxy {proxy_string} failed all {retries} attempts for {website_config['name']}.")
    return False


progress_lock = threading.Lock()
checked_count = 0

def run_initial_verification(proxy_list, config):
    """Checks all proxies in the list in parallel batches for basic connectivity."""
    global checked_count
    checked_count = 0
    total_proxies = len(proxy_list)
    workers = config['parallel_workers']
    batch_size = config['initial_check_batch_size']
    output_dir = config['output_directory']
    results_file_path = os.path.join(output_dir, 'working_proxies_master.jsonl')

    logging.info(f"Starting initial verification for {total_proxies} proxies...")
    logging.info(f"Using {workers} parallel workers.")
    logging.info(f"Batch size: {batch_size}")
    logging.info(f"Working proxies will be saved to: {results_file_path}")

    try:
        with open(results_file_path, 'w') as f: f.write("")
        logging.info(f"Cleared previous results file: {results_file_path}")
    except IOError as e:
        logging.error(f"Could not clear results file {results_file_path}: {e}")

    working_proxies_in_run = []
    total_batches = (total_proxies + batch_size - 1) // batch_size

    for i in range(0, total_proxies, batch_size):
        batch = proxy_list[i:min(i + batch_size, total_proxies)]
        batch_number = (i // batch_size) + 1
        logging.info(f"--- Starting Batch {batch_number}/{total_batches} ({len(batch)} proxies) ---")

        batch_working_count = 0
        futures = []
        with ThreadPoolExecutor(max_workers=workers) as executor:
            for proxy_info in batch:
                future = executor.submit(check_proxy_basic, proxy_info, config)
                futures.append(future)

            batch_checked_count = 0
            total_in_batch = len(batch)
            for future in as_completed(futures):
                result = future.result()
                batch_checked_count += 1
                with progress_lock:
                    checked_count += 1

                if batch_checked_count % 100 == 0 or batch_checked_count == total_in_batch:
                    logging.info(f"Batch {batch_number}/{total_batches} Progress: {batch_checked_count}/{total_in_batch} checked.")
                    logging.info(f"Overall Progress: {checked_count}/{total_proxies} proxies checked ({((checked_count/total_proxies)*100):.2f}%).") # Added percentage

                if result and result['status'] == 'working':
                    working_proxy_details = {
                        'proxy_string': f"{result['proxy']['ip']}:{result['proxy']['port']}",
                        'type': result['proxy']['type'],
                        'latency_ms': result['latency_ms']
                        # Removed 'source' field for now, can be added back if needed
                    }
                    try:
                        with open(results_file_path, 'a') as f:
                            json.dump(working_proxy_details, f)
                            f.write('\n')
                        batch_working_count += 1
                        working_proxies_in_run.append(working_proxy_details)
                    except IOError as e:
                        logging.error(f"Could not write working proxy {working_proxy_details['proxy_string']} to file {results_file_path}: {e}")

        logging.info(f"--- Finished Batch {batch_number}/{total_batches}. Found {batch_working_count} working proxies in this batch. ---")

    logging.info(f"Initial verification complete. Total working proxies found in this run: {len(working_proxies_in_run)}")
    logging.info(f"All working proxies saved to {results_file_path}")

    return working_proxies_in_run


# --- Specific Website Verification Orchestrator ---

def run_specific_website_verification(config):
    """
    Tests initially validated proxies against specific websites from the config.

    Args:
        config (dict): The loaded configuration.
    """
    output_dir = config['output_directory']
    master_results_path = os.path.join(output_dir, 'working_proxies_master.jsonl')
    websites_to_test = config['websites_to_test']
    workers = config['parallel_workers']

    # 1. Read the working proxies from the master file
    working_proxies_list = []
    try:
        with open(master_results_path, 'r') as f:
            for line in f:
                try:
                    proxy_data = json.loads(line.strip())
                    # Ensure it has the required keys from the initial check
                    if 'proxy_string' in proxy_data and 'type' in proxy_data:
                         working_proxies_list.append(proxy_data)
                    else:
                         logging.warning(f"Skipping malformed line in {master_results_path}: {line.strip()}")
                except json.JSONDecodeError:
                    logging.warning(f"Could not decode JSON line in {master_results_path}: {line.strip()}")
    except FileNotFoundError:
        logging.error(f"Master working proxies file not found: {master_results_path}. Cannot run specific website checks.")
        return # Stop if the input file doesn't exist
    except Exception as e:
        logging.error(f"Error reading master proxies file {master_results_path}: {e}")
        return # Stop on other read errors

    if not working_proxies_list:
        logging.warning("No working proxies found in the master list. Skipping specific website checks.")
        return

    logging.info(f"Starting specific website verification for {len(working_proxies_list)} initially working proxies against {len(websites_to_test)} websites...")

    # 2. Iterate through each website to test
    for site_config in websites_to_test:
        site_name = site_config.get('name', 'UnknownWebsite')
        site_url = site_config.get('url')
        if not site_url:
            logging.warning(f"Skipping website '{site_name}' because it has no URL defined in config.")
            continue

        logging.info(f"--- Testing proxies against: {site_name} ({site_url}) ---")
        site_results_file = os.path.join(output_dir, f"results_{site_name.replace(' ', '_')}.json")
        proxies_working_for_site = []
        futures = []
        checked_site_proxies = 0
        total_site_proxies = len(working_proxies_list)

        # Use ThreadPoolExecutor for parallel checks
        with ThreadPoolExecutor(max_workers=workers) as executor:
            for proxy_details in working_proxies_list:
                future = executor.submit(check_proxy_advanced, proxy_details, site_config, config)
                # Store the original proxy details with the future for later retrieval
                futures.append((future, proxy_details))

            # Process results as they complete
            for future, proxy_details in futures:
                checked_site_proxies += 1
                try:
                    is_working = future.result()
                    if is_working:
                        proxies_working_for_site.append(proxy_details['proxy_string']) # Save just the 'ip:port' string

                    # Log progress for this specific site
                    if checked_site_proxies % 100 == 0 or checked_site_proxies == total_site_proxies:
                         logging.info(f"Progress for {site_name}: {checked_site_proxies}/{total_site_proxies} proxies checked.")

                except Exception as e:
                    # Handle potential errors from the future itself (though check_proxy_advanced should catch most)
                    logging.error(f"Error processing result for proxy {proxy_details['proxy_string']} on {site_name}: {e}")


        # 3. Save results for this website
        logging.info(f"--- Finished testing for {site_name}. Found {len(proxies_working_for_site)} working proxies. ---")
        try:
            with open(site_results_file, 'w') as f:
                json.dump(proxies_working_for_site, f, indent=4) # Save as a pretty JSON list
            logging.info(f"Results for {site_name} saved to {site_results_file}")
        except IOError as e:
            logging.error(f"Could not write results file {site_results_file}: {e}")

    logging.info("Specific website verification complete.")
    

# --- Main Execution ---

if __name__ == "__main__":
    setup_logging()
    config = load_config()

    if config:
        ensure_output_directory(config)
        logging.info("Proxy Checker Program - Starting...")

        print("-" * 30)
        print("Configuration Details:")
        print(f"  Sources: {len(config['proxy_sources'])}")
        print(f"  Websites to test: {len(config['websites_to_test'])}")
        # ... [other print statements] ...
        print(f"  Output directory: {config['output_directory']}")
        print(f"  Workers: {config['parallel_workers']}")
        print(f"  Initial Check Batch Size: {config['initial_check_batch_size']}")
        print("-" * 30)

        # --- Step 1: Fetch Raw Proxy Data ---
        raw_data = fetch_proxy_lists(config)
        successful_sources = {url: data for url, data in raw_data.items() if data}
        if not successful_sources:
            logging.error("Failed to fetch data from any source. Exiting.")
            sys.exit(1)
        logging.info(f"Successfully fetched data from {len(successful_sources)} sources.")

        # --- Step 2: Parse, Normalize, and Deduplicate ---
        all_unique_proxies = parse_and_normalize(successful_sources)
        if not all_unique_proxies:
            logging.error("No proxies could be parsed from the fetched data. Exiting.")
            sys.exit(1)
        logging.info(f"Total unique proxies ready for checking: {len(all_unique_proxies)}")

        # --- Step 3: Initial Proxy Verification --- # MODIFIED THIS SECTION
        working_proxies = run_initial_verification(all_unique_proxies, config)

        if not working_proxies:
            logging.warning("No working proxies found after initial check.")
            # Continue anyway, the next step will just find nothing to test.

        # --- Step 4: Specific Website Verification ---
        # Run this regardless of whether working_proxies list from the *current run* is empty,
        # as the function reads from the master file which might contain results from previous runs.
        run_specific_website_verification(config)

        logging.info("Proxy Checker Program - All checks complete.")