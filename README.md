# Advanced Proxy Checker

A Python script to fetch proxy lists from various sources, perform initial validation, and conduct advanced checks to verify if proxies work reliably for specific target websites using configurable rules and keyword matching.

## Problem Solved

Public proxy lists are abundant, but finding proxies that *actually work* for a specific purpose or website can be tedious. Many proxies are slow, dead, or blocked by target sites (e.g., showing CAPTCHAs or access denied pages). This script automates the process of:

1.  Fetching proxies from multiple sources.
2.  Performing a quick initial connectivity check.
3.  Testing the working proxies against specific websites you care about.
4.  Verifying success based on expected content or lack of failure indicators.

## Features

*   **Multi-Source Fetching:** Load proxy lists from multiple URLs specified in `config.json`.
*   **Format Support:** Parses common formats:
    *   Plain text lists (`ip:port` per line).
    *   Specific JSON structures (currently supports examples similar to proxifly and vakhov structures - easily extendable).
*   **Initial Validation:** Performs a basic connectivity check against a configurable URL (`initial_check_url`) and measures latency.
*   **Advanced Website-Specific Checks:** Tests initially validated proxies against a list of target websites (`websites_to_test`).
*   **Keyword Matching:** Determines proxy success/failure on target websites by checking for presence (`success_keywords`) or absence (`failure_keywords`) of specific text in the response content (e.g., avoiding "CAPTCHA", "Access Denied", ensuring "Google Search" appears).
*   **Configurability:** Easily configure sources, target sites, keywords, timeouts, retries, and concurrency via `config.json`.
*   **Parallel Processing:** Uses multithreading (`ThreadPoolExecutor`) for faster checking of large proxy lists.
*   **User-Agent Rotation:** Rotates User-Agent strings for requests to mimic different browsers.
*   **Organized Output:** Saves results to structured files:
    *   `working_proxies_master.jsonl`: List of proxies passing the initial check.
    *   `results/<SiteName>.json`: List of proxies confirmed working for each specific target site.
*   **Logging:** Provides informative console output about the process.
*   **Resilience:** Implements timeouts and retries for network requests.

## Installation & Setup

**Prerequisites:**

*   Python 3.7+
*   Git

**Steps:**

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/<your-username>/<your-repository-name>.git
    cd <your-repository-name>
    ```
    *(Replace `<your-username>` and `<your-repository-name>` with your actual details)*

2.  **Create and activate a virtual environment (Recommended):**
    ```bash
    # For Linux/macOS
    python3 -m venv venv
    source venv/bin/activate

    # For Windows
    python -m venv venv
    .\venv\Scripts\activate
    ```

3.  **Install dependencies:**
    The script uses the `requests` library. You also need `requests[socks]` if you intend to check SOCKS proxies.
    ```bash
    pip install requests requests[socks]
    ```

## Configuration (`config.json`)

The script's behavior is controlled by the `config.json` file. Modify it according to your needs:

```json
{
    "proxy_sources": [
      "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt", // Example HTTP list
      "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt" // Example SOCKS5 list
      // Add more URLs pointing to .txt (ip:port) or supported .json proxy lists
    ],
    "initial_check_url": "https://httpbin.org/ip", // URL used for basic connectivity check
    "websites_to_test": [
      {
        "name": "Google",                      // Descriptive name for the output file (results_Google.json)
        "url": "https://www.google.com",       // Target website URL
        "success_keywords": ["Google Search", "I'm Feeling Lucky"], // List of keywords that MUST be present for success (case-insensitive). Empty list means any 200 OK without failure keywords is success.
        "failure_keywords": ["About this page", "unusual traffic", "CAPTCHA"] // List of keywords indicating failure (case-insensitive). If found, the proxy fails for this site.
      },
      {
        "name": "ExampleSite",
        "url": "https://example.com",
        "success_keywords": ["Example Domain"], // Check for specific text
        "failure_keywords": ["Access Denied", "Blocked"]
      }
      // Add more website configurations here
    ],
    "request_timeout_initial": 10,        // Timeout in seconds for the initial proxy check
    "request_timeout_website": 15,        // Timeout in seconds for checking against specific websites
    "parallel_workers": 100,              // Number of threads for concurrent checks
    "initial_check_batch_size": 5000,     // Process initial checks in batches of this size (adjust based on memory)
    "website_check_retries": 2,           // Number of attempts for each proxy on a specific website (total attempts = 1 + retries)
    "output_directory": "results",        // Folder where output files will be saved
    "user_agent_list": [                  // List of User-Agent strings to rotate randomly
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
          "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
          // Add more user agents if desired
          "Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/109.0"
      ]
}
