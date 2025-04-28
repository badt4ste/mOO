# mostlyObviousOSINT (MOO) - Automated OSINT and Reconnaissance Scanner

MOO is a Bash script designed to automate basic Open Source Intelligence (OSINT) gathering and network reconnaissance tasks against a list of targets (domain names or IP addresses). It orchestrates several common tools like `nslookup`, `nmap`, and `testssl.sh` to provide a consolidated report.

## Features

* **Input File:** Takes a simple text file list of targets.
* **Deduplication:** Automatically removes duplicate targets from the input list.
* **DNS Resolution:** Performs `nslookup` to find IP addresses associated with domain names.
* **TCP Port Scanning:**
    * Discovers all open TCP ports (`nmap -p-`).
    * Performs service version detection (`-sV`) and script scanning (`-sC`) on discovered open ports.
* **UDP Port Scanning (Optional):**
    * Discovers open UDP ports from the top 1000 (`nmap -sU --top-ports 1000`).
    * Performs service version detection (`-sV`) and script scanning (`-sC`) on discovered open UDP ports.
    * Can be skipped using `--skip-udp`.
* **SSL/TLS Analysis (Optional):**
    * Identifies potential SSL/TLS ports based on common defaults and service detection.
    * Runs `testssl.sh` against identified ports to find vulnerabilities and configuration details.
    * Extracts significant findings (Critical, High, Medium, Low, etc.).
    * Can be skipped using `--skip-testssl`.
* **Parallel Scanning:** Runs scans concurrently on multiple targets to speed up the process (configurable via `MAX_JOBS` variable, default is 4).
* **Resume Capability:** If the script is interrupted (e.g., with Ctrl+C), it records completed targets. Re-running the script with the same input file and client name will skip the already finished targets.
* **Output Organization:**
    * Creates a timestamped and client-tagged main output directory (`scan_results_YYYYMMDD_clientname`).
    * Generates a consolidated text summary (`final_summary.txt`).
    * Generates a consolidated HTML report (`report.html`).
    * Keeps a detailed log file (`osint_scan.log`).
    * Stores raw output from tools in target-specific subdirectories.
* **Concurrency Control:** Uses `flock` to safely write to shared summary and report files from parallel processes.
* **Progress Bar:** Displays real-time progress, including percentage complete, targets processed, running jobs count, and estimated time remaining (ETA).

## Prerequisites

Before running MOO, ensure the following tools are installed and available in your system's PATH:

* **`bash`**: The script interpreter.
* **`nslookup`**: For DNS queries (often part of `dnsutils` or `bind-utils` package).
* **`nmap`**: The network scanner. **Crucially, the script uses `sudo nmap` for some operations (like UDP scans). You need `sudo` privileges, potentially configured for passwordless execution of `nmap`, or you must run the entire MOO script using `sudo`.**
* **`jq`**: A command-line JSON processor (used for parsing `testssl.sh` output).
* **`testssl.sh`**: The SSL/TLS scanner (required unless using `--skip-testssl`). Download it from [https://testssl.sh/](https://testssl.sh/).
* **`flock` (`brew install flock`) MacOS doesn't come preloaded with the linux `flock` utility.ß

## Installation

1.  Save the script code to a file, for example, `moo.sh`.
2.  Make the script executable: `chmod +x moo.sh`
3.  Ensure all prerequisite tools listed above are installed.

## Usage

```bash
./moo.sh <input_file.txt> [--client=name] [--skip-udp] [--skip-testssl] [--silent]
```

### Command-Line Options

* `<input_file.txt>`: **Required**. Path to the text file containing the list of targets (one per line).
* `--client=<name>`: Optional. A name or identifier for this scan batch. This name will be part of the output directory name (e.g., `scan_results_20250426_projectX`). Defaults to `default`.
* `--skip-udp`: Optional. If specified, the UDP port scan phase will be skipped.
* `--skip-testssl`: Optional. If specified, the `testssl.sh` analysis phase will be skipped. This also removes `testssl.sh` from the list of required tools.
* `--silent`: Optional. This flag is parsed but does not appear to have a significant effect on the script's output behavior based on the provided code.

### Input File Format

The input file should be a plain text file with one target (domain name or IP address) per line.

Example (`targets.txt`):

```
example.com
192.168.1.1
scanme.nmap.org
# this is a comment and will be ignored

another-target.net
```

Empty lines and lines starting with a `#` symbol are ignored.

## Output Files and Structure

The script creates a main output directory named `scan_results_YYYYMMDD_clientname/`. Inside this directory, you will find:

* `final_summary.txt`: A text file summarizing the key findings (IPs, open TCP/UDP ports, TestSSL results) for all scanned targets.
* `report.html`: An HTML version of the summary report for easy viewing in a browser.
* `osint_scan.log`: A log file containing timestamped messages about the script's execution progress and actions.
* `<input_file>_deduped.txt`: A copy of the input file after removing duplicates and comments/empty lines. This is the actual list of targets processed.
* `targets_done_list.txt`: A list of targets that have been successfully scanned. This file is used for resuming interrupted scans. (Removed on successful completion).
* **Target-Specific Subdirectories:** For each target (e.g., `example_com/`), a subdirectory is created containing the raw output files from the tools:
    * `nslookup_*.txt`: Output from `nslookup`.
    * `nmap_tcp_ports_*.gnmap`: Grepable output from the initial TCP port discovery scan.
    * `nmap_detailed_tcp_*.txt`: Normal output from the detailed TCP service scan.
    * `nmap_udp_ports_*.gnmap`: Grepable output from the UDP port discovery scan (or indicates skipped).
    * `nmap_detailed_udp_*.txt`: Normal output from the detailed UDP service scan (or indicates skipped).
    * `testssl_<port>_*.json`: JSON output from `testssl.sh` for each identified SSL/TLS port (if run).

## Important Notes

* **Root Privileges:** As mentioned, `sudo nmap` is used. Ensure you have the necessary permissions. Running the entire script with `sudo ./moo.sh ...` is a common way to handle this if passwordless `sudo` for `nmap` isn't configured.
* **Parallelism:** The script runs up to `MAX_JOBS` (default: 4) scans concurrently. You can modify the `MAX_JOBS` variable near the top of the script if you want to use more or fewer parallel processes, considering your system's resources and network limitations.
* **Resource Usage:** This script can be network and CPU intensive, especially the `nmap -p-` scan and running multiple `testssl.sh` instances. Be mindful of the impact on the network you are scanning from and the targets themselves.
* **Error Handling:** The script includes basic checks for tools and input files, as well as interrupt handling (Ctrl+C) for cleanup and enabling resumption. However, individual tool errors (e.g., `nmap` failing on a specific target) are logged but might not halt the entire script. Check the `osint_scan.log` and individual target directories for details.

## Disclaimer

⚠️ **Use responsibly!** This tool is intended for legitimate security auditing and reconnaissance purposes *only*. Ensure you have explicit, written permission from the target system owners before initiating any scans. Unauthorized scanning is illegal and unethical. The creators of this script are not responsible for any misuse or damage caused by this tool.
