#!/bin/bash

# === Configuration ===
MAX_JOBS=4
INPUT_FILE=""
SKIP_UDP=false
SKIP_TESTSSL=false
CLIENT="default"

# === Color codes ===
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# === Parse arguments ===
while [[ "$1" != "" ]]; do
    case "$1" in
        --skip-udp) SKIP_UDP=true ;;
        --skip-testssl) SKIP_TESTSSL=true ;;
        --client=*) CLIENT="${1#*=}" ;;
        --silent) SILENT=true ;;
        *.txt) INPUT_FILE="$1" ;;
        *) echo -e "${RED}Unknown argument: $1${NC}" && exit 1 ;;
    esac
    shift
done

# === Sanity check & dedupe input ===
if [[ -n "$INPUT_FILE" && -f "$INPUT_FILE" ]]; then
    INPUT_FILE_SORTED="${INPUT_FILE%.txt}_deduped.txt"
    grep -vE '^\s*$|^\s*#' "$INPUT_FILE" | sort -u > "$INPUT_FILE_SORTED"
    INPUT_FILE="$INPUT_FILE_SORTED"
fi

# === Validate input ===
if [[ -z "$INPUT_FILE" || ! -f "$INPUT_FILE" ]]; then
    echo -e "${RED}Input file is missing or not found.${NC}"
    echo "Usage: ./moo_v6.3.sh targets.txt [--client=name] [--skip-udp] [--skip-testssl]"
    exit 1
fi

# === Setup paths ===
DATESTAMP=$(date +"%Y%m%d")
OUTPUT_DIR="scan_results_${DATESTAMP}_${CLIENT}"
SUMMARY_FILE="$OUTPUT_DIR/final_summary.txt"
HTML_REPORT="$OUTPUT_DIR/report.html"
LOG_FILE="$OUTPUT_DIR/osint_scan.log"
TARGETS_DONE_FILE="$OUTPUT_DIR/targets_done.tmp"
TARGETS_DONE_LIST="$OUTPUT_DIR/targets_done_list.txt"
TARGETS_DONE_LOCK_FILE="$OUTPUT_DIR/targets_done_list.txt.lock"
SUMMARY_LOCK_FILE="$OUTPUT_DIR/final_summary.txt.lock"
HTML_LOCK_FILE="$OUTPUT_DIR/report.html.lock"

mkdir -p "$OUTPUT_DIR"
echo "" > "$SUMMARY_FILE"
echo "<html><head><title>Scan Report</title></head><body><h1>OSINT Scan Report - $(echo "$CLIENT" | tr '[:lower:]' '[:upper:]')</h1>" > "$HTML_REPORT"
echo "=== Log started at $(date) ===" > "$LOG_FILE"
touch "$TARGETS_DONE_LIST"
# ---> Touch all lock files <---
touch "$TARGETS_DONE_LOCK_FILE"
touch "$SUMMARY_LOCK_FILE"
touch "$HTML_LOCK_FILE"

# === Recalculate DONE if resuming ===
if [[ -s "$TARGETS_DONE_LIST" ]]; then
    echo $(grep -Fx -f "$TARGETS_DONE_LIST" "$INPUT_FILE" | sort -u | wc -l) > "$TARGETS_DONE_FILE"
else
    echo 0 > "$TARGETS_DONE_FILE"
fi

# === Calculate total ===
TARGETS_TOTAL=$(wc -l < "$INPUT_FILE")

# === Auto-exit if already done ===
if [[ $(cat "$TARGETS_DONE_FILE") -eq "$TARGETS_TOTAL" ]]; then
    echo -e "${GREEN}All targets already scanned. Nothing to do.${NC}"
    echo "</body></html>" >> "$HTML_REPORT"
    exit 0
fi

DEFAULT_SSL_PORTS=("443" "8443" "9443" "10443" "4443" "2083" "444" "944" "12443")

# === Required tools ===
REQUIRED_TOOLS=("nslookup" "nmap" "jq")
$SKIP_TESTSSL || REQUIRED_TOOLS+=("testssl.sh")

for tool in "${REQUIRED_TOOLS[@]}"; do
    if ! command -v $tool &>/dev/null; then
        echo -e "${RED}Required tool '$tool' not found. Please install it first.${NC}"
        exit 1
    fi
done

# === Logger ===
log() {
    # === Clear the line on stderr (where the progress bar is) first ===
    # \r: Move cursor to beginning of the line
    # \033[K: Clear from cursor to end of line
    # >&2: Send these control codes to standard error
    printf "\r\033[K" >&2

    # === Original log action: Print timestamped message to stdout and log file ===
    echo -e "[$(date +%H:%M:%S)] $*" | tee -a "$LOG_FILE"
}

# === Safe file reader for TCP/UDP port data (for HTML report) ===
# Adjusted to use awk for better parsing of Nmap -oN output, similar to text summary
print_port_section() {
    local file="$1"
    local port_type="$2" # Expect 'tcp' or 'udp'
    if [[ -s "$file" ]]; then
        # Use awk to print lines containing '/<port_type> open'
        awk -v type="$port_type" '$0 ~ ("/" type "\\s+open") { print }' "$file" || echo "None"
    else
        echo "None"
    fi
}

# === Progress bar ===
show_progress() {
    local spin='-\|/'
    local i=0
    local start_time=$(date +%s)

    while true; do
        # Check if the temporary file exists before trying to read it
        if [[ -f "$TARGETS_DONE_FILE" ]]; then
            DONE=$(cat "$TARGETS_DONE_FILE")
        else
             # If file doesn't exist (e.g., during final cleanup), assume 0 or last known value if needed
             # For display purposes, just break or show final state might be better. Let's assume 0 if missing.
             DONE=0
             # Or maybe it's better to break if the file is gone, indicating completion/cleanup
             # Let's stick with reading it, the main script should kill this process.
             [[ ! -f "$TARGETS_DONE_FILE" ]] && DONE=$(wc -l < "$TARGETS_DONE_LIST") # Fallback if temp file removed early
        fi

        # Prevent division by zero if TARGETS_TOTAL is somehow 0
        if [[ "$TARGETS_TOTAL" -eq 0 ]]; then
            PERCENT=100
            ETA="N/A"
        else
            PERCENT=$(( 100 * DONE / TARGETS_TOTAL ))
            BAR_WIDTH=40
            FILLED=$(( BAR_WIDTH * DONE / TARGETS_TOTAL ))
            EMPTY=$(( BAR_WIDTH - FILLED ))

            BAR=$(printf "%0.s#" $(seq 1 $FILLED))
            EMPTY_BAR=$(printf "%0.s-" $(seq 1 $EMPTY))

            elapsed=$(( $(date +%s) - start_time ))
            if [ "$DONE" -gt 0 ]; then
                est_total=$(( elapsed * TARGETS_TOTAL / DONE ))
                est_remaining=$(( est_total - elapsed ))
                ETA=$(printf "%02dm%02ds" $((est_remaining / 60)) $((est_remaining % 60)))
            else
                ETA="calculating..."
            fi
        fi

        RUNNING=$(jobs -r | wc -l)
        # Adjust running count: Exclude self (progress bar) if it's the only job left
        [[ $RUNNING -gt 0 ]] && RUNNING=$((RUNNING -1))
        if [[ "$RUNNING" -eq 0 && $(jobs -p | wc -l) -gt 1 ]]; then # Check against total jobs (incl self)
            RUNNING="flushing"
        elif [[ $RUNNING -lt 0 ]]; then # Handle case where only progress bar remains
            RUNNING=0
        fi

        i=$(( (i+1) %4 ))
        printf "\r${YELLOW}[%s] [%s%s] %d%% (%d/%d targets) Running: %s | ETA: %s ${NC}\033[K" \
            "${spin:$i:1}" "$BAR" "$EMPTY_BAR" "$PERCENT" "$DONE" "$TARGETS_TOTAL" "$RUNNING" "$ETA" >&2

        sleep 1
    done
}

# === Cleanup handler ===
cleanup() {
    echo -e "\n${RED}Interrupted. Cleaning up...${NC}"
    kill $PROGRESS_PID &>/dev/null
    jobs -p | xargs -r kill 2>/dev/null
    if [[ -f "$HTML_REPORT" ]]; then
        if ! grep -q "</body></html>" "$HTML_REPORT"; then
            echo "</body></html>" >> "$HTML_REPORT"
        fi
    fi
    # ---> Remove all temporary and lock files <---
    rm -f "$TARGETS_DONE_FILE" \
          "$TARGETS_DONE_LOCK_FILE" \
          "$SUMMARY_LOCK_FILE" \
          "$HTML_LOCK_FILE"
    echo -e "${YELLOW}Scan interrupted. Already scanned targets will be resumed next run.${NC}"
    exit 1
}

trap cleanup INT

# === Main scanning function ===
scan_target() {
    local target="$1"
    local TGT_CLEAN="${target//[^a-zA-Z0-9]/_}"
    local TGT_DIR="$OUTPUT_DIR/$TGT_CLEAN"
    mkdir -p "$TGT_DIR"
    local TS=$(date +"%Y%m%d_%H%M%S")
    log "${BLUE}Scanning $target...${NC}"

    # nslookup
    nslookup "$target" > "$TGT_DIR/nslookup_$TS.txt"
    IPS=$(grep -Eo 'Address: [0-9.]+' "$TGT_DIR/nslookup_$TS.txt" | awk '{print $2}' | sort -u)
    [[ -z "$IPS" ]] && IPS="(No IPs resolved)" # Handle case where nslookup fails

    # TCP Discovery
    log "${YELLOW}Discovering open TCP ports (-p-)${NC}"
    # Ensure files are writable by the script user if nmap runs as root
    touch "$TGT_DIR/nmap_tcp_ports_$TS.gnmap"
    sudo nmap -p- -T4 --max-retries 1 --host-timeout 5m -Pn "$target" -oG "$TGT_DIR/nmap_tcp_ports_$TS.gnmap" > /dev/null 2>&1
    OPEN_PORTS=$(awk -F'[ /]' '/Ports:/ {
        for (i=1; i<=NF; i++) {
            if ($i == "open" && $(i+1) == "tcp") {
                print $(i-1)
            }
        }
    }' "$TGT_DIR/nmap_tcp_ports_$TS.gnmap" | sort -n | uniq | paste -sd, -)

    log "${BLUE}Extracted TCP Ports: ${OPEN_PORTS:-None}${NC}" # Display None if empty

    # Detailed TCP Scan
    # Ensure files are writable by the script user if nmap runs as root
    touch "$TGT_DIR/nmap_detailed_tcp_$TS.txt"
    if [[ -n "$OPEN_PORTS" ]]; then
        log "${YELLOW}Enumerating services on TCP ports: $OPEN_PORTS${NC}"
        sudo nmap -sC -sV -T4 --max-retries 2 --host-timeout 5m -p "$OPEN_PORTS" -Pn "$target" -oN "$TGT_DIR/nmap_detailed_tcp_$TS.txt" > /dev/null 2>&1
    else
        log "${RED}Warning: No open TCP ports found for detailed scan on $target${NC}"
        echo "(No open TCP ports found)" > "$TGT_DIR/nmap_detailed_tcp_$TS.txt"
    fi

    # UDP Discovery
    if ! $SKIP_UDP; then
        log "${YELLOW}Discovering open UDP ports (top 1000)${NC}"
         # Ensure files are writable by the script user if nmap runs as root
        touch "$TGT_DIR/nmap_udp_ports_$TS.gnmap" "$TGT_DIR/nmap_detailed_udp_$TS.txt"
        sudo nmap -sU --top-ports 1000 -T4 --max-retries 1 --host-timeout 3m -Pn "$target" -oG "$TGT_DIR/nmap_udp_ports_$TS.gnmap" > /dev/null 2>&1

        # Improved UDP port extraction from gnmap
        OPEN_UDP_PORTS=$(awk -F'[/ ]' '/Status: Up/{ for(i=1;i<=NF;i++){ if($i=="Ports:"){ for(j=i+1;j<=NF;j++){ if( $(j+1) == "open" && $(j+2) == "udp" ){ print $j } } break}}}' "$TGT_DIR/nmap_udp_ports_$TS.gnmap" | sort -n | paste -sd, -)
        log "${BLUE}Extracted UDP Ports: ${OPEN_UDP_PORTS:-None}${NC}" # Display None if empty

        if [ -n "$OPEN_UDP_PORTS" ]; then
            log "${YELLOW}Enumerating services on UDP ports: $OPEN_UDP_PORTS${NC}"
            sudo nmap -sU -sC -sV -T4 --max-retries 1 --host-timeout 5m -p "$OPEN_UDP_PORTS" -Pn "$target" -oN "$TGT_DIR/nmap_detailed_udp_$TS.txt" > /dev/null 2>&1
        else
            echo "(No open UDP ports found)" > "$TGT_DIR/nmap_detailed_udp_$TS.txt"
             # Also clear the discovery file if no ports found, to avoid confusion
            echo "(No open UDP ports found in discovery)" > "$TGT_DIR/nmap_udp_ports_$TS.gnmap"
        fi
    else
        echo "(UDP Scan Skipped)" > "$TGT_DIR/nmap_detailed_udp_$TS.txt"
         echo "(UDP Scan Skipped)" > "$TGT_DIR/nmap_udp_ports_$TS.gnmap" # Ensure gnmap file reflects skipped state too
    fi

    # TestSSL
    SSL_FINDINGS="(Skipped)" # Default value
    if ! $SKIP_TESTSSL; then
        log "${YELLOW}Analyzing TCP services for SSL ports on $target...${NC}"
        SSL_PORTS=()

        # Check default SSL ports first if detailed TCP scan file exists and has content
         if [[ -s "$TGT_DIR/nmap_detailed_tcp_$TS.txt" ]]; then
            for port in "${DEFAULT_SSL_PORTS[@]}"; do
                 # Check if the port line exists and indicates an open state
                if grep -q -E "^${port}/tcp\s+open" "$TGT_DIR/nmap_detailed_tcp_$TS.txt"; then
                    SSL_PORTS+=("$port")
                fi
            done

            # Check other open TCP ports for 'ssl' or 'https' in service name
             while IFS= read -r line; do
                port=$(echo "$line" | cut -d '/' -f 1)
                # Ensure port is numeric before adding
                if [[ "$port" =~ ^[0-9]+$ ]]; then
                     # Check if service name contains ssl or https variations
                     if echo "$line" | awk '{print $3}' | grep -qiE 'ssl|https|tls'; then
                        SSL_PORTS+=("$port")
                    fi
                fi
             done < <(awk '/\/tcp\s+open/ { print }' "$TGT_DIR/nmap_detailed_tcp_$TS.txt")
         else
              log "${YELLOW}Skipping SSL check for $target as no detailed TCP scan results found.${NC}"
         fi

        # Deduplicate ports found
        UNIQUE_SSL_PORTS=($(echo "${SSL_PORTS[@]}" | tr ' ' '\n' | sort -u))

        if [ "${#UNIQUE_SSL_PORTS[@]}" -eq 0 ]; then
            log "${RED}No potential SSL/TLS enabled TCP ports found on $target${NC}"
            SSL_FINDINGS="(No SSL/TLS ports found)"
        else
            log "${BLUE}Found potential SSL/TLS ports: ${UNIQUE_SSL_PORTS[*]}${NC}"
            SSL_FINDINGS="" # Reset findings for this target
            for ssl_port in "${UNIQUE_SSL_PORTS[@]}"; do
                log "${YELLOW}Running testssl on $target:$ssl_port${NC}"
                # Ensure JSON file is writable
                touch "$TGT_DIR/testssl_${ssl_port}_$TS.json"
                 # Run testssl with host and port, handle connection errors
                testssl.sh --quiet --connect-timeout 5 --openssl-timeout 5 --jsonfile-pretty "$TGT_DIR/testssl_${ssl_port}_$TS.json" "$target:$ssl_port" > /dev/null 2>&1
                # Check if JSON file was created and has content
                if [[ -s "$TGT_DIR/testssl_${ssl_port}_$TS.json" ]]; then
                     findings=$(jq -r '.[] | select(type == "object") | select(.id != null and (.severity? | test("FATAL|CRITICAL|HIGH|MEDIUM|LOW|WARN|INFO"; "i")) and (.finding | test("is not offered|not vulnerable|OK|"; "i") | not)) | "\(.severity // "INFO") - \(.id): \(.finding)"' "$TGT_DIR/testssl_${ssl_port}_$TS.json" 2>/dev/null)

                    if [[ -n "$findings" ]]; then
                        SSL_FINDINGS+="Port $ssl_port:\n$findings\n\n"
                    else
                         # Check for connection errors explicitly if jq found nothing
                        if grep -q '"id" *: *"scanProblem"' "$TGT_DIR/testssl_${ssl_port}_$TS.json"; then
                             problem=$(jq -r '.[] | select(.id == "scanProblem") | .finding' "$TGT_DIR/testssl_${ssl_port}_$TS.json")
                             SSL_FINDINGS+="Port $ssl_port: Scan Problem - $problem\n\n"
                             log "${RED}TestSSL scan problem on $target:$ssl_port: $problem ${NC}"
                         else
                            SSL_FINDINGS+="Port $ssl_port: (No significant findings)\n\n"
                         fi
                    fi
                else
                    SSL_FINDINGS+="Port $ssl_port: (Scan failed or produced no output)\n\n"
                     log "${RED}TestSSL failed or produced no output for $target:$ssl_port ${NC}"
                fi
            done
            # If after all ports, SSL_FINDINGS is still empty, means no significant findings overall
             [[ -z "$SSL_FINDINGS" ]] && SSL_FINDINGS="(No significant findings across scanned ports)"
        fi
    fi

    # Output summaries (ensure atomicity using subshell grouping and locking)
    (
        # Associate FD 200 with the summary lock file and acquire lock
        exec 200>"$SUMMARY_LOCK_FILE"
        flock -x 200

        # These echo commands now write to the subshell's stdout,
        # which is redirected below (>>) to the actual summary file.
        echo "=========================="
        echo "Target: $target"
        echo "Timestamp: $TS"
        echo "--------------------------"
        echo "IP Addresses:"
        echo "$IPS"
        echo ""
        echo "TestSSL Findings:"
        echo -e "$SSL_FINDINGS" # Use -e to interpret escapes like \n
        echo ""
        echo "Open TCP Ports and Services:"
        awk '/\/tcp\s+open/ { print }' "$TGT_DIR/nmap_detailed_tcp_$TS.txt" || echo "None"
        echo ""
        echo "Open UDP Ports and Services:"
        awk '/\/udp\s+open/ { print }' "$TGT_DIR/nmap_detailed_udp_$TS.txt" || echo "None"
        echo ""
        echo "=========================="
        echo "" # Add extra newline for spacing

        # Lock on FD 200 is released automatically when the subshell exits
    ) >> "$SUMMARY_FILE" # Redirect the subshell's stdout (FD 1) to the summary file

    # Update HTML Report (also use flock for safety)
    (
        # Associate FD 201 with the HTML lock file and acquire lock
        exec 201>"$HTML_LOCK_FILE"
        flock -x 201

        # These echo commands write to the subshell's stdout,
        # which is redirected below (>>) to the actual HTML report file.
        echo "<hr><h2>$target ($TS)</h2>"
        echo "<h3>IP Addresses:</h3><pre>$IPS</pre>"
        echo "<h3>TestSSL Findings:</h3><pre>$(echo -e "$SSL_FINDINGS" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')</pre>"
        echo "<h3>Open TCP Ports and Services:</h3><pre>"
        print_port_section "$TGT_DIR/nmap_detailed_tcp_$TS.txt" "tcp" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g'
        echo "</pre>"
        echo "<h3>Open UDP Ports and Services:</h3><pre>"
        print_port_section "$TGT_DIR/nmap_detailed_udp_$TS.txt" "udp" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g'
        echo "</pre>"

        # Lock on FD 201 is released automatically when the subshell exits
    ) >> "$HTML_REPORT" # Redirect the subshell's stdout (FD 1) to the HTML report file

    # Update done list and progress file (critical section, using flock)
    (
        # Associate FD 202 with the done list lock file and acquire lock
        exec 202>"$TARGETS_DONE_LOCK_FILE"
        flock -x 202
        echo "$target" >> "$TARGETS_DONE_LIST"
        # Recalculate DONE based on the updated list and write to temp file
        DONE=$(sort -u "$TARGETS_DONE_LIST" | wc -l) # Count unique lines directly
        echo "$DONE" > "$TARGETS_DONE_FILE"
        # Lock on FD 202 is released automatically when the subshell exits
    ) # No redirection needed here, commands write directly to files

    log "${GREEN}Finished $target (${DONE}/${TARGETS_TOTAL})${NC}"

    # The main script will wait for all jobs and handle the final exit.
}

# === Progress monitor ===
show_progress &
PROGRESS_PID=$!
# Disown the progress monitor so it doesn't get killed if the terminal closes,
# although the main script should kill it on normal exit or interrupt.
disown $PROGRESS_PID &>/dev/null

# === Start scanning loop ===
while IFS= read -r target || [[ -n "$target" ]]; do
    # Skip empty lines and comments
    [[ -z "$target" || "$target" =~ ^\s*# ]] && continue
    # Trim whitespace
    target=$(echo "$target" | xargs)
     [[ -z "$target" ]] && continue # Skip if only whitespace

    # Check if already done (using flock for read safety)
    ALREADY_DONE=false
    (
         flock -s 201 # Shared lock for reading
         if grep -Fxq "$target" "$TARGETS_DONE_LIST"; then
             ALREADY_DONE=true
         fi
    ) 201<"$TARGETS_DONE_LIST.lock" # Read lock associated with lock file

    if $ALREADY_DONE; then
        log "${GREEN}Already scanned $target, skipping.${NC}"
        continue
    fi

    # Job control: Wait if max jobs are running
    while true; do
         # Count only scan_target jobs, not the progress bar
         RUNNING_SCANS=$(jobs -rp | grep -v "^${PROGRESS_PID}$" | wc -l)
         if [[ "$RUNNING_SCANS" -lt "$MAX_JOBS" ]]; then
             break # Slot available
         fi
         sleep 0.5 # Wait before checking again
     done

    scan_target "$target" &
done < "$INPUT_FILE"

# === Wait for all background scanning jobs to complete ===
# We need to wait specifically for the scan_target jobs, not the progress bar
log "Waiting for remaining scans to finish..."
while true; do
     # Check if any scan jobs (excluding the progress bar) are still running
     RUNNING_SCANS=$(jobs -rp | grep -v "^${PROGRESS_PID}$" | wc -l)
     if [[ "$RUNNING_SCANS" -eq 0 ]]; then
         break # All scan jobs are done
     fi
     # Optionally show which jobs are still running
     # jobs -rp | grep -v "^${PROGRESS_PID}$"
     sleep 1 # Wait before checking again
 done

# === Final cleanup after all jobs are finished ===
log "${GREEN}All scan jobs completed. Finalizing report...${NC}"

# Kill the progress bar process now that scans are done
kill "$PROGRESS_PID" &>/dev/null
wait "$PROGRESS_PID" 2>/dev/null # Wait briefly for it to exit cleanly

# Ensure HTML report is properly closed
if [[ -f "$HTML_REPORT" ]]; then
    # Check if the closing tags are already present before appending
    if ! tail -n 1 "$HTML_REPORT" | grep -q "</body></html>"; then
        echo "</body></html>" >> "$HTML_REPORT"
    fi
fi

# ---> Remove all temporary and lock files <---
rm -f "$TARGETS_DONE_FILE" \
      "$TARGETS_DONE_LOCK_FILE" \
      "$SUMMARY_LOCK_FILE" \
      "$HTML_LOCK_FILE"

log "${GREEN}Scan complete.${NC}"
log "${BLUE}Summary: $SUMMARY_FILE${NC}"
log "${BLUE}HTML Report: $HTML_REPORT${NC}"

exit 0 # Explicitly exit with success code
