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

mkdir -p "$OUTPUT_DIR"
echo "" > "$SUMMARY_FILE"
echo "<html><head><title>Scan Report</title></head><body><h1>OSINT Scan Report - $(echo "$CLIENT" | tr '[:lower:]' '[:upper:]')</h1>" > "$HTML_REPORT"
echo "=== Log started at $(date) ===" > "$LOG_FILE"
touch "$TARGETS_DONE_LIST"

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
    echo -e "[$(date +%H:%M:%S)] $*" | tee -a "$LOG_FILE"
}

# === Safe file reader for TCP/UDP port data ===
print_port_section() {
    local file="$1"
    if [[ -s "$file" ]]; then
        grep -E '^[0-9]+/(tcp|udp)\s+open' "$file" || echo "None"
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
        sleep 1
        DONE=$(cat "$TARGETS_DONE_FILE")
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

        RUNNING=$(jobs -r | wc -l)
        if [[ "$RUNNING" -eq 0 && $(jobs -p | wc -l) -gt 0 ]]; then
            RUNNING="flushing"
        fi

        i=$(( (i+1) %4 ))
        printf "\r${YELLOW}[%s] [%s%s] %d%% (%d/%d targets) Running: %s | ETA: %s ${NC}" \
            "${spin:$i:1}" "$BAR" "$EMPTY_BAR" "$PERCENT" "$DONE" "$TARGETS_TOTAL" "$RUNNING" "$ETA"
    done
}

# === Cleanup handler ===
cleanup() {
    echo -e "\n${RED}Interrupted. Cleaning up...${NC}"
    kill $PROGRESS_PID &>/dev/null
    jobs -p | xargs -r kill 2>/dev/null

    # Gracefully close HTML if it exists and is open
    if [[ -f "$HTML_REPORT" ]]; then
        if ! grep -q "</body></html>" "$HTML_REPORT"; then
            echo "</body></html>" >> "$HTML_REPORT"
        fi
    fi

    rm -f "$TARGETS_DONE_FILE"
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

    # TCP Discovery
    log "${YELLOW}Discovering open TCP ports (-p-)${NC}"
    sudo nmap -p- --min-rate 1000 -T4 --max-retries 1 --host-timeout 5m -Pn "$target" -oG "$TGT_DIR/nmap_tcp_ports_$TS.gnmap"
    OPEN_PORTS=$(awk -F'[ /]' '/Ports:/ {
        for (i=1; i<=NF; i++) {
            if ($i == "open" && $(i+1) == "tcp") {
                print $(i-1)
            }
        }
    }' "$TGT_DIR/nmap_tcp_ports_$TS.gnmap" | sort -n | uniq | paste -sd, -)

    log "${BLUE}Extracted TCP Ports: $OPEN_PORTS${NC}"

    if [[ -z "$OPEN_PORTS" ]]; then
        log "${RED}Warning: No open TCP ports extracted from gnmap for $target${NC}"
            echo "(No open TCP ports found)" > "$TGT_DIR/nmap_detailed_tcp_$TS.txt"
    else
        log "${YELLOW}Enumerating services on TCP ports: $OPEN_PORTS${NC}"
        sudo nmap -sC -sV -T4 --max-retries 2 --host-timeout 5m -p "$OPEN_PORTS" -Pn "$target" -oN "$TGT_DIR/nmap_detailed_tcp_$TS.txt"
    fi



    # Detailed TCP Scan
    if [ -n "$OPEN_PORTS" ]; then
        log "${YELLOW}Enumerating services on TCP ports: $OPEN_PORTS${NC}"
        sudo nmap -sC -sV -T4 --max-retries 2 --host-timeout 5m -p "$OPEN_PORTS" -Pn "$target" -oN "$TGT_DIR/nmap_detailed_tcp_$TS.txt"
    else
        echo "(No open TCP ports found)" > "$TGT_DIR/nmap_detailed_tcp_$TS.txt"
    fi

    # UDP Discovery
    if ! $SKIP_UDP; then
        log "${YELLOW}Discovering open UDP ports (top 1000)${NC}"
        sudo nmap -sU --top-ports 1000 --min-rate 500 -T4 --max-retries 1 --host-timeout 3m -Pn "$target" -oG "$TGT_DIR/nmap_udp_ports_$TS.gnmap"
        OPEN_UDP_PORTS=$(grep '/open/udp' "$TGT_DIR/nmap_udp_ports_$TS.gnmap" \
            | awk '/Ports:/{print $NF}' \
            | tr ',' '\n' | grep -E '^[0-9]+$' \
            | sort -n | paste -sd, -)

        if [ -n "$OPEN_UDP_PORTS" ]; then
            log "${YELLOW}Enumerating services on UDP ports: $OPEN_UDP_PORTS${NC}"
            sudo nmap -sU -sV -T4 --max-retries 1 --host-timeout 5m -p "$OPEN_UDP_PORTS" -Pn "$target" -oN "$TGT_DIR/nmap_detailed_udp_$TS.txt"
        else
            echo "(No open UDP ports found)" > "$TGT_DIR/nmap_detailed_udp_$TS.txt"
        fi
    else
        echo "(UDP Scan Skipped)" > "$TGT_DIR/nmap_udp_ports_$TS.txt"
    fi

    # TestSSL
    if ! $SKIP_TESTSSL; then
        log "${YELLOW}Analyzing services for SSL ports...${NC}"
        SSL_PORTS=()

        for port in "${DEFAULT_SSL_PORTS[@]}"; do
            if grep -q "^$port/tcp\s\+open" "$TGT_DIR/nmap_detailed_tcp_$TS.txt"; then
                SSL_PORTS+=("$port")
            fi
        done

        while read -r line; do
            port=$(echo "$line" | cut -d '/' -f 1)
            service=$(echo "$line" | awk '{print $3}')
            if [[ "$service" == *"ssl"* || "$service" == *"https"* ]]; then
                SSL_PORTS+=("$port")
            fi
        done < <(grep -E '^[0-9]+/tcp\s+open' "$TGT_DIR/nmap_detailed_tcp_$TS.txt")

        if [ "${#SSL_PORTS[@]}" -eq 0 ]; then
            log "${RED}No SSL-enabled ports found on $target${NC}"
            SSL_FINDINGS="(No SSL ports found)"
        else
            SSL_FINDINGS=""
            for ssl_port in $(echo "${SSL_PORTS[@]}" | tr ' ' '\n' | sort -u); do
                log "${YELLOW}Running testssl on https://$target:$ssl_port${NC}"
                testssl.sh --quiet --jsonfile-pretty "$TGT_DIR/testssl_${ssl_port}_$TS.json" "https://$target:$ssl_port"
                findings=$(jq -r '.[] | select(type == "object") | select(.id != null and (.finding | test("OBSOLETE|VULNERABLE|INSECURE"; "i"))) | "\(.id): \(.finding)"' "$TGT_DIR/testssl_${ssl_port}_$TS.json")
                if [[ -n "$findings" ]]; then
                    SSL_FINDINGS+="Port $ssl_port:\n$findings\n\n"
                fi
            done
        fi
    else
        SSL_FINDINGS="(Skipped)"
    fi

    # Output summaries
    {
        echo "=========================="
        echo "Target: $target"
        echo "--------------------------"
        echo "IP Addresses:"
        echo "$IPS"
        echo ""
        echo "Obsolete / Vulnerable Ciphers (testssl):"
        echo -e "$SSL_FINDINGS"
        echo ""
        echo "Open TCP Ports and Services:"
        awk '/\/tcp\s+open/ { print }' "$TGT_DIR/nmap_detailed_tcp_$TS.txt" || echo "None"
        echo ""
        echo "Open UDP Ports:"
        awk '/\/udp\s+open/ { print }' "$TGT_DIR/nmap_detailed_udp_$TS.txt" 2>/dev/null || echo "None"
        echo ""
    } >> "$SUMMARY_FILE"

    {
        echo "<hr><h2>$target</h2>"
        echo "<h3>IP Addresses:</h3><pre>$IPS</pre>"
        echo "<h3>TestSSL Vulnerabilities:</h3><pre>${SSL_FINDINGS}</pre>"
        echo "<h3>Open TCP Ports and Services:</h3><pre>"
            print_port_section "$TGT_DIR/nmap_detailed_tcp_$TS.txt"
            echo "</pre>"

       echo "<h3>Open UDP Ports:</h3><pre>"
            print_port_section "$TGT_DIR/nmap_detailed_udp_$TS.txt"
            echo "</pre>"
    
    } >> "$HTML_REPORT"

    echo "$target" >> "$TARGETS_DONE_LIST"
    DONE=$(grep -Fx -f "$TARGETS_DONE_LIST" "$INPUT_FILE" | sort -u | wc -l)
    echo "$DONE" > "$TARGETS_DONE_FILE"
    log "${GREEN}Finished $target${NC}"


    # Final check: if all done, close HTML + exit
    CURRENT_DONE=$(grep -Fx -f "$TARGETS_DONE_LIST" "$INPUT_FILE" | sort -u | wc -l)
    echo "$CURRENT_DONE" > "$TARGETS_DONE_FILE"

    if [[ "$CURRENT_DONE" -eq "$TARGETS_TOTAL" ]]; then
        log "${GREEN}All scans finished. Closing report and exiting...${NC}"
        [[ -f "$HTML_REPORT" ]] && echo "</body></html>" >> "$HTML_REPORT"
        kill "$PROGRESS_PID" &>/dev/null
        rm -f "$TARGETS_DONE_FILE"
        exit 0
    fi

    # Recalculate progress
    CURRENT_DONE=$(grep -Fx -f "$TARGETS_DONE_LIST" "$INPUT_FILE" | sort -u | wc -l)
    echo "$CURRENT_DONE" > "$TARGETS_DONE_FILE"

    if [[ "$CURRENT_DONE" -eq "$TARGETS_TOTAL" ]]; then
        log "${GREEN}All scans finished. Closing report and exiting...${NC}"
        [[ -f "$HTML_REPORT" && ! $(tail -1 "$HTML_REPORT") =~ "</body></html>" ]] && echo "</body></html>" >> "$HTML_REPORT"
        kill "$PROGRESS_PID" &>/dev/null
        rm -f "$TARGETS_DONE_FILE"
        exit 0
    fi

}

# === Progress monitor ===
show_progress &
PROGRESS_PID=$!

# === Start scanning loop ===
while IFS= read -r target || [[ -n "$target" ]]; do
    [[ -z "$target" || "$target" == \#* ]] && continue

    if grep -Fxq "$target" "$TARGETS_DONE_LIST"; then
        log "${GREEN}Already scanned $target, skipping.${NC}"
        continue
    fi

    while (( $(jobs -r | wc -l) >= MAX_JOBS )); do
        sleep 0.5
    done

    scan_target "$target" &
done < "$INPUT_FILE"

# === Final sync after all background jobs ===
wait

# === Safety fallback: close HTML if missed inside scan_target ===
DONE=$(cat "$TARGETS_DONE_FILE")
if [[ "$DONE" -eq "$TARGETS_TOTAL" ]]; then
    log "${GREEN}Scan complete. Finalizing HTML report...${NC}"
    if [[ -f "$HTML_REPORT" && ! $(tail -1 "$HTML_REPORT") =~ "</body></html>" ]]; then
        echo "</body></html>" >> "$HTML_REPORT"
    fi
fi

kill "$PROGRESS_PID" &>/dev/null
rm -f "$TARGETS_DONE_FILE"

log "${GREEN}All targets scanned.${NC}"
log "${BLUE}Summary: $SUMMARY_FILE${NC}"
log "${BLUE}HTML Report: $HTML_REPORT${NC}"
