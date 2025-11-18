#!/bin/bash

#==============================================================================
# Enhanced Server Statistics Script
# Description: Comprehensive server monitoring and statistics collection
# Supports: Ubuntu, Debian, RHEL, CentOS, Fedora, AlmaLinux, Rocky Linux
# Author: System Administrator
# Version: 2.0
#==============================================================================

# Exit on error, undefined variables, and pipe failures
set -euo pipefail

# Configuration (declare early, before help function)
SCRIPT_VERSION="2.0"
LOG_DIR="${LOG_DIR:-./logs}"
MAX_LOG_FILES="${MAX_LOG_FILES:-30}"
ENABLE_JSON_OUTPUT="${ENABLE_JSON_OUTPUT:-false}"
ALERT_CPU_THRESHOLD="${ALERT_CPU_THRESHOLD:-80}"
ALERT_MEM_THRESHOLD="${ALERT_MEM_THRESHOLD:-85}"
ALERT_DISK_THRESHOLD="${ALERT_DISK_THRESHOLD:-90}"

# Colors and formatting (will be cleared if --no-color is used)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[1;36m'
MAGENTA='\033[0;35m'
BLUE='\033[0;34m'
RESET='\033[0m'
BOLD=$(tput bold 2>/dev/null || echo '')
NORMAL=$(tput sgr0 2>/dev/null || echo '')
readonly SEPARATOR="================================================================================"

# Global variables for JSON output
declare -A json_data

#==============================================================================
# Command-line Arguments
#==============================================================================

show_help() {
    cat << EOF
Enhanced Server Statistics Script v${SCRIPT_VERSION}

Usage: $0 [OPTIONS]

OPTIONS:
    -h, --help              Show this help message
    -j, --json              Enable JSON output
    -q, --quick             Quick mode (skip I/O stats and temperature)
    -s, --security-only     Show only security information
    --no-color              Disable colored output
    --cpu-alert PERCENT     Set CPU alert threshold (default: 80)
    --mem-alert PERCENT     Set memory alert threshold (default: 85)
    --disk-alert PERCENT    Set disk alert threshold (default: 90)

ENVIRONMENT VARIABLES:
    LOG_DIR                 Log directory (default: ./logs)
    MAX_LOG_FILES          Number of log files to keep (default: 30)
    ENABLE_JSON_OUTPUT     Enable JSON export (default: false)
    ALERT_CPU_THRESHOLD    CPU alert threshold percentage
    ALERT_MEM_THRESHOLD    Memory alert threshold percentage
    ALERT_DISK_THRESHOLD   Disk alert threshold percentage

EXAMPLES:
    # Basic usage
    $0

    # Run with JSON output
    $0 --json

    # Quick check without I/O stats
    $0 --quick

    # Custom alert thresholds
    $0 --cpu-alert 70 --mem-alert 80

    # Security audit only
    sudo $0 --security-only

EOF
    exit 0
}

# Parse command-line arguments
QUICK_MODE=false
SECURITY_ONLY=false
DISABLE_COLOR=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            ;;
        -j|--json)
            ENABLE_JSON_OUTPUT=true
            shift
            ;;
        -q|--quick)
            QUICK_MODE=true
            shift
            ;;
        -s|--security-only)
            SECURITY_ONLY=true
            shift
            ;;
        --no-color)
            DISABLE_COLOR=true
            shift
            ;;
        --cpu-alert)
            ALERT_CPU_THRESHOLD="$2"
            shift 2
            ;;
        --mem-alert)
            ALERT_MEM_THRESHOLD="$2"
            shift 2
            ;;
        --disk-alert)
            ALERT_DISK_THRESHOLD="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use -h or --help for usage information"
            exit 1
            ;;
    esac
done

# Disable colors if requested
if [ "$DISABLE_COLOR" = true ]; then
    RED=''
    GREEN=''
    YELLOW=''
    CYAN=''
    MAGENTA=''
    BLUE=''
    RESET=''
    BOLD=''
    NORMAL=''
fi

#==============================================================================
# Utility Functions
#==============================================================================

print_header() {
    echo -e "\n${CYAN}${BOLD}$1${RESET}"
    echo "$SEPARATOR"
}

print_alert() {
    echo -e "${RED}${BOLD}⚠️  ALERT: $1${RESET}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  Warning: $1${RESET}"
}

print_success() {
    echo -e "${GREEN}✓ $1${RESET}"
}

error_exit() {
    echo -e "${RED}ERROR: $1${RESET}" >&2
    exit 1
}

check_command() {
    command -v "$1" &>/dev/null
}

setup_logging() {
    mkdir -p "$LOG_DIR"
    local log_file="$LOG_DIR/server-stats-$(date '+%F_%H-%M-%S').log"
    exec > >(tee -a "$log_file") 2>&1
    
    # Rotate old logs
    find "$LOG_DIR" -name "server-stats-*.log" -type f -mtime +$MAX_LOG_FILES -delete 2>/dev/null || true
}

get_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        echo "$ID"
    else
        echo "unknown"
    fi
}

#==============================================================================
# System Information
#==============================================================================

get_os_info() {
    print_header "System Information"
    
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        echo -e "${GREEN}OS:${RESET}           $NAME $VERSION"
        echo -e "${GREEN}Kernel:${RESET}       $(uname -r)"
        echo -e "${GREEN}Architecture:${RESET} $(uname -m)"
        
        json_data[os_name]="$NAME"
        json_data[os_version]="$VERSION"
        json_data[kernel]="$(uname -r)"
        json_data[architecture]="$(uname -m)"
    else
        uname -a
    fi
    
    # Hostname and IP
    echo -e "${GREEN}Hostname:${RESET}     $(hostname)"
    echo -e "${GREEN}Primary IP:${RESET}   $(hostname -I | awk '{print $1}')"
    
    # Last boot time
    if check_command who; then
        echo -e "${GREEN}Last Boot:${RESET}    $(who -b 2>/dev/null | awk '{print $3, $4}')"
    fi
}

#==============================================================================
# CPU Information and Usage
#==============================================================================

get_cpu_info() {
    print_header "🖥️  CPU Information & Usage"
    
    # CPU Model and Cores
    if [ -f /proc/cpuinfo ]; then
        local cpu_model=$(grep "model name" /proc/cpuinfo | head -1 | cut -d: -f2 | xargs)
        local cpu_cores=$(grep -c "processor" /proc/cpuinfo)
        local cpu_threads=$(nproc)
        
        echo -e "${GREEN}CPU Model:${RESET}    $cpu_model"
        echo -e "${GREEN}Cores:${RESET}        $cpu_cores"
        echo -e "${GREEN}Threads:${RESET}      $cpu_threads"
        
        json_data[cpu_model]="$cpu_model"
        json_data[cpu_cores]="$cpu_cores"
    fi
    
    # CPU Usage
    local cpu_usage
    if check_command mpstat; then
        cpu_usage=$(mpstat 1 1 | awk '/Average:/ {printf "%.1f", 100 - $NF}')
    else
        local top_output=$(top -bn2 -d 0.5 | tail -n +8)
        local cpu_idle=$(echo "$top_output" | grep "Cpu(s)" | tail -1 | sed 's/.*, *\([0-9.]*\)%* id.*/\1/')
        cpu_usage=$(awk -v idle="$cpu_idle" 'BEGIN { printf("%.1f", 100 - idle) }')
    fi
    
    echo -e "${GREEN}Current Usage:${RESET} ${cpu_usage}%"
    json_data[cpu_usage]="$cpu_usage"
    
    # Alert if high CPU
    if (( $(echo "$cpu_usage > $ALERT_CPU_THRESHOLD" | bc -l 2>/dev/null || echo 0) )); then
        print_alert "CPU usage is above ${ALERT_CPU_THRESHOLD}%!"
    fi
    
    # Load Average
    local load_avg=$(uptime | awk -F'load average:' '{print $2}' | xargs)
    echo -e "${GREEN}Load Average:${RESET}  $load_avg"
    
    # Uptime
    read system_uptime _ < /proc/uptime
    local total_seconds=${system_uptime%.*}
    local days=$((total_seconds / 86400))
    local hours=$(((total_seconds % 86400) / 3600))
    local minutes=$(((total_seconds % 3600) / 60))
    
    local uptime_str=""
    [[ $days -gt 0 ]] && uptime_str="${days}d "
    [[ $hours -gt 0 ]] && uptime_str="${uptime_str}${hours}h "
    [[ $minutes -gt 0 ]] && uptime_str="${uptime_str}${minutes}m"
    
    echo -e "${GREEN}Uptime:${RESET}        $uptime_str"
    json_data[uptime_seconds]="$total_seconds"
}

#==============================================================================
# Memory Usage
#==============================================================================

get_memory_info() {
    print_header "🧠 Memory Usage"
    
    # Read memory info
    local total_mem=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
    local available_mem=$(awk '/MemAvailable/ {print $2}' /proc/meminfo)
    local used_mem=$((total_mem - available_mem))
    
    # Calculate percentages
    local used_percent=$(awk -v u=$used_mem -v t=$total_mem 'BEGIN { printf("%.1f", (u / t) * 100) }')
    local free_percent=$(awk -v a=$available_mem -v t=$total_mem 'BEGIN { printf("%.1f", (a / t) * 100) }')
    
    # Convert to MB/GB
    local total_gb=$(awk -v t=$total_mem 'BEGIN { printf("%.2f", t/1024/1024) }')
    local used_gb=$(awk -v u=$used_mem 'BEGIN { printf("%.2f", u/1024/1024) }')
    local available_gb=$(awk -v a=$available_mem 'BEGIN { printf("%.2f", a/1024/1024) }')
    
    printf "${GREEN}Total:${RESET}        ${YELLOW}%6.2f GB${RESET}\n" "$total_gb"
    printf "${GREEN}Used:${RESET}         ${YELLOW}%6.2f GB${RESET} (%s%%)\n" "$used_gb" "$used_percent"
    printf "${GREEN}Available:${RESET}    ${YELLOW}%6.2f GB${RESET} (%s%%)\n" "$available_gb" "$free_percent"
    
    json_data[memory_total_gb]="$total_gb"
    json_data[memory_used_percent]="$used_percent"
    
    # Swap information
    local swap_total=$(awk '/SwapTotal/ {print $2}' /proc/meminfo)
    local swap_free=$(awk '/SwapFree/ {print $2}' /proc/meminfo)
    local swap_used=$((swap_total - swap_free))
    
    if [ "$swap_total" -gt 0 ]; then
        local swap_used_gb=$(awk -v s=$swap_used 'BEGIN { printf("%.2f", s/1024/1024) }')
        local swap_total_gb=$(awk -v s=$swap_total 'BEGIN { printf("%.2f", s/1024/1024) }')
        local swap_percent=$(awk -v u=$swap_used -v t=$swap_total 'BEGIN { printf("%.1f", (u / t) * 100) }')
        
        printf "${GREEN}Swap Used:${RESET}    ${YELLOW}%6.2f GB${RESET} / %.2f GB (%s%%)\n" "$swap_used_gb" "$swap_total_gb" "$swap_percent"
    fi
    
    # Alert if high memory
    if (( $(echo "$used_percent > $ALERT_MEM_THRESHOLD" | bc -l 2>/dev/null || echo 0) )); then
        print_alert "Memory usage is above ${ALERT_MEM_THRESHOLD}%!"
    fi
}

#==============================================================================
# Disk Usage
#==============================================================================

get_disk_info() {
    print_header "💾 Disk Usage"
    
    # Show all mounted filesystems
    df -h -x tmpfs -x devtmpfs -x squashfs 2>/dev/null | awk 'NR==1 {printf "%-20s %8s %8s %8s %6s %s\n", $1, $2, $3, $4, $5, $6} NR>1 {printf "%-20s %8s %8s %8s %6s %s\n", $1, $2, $3, $4, $5, $6}'
    
    # Check for alerts on root partition
    local root_usage=$(df / 2>/dev/null | awk 'NR==2 {print $5}' | sed 's/%//')
    json_data[disk_root_usage]="$root_usage"
    
    if [ -n "$root_usage" ] && [ "$root_usage" -gt "$ALERT_DISK_THRESHOLD" ]; then
        print_alert "Root partition usage is above ${ALERT_DISK_THRESHOLD}%!"
    fi
    
    # I/O Statistics (if iostat available and not in quick mode)
    if [ "$QUICK_MODE" = false ] && check_command iostat; then
        echo ""
        echo -e "${CYAN}Disk I/O Statistics (Average):${RESET}"
        iostat -x 1 2 2>/dev/null | awk '/^avg-cpu:/{flag=1} flag' | head -15
    fi
}

#==============================================================================
# Network Information
#==============================================================================

get_network_info() {
    print_header "🌐 Network Information"
    
    # Network interfaces and IPs
    if check_command ip; then
        echo -e "${CYAN}Active Interfaces:${RESET}"
        ip -br addr show | grep -v "^lo" | awk '{printf "%-15s %-10s %s\n", $1, $2, $3}'
    fi
    
    echo ""
    
    # Network statistics
    if check_command ss; then
        local tcp_established=$(ss -tan | grep ESTAB | wc -l)
        local tcp_listen=$(ss -tln | grep LISTEN | wc -l)
        
        echo -e "${GREEN}TCP Established:${RESET} $tcp_established"
        echo -e "${GREEN}TCP Listening:${RESET}   $tcp_listen"
    elif check_command netstat; then
        local tcp_established=$(netstat -tan | grep ESTABLISHED | wc -l)
        local tcp_listen=$(netstat -tln | grep LISTEN | wc -l)
        
        echo -e "${GREEN}TCP Established:${RESET} $tcp_established"
        echo -e "${GREEN}TCP Listening:${RESET}   $tcp_listen"
    fi
}

#==============================================================================
# Process Information
#==============================================================================

get_process_info() {
    print_header "🔥 Top Processes by CPU"
    ps aux --sort=-%cpu | head -6 | awk 'NR==1 {printf "%-12s %-7s %-6s %-6s %-10s %s\n", $1, $2, $3, $4, $8, $11} NR>1 {printf "%-12s %-7s %-6s %-6s %-10s %s\n", $1, $2, $3, $4, $8, $11}'
    
    print_header "🧠 Top Processes by Memory"
    ps aux --sort=-%mem | head -6 | awk 'NR==1 {printf "%-12s %-7s %-6s %-6s %-10s %s\n", $1, $2, $3, $4, $8, $11} NR>1 {printf "%-12s %-7s %-6s %-6s %-10s %s\n", $1, $2, $3, $4, $8, $11}'
    
    # Process count
    local total_processes=$(ps aux | wc -l)
    local zombie_processes=$(ps aux | awk '$8 ~ /^Z/ {count++} END {print count+0}')
    
    echo ""
    echo -e "${GREEN}Total Processes:${RESET}  $total_processes"
    
    if [ "$zombie_processes" -gt 0 ]; then
        print_warning "Zombie processes detected: $zombie_processes"
    fi
}

#==============================================================================
# User Sessions
#==============================================================================

get_user_sessions() {
    print_header "👥 Active User Sessions"
    
    echo -e "${CYAN}Currently Logged In:${RESET}"
    
    if [ -z "$(who)" ]; then
        echo "No users currently logged in"
    else
        printf "%-12s %-12s %-20s %s\n" "USER" "TTY" "LOGIN-TIME" "FROM"
        who | while read -r line; do
            local user=$(echo "$line" | awk '{print $1}')
            local tty=$(echo "$line" | awk '{print $2}')
            local date_time=$(echo "$line" | awk '{print $3, $4}')
            local from=$(echo "$line" | awk '{print $5}' | tr -d '()')
            printf "%-12s %-12s %-20s %s\n" "$user" "$tty" "$date_time" "$from"
        done
        
        echo ""
        local unique_users=$(who | awk '{print $1}' | sort -u | wc -l)
        local total_sessions=$(who | wc -l)
        echo -e "${GREEN}Unique Users:${RESET}    $unique_users"
        echo -e "${GREEN}Total Sessions:${RESET}  $total_sessions"
    fi
}

#==============================================================================
# Security - Failed Login Attempts
#==============================================================================

get_security_info() {
    print_header "🔒 Security - Failed Login Attempts"
    
    local auth_log=""
    local distro=$(get_distro)
    
    # Determine correct log file
    if [ -f /var/log/auth.log ]; then
        auth_log="/var/log/auth.log"
    elif [ -f /var/log/secure ]; then
        auth_log="/var/log/secure"
    else
        echo "Authentication log not found or not accessible"
        return
    fi
    
    # Check if we have permission
    if [ ! -r "$auth_log" ]; then
        print_warning "No permission to read $auth_log. Run with sudo for security info."
        return
    fi
    
    # Top failed login IPs (last 24 hours)
    echo -e "${CYAN}Top IPs with Failed SSH Login Attempts (Last 24h):${RESET}"
    local failed_ips=$(grep "Failed password" "$auth_log" | \
        awk '{for(i=1;i<=NF;i++){if($i=="from"){print $(i+1)}}}' | \
        sort | uniq -c | sort -rn | head -10)
    
    if [ -n "$failed_ips" ]; then
        echo "$failed_ips" | awk '{printf "  %5d attempts  %s\n", $1, $2}'
        
        # Check for brute force attempts
        local max_attempts=$(echo "$failed_ips" | head -1 | awk '{print $1}')
        if [ "$max_attempts" -gt 10 ]; then
            print_alert "Possible brute force attack detected! IP with $max_attempts failed attempts."
        fi
    else
        print_success "No failed SSH login attempts in the last 24 hours"
    fi
    
    # Recent failed logins (last 5)
    echo ""
    echo -e "${CYAN}Recent Failed SSH Login Attempts (Last 5):${RESET}"
    local recent_failures=$(grep "Failed password" "$auth_log" | tail -5)
    
    if [ -n "$recent_failures" ]; then
        echo "$recent_failures" | while read -r line; do
            local timestamp=$(echo "$line" | awk '{print $1}')
            local user=$(echo "$line" | grep -oP 'for (\w+|invalid user \w+)' | awk '{print $NF}')
            local ip=$(echo "$line" | grep -oP 'from \S+' | awk '{print $2}')
            echo "  $timestamp → User: $user, IP: $ip"
        done
    else
        echo "  No recent failed attempts found"
    fi
    
    # Check for sudo authentication failures
    echo ""
    echo -e "${CYAN}Failed Sudo Attempts (Last 5):${RESET}"
    local sudo_failures=$(grep "authentication failure" "$auth_log" | grep "sudo" | tail -5)
    
    if [ -n "$sudo_failures" ]; then
        echo "$sudo_failures" | while read -r line; do
            echo "  $(echo "$line" | awk '{print $1, $2, $3}') → $(echo "$line" | grep -oP 'user=\w+')"
        done
    else
        echo "  No sudo authentication failures found"
    fi
}

#==============================================================================
# Service Status (Common Services)
#==============================================================================

get_service_status() {
    print_header "⚙️  Critical Services Status"
    
    local services=("sshd" "ssh" "docker" "nginx" "apache2" "httpd" "mysql" "mariadb" "postgresql" "redis" "mongodb")
    local found_services=0
    
    for service in "${services[@]}"; do
        if systemctl list-unit-files 2>/dev/null | grep -q "^${service}.service"; then
            local status=$(systemctl is-active "$service" 2>/dev/null || echo "inactive")
            local enabled=$(systemctl is-enabled "$service" 2>/dev/null || echo "disabled")
            
            if [ "$status" = "active" ]; then
                echo -e "${GREEN}✓${RESET} ${service}: ${GREEN}running${RESET} (${enabled})"
                ((found_services++))
            elif [ "$enabled" != "disabled" ]; then
                echo -e "${RED}✗${RESET} ${service}: ${RED}stopped${RESET} (${enabled})"
                ((found_services++))
            fi
        fi
    done
    
    # Check for Docker containers if Docker is running
    if systemctl is-active docker &>/dev/null && check_command docker; then
        local running_containers=$(docker ps -q 2>/dev/null | wc -l)
        local total_containers=$(docker ps -aq 2>/dev/null | wc -l)
        
        if [ "$total_containers" -gt 0 ]; then
            echo ""
            echo -e "${CYAN}Docker Containers:${RESET} $running_containers running / $total_containers total"
            ((found_services++))
        fi
    fi
    
    if [ $found_services -eq 0 ]; then
        echo "No monitored services found or systemctl not available"
    fi
}

#==============================================================================
# System Temperature (if sensors available)
#==============================================================================

get_temperature_info() {
    if [ "$QUICK_MODE" = false ] && check_command sensors; then
        print_header "🌡️  System Temperature"
        
        sensors 2>/dev/null | grep -E "Core|temp|Package" | head -10
    fi
}

#==============================================================================
# NFS Mounts
#==============================================================================

get_nfs_mounts() {
    local nfs_mounts=$(df -h -t nfs -t nfs4 2>/dev/null)
    
    if [ -n "$nfs_mounts" ] && [ "$(echo "$nfs_mounts" | wc -l)" -gt 1 ]; then
        print_header "📡 NFS Mounts"
        echo "$nfs_mounts"
    fi
}

#==============================================================================
# System Health Summary
#==============================================================================

print_health_summary() {
    print_header "📊 System Health Summary"
    
    local health_score=100
    local issues=()
    
    # Check CPU
    local cpu_usage=${json_data[cpu_usage]:-0}
    if (( $(echo "$cpu_usage > 80" | bc -l 2>/dev/null || echo 0) )); then
        health_score=$((health_score - 20))
        issues+=("High CPU usage: ${cpu_usage}%")
    fi
    
    # Check Memory
    local mem_usage=${json_data[memory_used_percent]:-0}
    if (( $(echo "$mem_usage > 85" | bc -l 2>/dev/null || echo 0) )); then
        health_score=$((health_score - 20))
        issues+=("High memory usage: ${mem_usage}%")
    fi
    
    # Check Disk
    local disk_usage=${json_data[disk_root_usage]:-0}
    if [ -n "$disk_usage" ] && [ "$disk_usage" -gt 90 ]; then
        health_score=$((health_score - 30))
        issues+=("Critical disk usage: ${disk_usage}%")
    elif [ -n "$disk_usage" ] && [ "$disk_usage" -gt 80 ]; then
        health_score=$((health_score - 15))
        issues+=("High disk usage: ${disk_usage}%")
    fi
    
    # Display health score
    if [ $health_score -ge 80 ]; then
        echo -e "${GREEN}Health Score: ${health_score}/100 ✓ HEALTHY${RESET}"
    elif [ $health_score -ge 60 ]; then
        echo -e "${YELLOW}Health Score: ${health_score}/100 ⚠ WARNING${RESET}"
    else
        echo -e "${RED}Health Score: ${health_score}/100 ✗ CRITICAL${RESET}"
    fi
    
    # Display issues
    if [ ${#issues[@]} -gt 0 ]; then
        echo ""
        echo -e "${YELLOW}Issues detected:${RESET}"
        for issue in "${issues[@]}"; do
            echo "  • $issue"
        done
    fi
}

#==============================================================================
# JSON Export
#==============================================================================

export_json() {
    if [ "$ENABLE_JSON_OUTPUT" = "true" ]; then
        local json_file="$LOG_DIR/server-stats-$(date '+%F_%H-%M-%S').json"
        echo "{" > "$json_file"
        local first=true
        for key in "${!json_data[@]}"; do
            if [ "$first" = true ]; then
                first=false
            else
                echo "," >> "$json_file"
            fi
            echo -n "  \"$key\": \"${json_data[$key]}\"" >> "$json_file"
        done
        echo "" >> "$json_file"
        echo "}" >> "$json_file"
        echo -e "\n${GREEN}JSON output saved to: $json_file${RESET}"
    fi
}

#==============================================================================
# Main Execution
#==============================================================================

main() {
    # Setup
    setup_logging
    
    # Security-only mode
    if [ "$SECURITY_ONLY" = true ]; then
        print_header "🔒 Security Audit - $(date '+%Y-%m-%d %H:%M:%S')"
        get_security_info
        exit 0
    fi
    
    # Header
    echo -e "${MAGENTA}${BOLD}"
    echo "╔════════════════════════════════════════════════════════════════════════════╗"
    echo "║                    ENHANCED SERVER STATISTICS REPORT                       ║"
    echo "║                          Version $SCRIPT_VERSION                                      ║"
    echo "╚════════════════════════════════════════════════════════════════════════════╝"
    echo -e "${RESET}"
    echo "Generated: $(date '+%Y-%m-%d %H:%M:%S %Z')"
    
    # Collect all information
    get_os_info
    get_cpu_info
    get_memory_info
    get_disk_info
    get_nfs_mounts
    get_network_info
    get_process_info
    get_user_sessions
    get_security_info
    get_service_status
    get_temperature_info
    print_health_summary
    
    # Export JSON if enabled
    export_json
    
    # Footer
    echo ""
    echo "$SEPARATOR"
    echo -e "${CYAN}Report completed at $(date '+%Y-%m-%d %H:%M:%S')${RESET}"
    echo "$SEPARATOR"
}

# Run main function
main "$@"