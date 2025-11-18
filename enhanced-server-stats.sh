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

# Configuration
readonly SCRIPT_VERSION="2.0"
readonly LOG_DIR="${LOG_DIR:-./logs}"
readonly MAX_LOG_FILES="${MAX_LOG_FILES:-30}"
readonly ENABLE_JSON_OUTPUT="${ENABLE_JSON_OUTPUT:-false}"
readonly ALERT_CPU_THRESHOLD="${ALERT_CPU_THRESHOLD:-80}"
readonly ALERT_MEM_THRESHOLD="${ALERT_MEM_THRESHOLD:-85}"
readonly ALERT_DISK_THRESHOLD="${ALERT_DISK_THRESHOLD:-90}"

# Colors and formatting
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly CYAN='\033[1;36m'
readonly MAGENTA='\033[0;35m'
readonly BLUE='\033[0;34m'
readonly RESET='\033[0m'
readonly BOLD=$(tput bold 2>/dev/null || echo '')
readonly NORMAL=$(tput sgr0 2>/dev/null || echo '')
readonly SEPARATOR="================================================================================"

# Global variables for JSON output
declare -A json_data

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
        echo -e "${GREEN}Last Boot:${RESET}    $(who -b | awk '{print $3, $4}')"
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
    df -h -x tmpfs -x devtmpfs -x squashfs | awk 'NR==1 {printf "%-20s %8s %8s %8s %6s %s\n", $1, $2, $3, $4, $5, $6} NR>1 {printf "%-20s %8s %8s %8s %6s %s\n", $1, $2, $3, $4, $5, $6}'
    
    # Check for alerts on root partition
    local root_usage=$(df / | awk 'NR==2 {print $5}' | sed 's/%//')
    json_data[disk_root_usage]="$root_usage"
    
    if [ "$root_usage" -gt "$ALERT_DISK_THRESHOLD" ]; then
        print_alert "Root partition usage is above ${ALERT_DISK_THRESHOLD}%!"
    fi
    
    # I/O Statistics (if iostat available)
    if check_command iostat; then
        echo ""
        echo -e "${CYAN}Disk I/O:${RESET}"
        iostat -x 1 2 | tail -n +4 | head -n -1
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
    local zombie_processes=$(ps aux | awk '{print $8}' | grep -c '^Z' || echo 0)
    
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
    printf "%-12s %-12s %-20s %s\n" "USER" "TTY" "LOGIN-TIME" "FROM"
    who | awk '{printf "%-12s %-12s %-20s %s\n", $1, $2, $3" "$4, $5}'
    
    echo ""
    local unique_users=$(who | awk '{print $1}' | sort -u | wc -l)
    echo -e "${GREEN}Unique Users:${RESET} $unique_users"
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
    echo -e "${CYAN}Top IPs with Failed Logins (Last 24h):${RESET}"
    local failed_ips=$(grep "Failed password" "$auth_log" | \
        awk '{for(i=1;i<=NF;i++){if($i=="from"){print $(i+1)}}}' | \
        sort | uniq -c | sort -rn | head -10)
    
    if [ -n "$failed_ips" ]; then
        echo "$failed_ips" | awk '{printf "  %5d  %s\n", $1, $2}'
        
        # Check for brute force attempts
        local max_attempts=$(echo "$failed_ips" | head -1 | awk '{print $1}')
        if [ "$max_attempts" -gt 10 ]; then
            print_alert "Possible brute force attack detected! IP with $max_attempts failed attempts."
        fi
    else
        print_success "No failed login attempts in the last 24 hours"
    fi
    
    # Recent failed logins (last 10)
    echo ""
    echo -e "${CYAN}Recent Failed Login Attempts:${RESET}"
    grep -E "Failed password|authentication failure" "$auth_log" | tail -5 | \
        awk '{print $1, $2, $3, "→", substr($0, index($0,$9))}'
}

#==============================================================================
# Service Status (Common Services)
#==============================================================================

get_service_status() {
    print_header "⚙️  Critical Services Status"
    
    local services=("sshd" "ssh" "docker" "nginx" "apache2" "httpd" "mysql" "mariadb" "postgresql")
    local found_services=0
    
    for service in "${services[@]}"; do
        if systemctl list-unit-files | grep -q "^${service}.service"; then
            local status=$(systemctl is-active "$service" 2>/dev/null || echo "inactive")
            if [ "$status" = "active" ]; then
                echo -e "${GREEN}✓${RESET} ${service}: ${GREEN}running${RESET}"
                ((found_services++))
            elif systemctl is-enabled "$service" &>/dev/null; then
                echo -e "${RED}✗${RESET} ${service}: ${RED}stopped${RESET}"
                ((found_services++))
            fi
        fi
    done
    
    if [ $found_services -eq 0 ]; then
        echo "No monitored services found"
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
    if [ "$disk_usage" -gt 90 ]; then
        health_score=$((health_score - 30))
        issues+=("Critical disk usage: ${disk_usage}%")
    elif [ "$disk_usage" -gt 80 ]; then
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
    get_network_info
    get_process_info
    get_user_sessions
    get_security_info
    get_service_status
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