#!/bin/bash

# Colors (for console output)
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[1;36m'
RESET='\033[0m'
BOLD=$(tput bold)
NORMAL=$(tput sgr0)

separator="================================================================================"

# Logging setup
private_ip=$(hostname -I | awk '{print $1}')
timestamp=$(date +"%Y%m%d_%H%M%S")
log_dir="/root/server_stats"
log_file="${log_dir}/${private_ip}_${timestamp}.log"

# Create log directory if it doesn't exist
mkdir -p "$log_dir" || {
    echo "Failed to create log directory $log_dir"
    exit 1
}

# Redirect output to both console and log file (without stripping colors for console)
exec > >(tee -a "$log_file") 2>&1

print_header() {
    echo -e "\n${CYAN}${BOLD}$1${RESET}"
    echo "$separator"
}

# ------------------------ System Info ------------------------

# Network Info
public_ip=$(curl -s --max-time 3 ifconfig.me || echo "Unable to determine")

print_header "ðŸŒ Network Info"
echo -e "Private IP      : ${GREEN}${private_ip}${RESET}"
echo -e "Public IP       : ${GREEN}${public_ip}${RESET}"

# ------------------------ OS Info ------------------------

print_header "ðŸ’» OS Info"

# Get OS information
if [ -f /etc/os-release ]; then
    os_name=$(grep PRETTY_NAME /etc/os-release | cut -d'"' -f2)
    os_version=$(grep VERSION_ID /etc/os-release | cut -d'"' -f2)
elif command -v lsb_release >/dev/null; then
    os_name=$(lsb_release -d | awk -F"\t" '{print $2}')
    os_version=$(lsb_release -r | awk -F"\t" '{print $2}')
else
    os_name=$(uname -o)
    os_version=$(uname -r)
fi

architecture=$(uname -m)
kernel_version=$(uname -r)

echo -e "OS Name          : ${GREEN}${os_name}${RESET}"
echo -e "OS Version       : ${GREEN}${os_version}${RESET}"
echo -e "Architecture     : ${GREEN}${architecture}${RESET}"
echo -e "Kernel Version   : ${GREEN}${kernel_version}${RESET}"

# ------------------------ Tool Versions & Status ------------------------

print_header "ðŸ”§ Tool Versions & Status"

# Function to check service status safely
check_service() {
    if systemctl list-unit-files | grep -q "$1.service"; then
        systemctl is-active "$1" 2>/dev/null || echo "Inactive"
    else
        echo "Not Installed"
    fi
}

kubelet_version=$(kubelet --version 2>/dev/null || echo "Not Installed")
kubelet_status=$(check_service kubelet)
docker_version=$(docker --version 2>/dev/null || echo "Not Installed")
docker_status=$(check_service docker)
git_version=$(git --version 2>/dev/null || echo "Not Installed")
nginx_status=$(check_service nginx)
containerd_status=$(check_service containerd)

echo -e "kubelet         : ${YELLOW}${kubelet_version}${RESET}"
echo -e "kubelet status  : ${YELLOW}${kubelet_status}${RESET}"
echo -e "Docker          : ${YELLOW}${docker_version}${RESET}"
echo -e "Docker status   : ${YELLOW}${docker_status}${RESET}"
echo -e "Git             : ${YELLOW}${git_version}${RESET}"
echo -e "Nginx status    : ${YELLOW}${nginx_status}${RESET}"
echo -e "Containerd stat.: ${YELLOW}${containerd_status}${RESET}"

# ------------------------ CPU Usage ------------------------

cpu_usage=$(top -bn1 | grep "Cpu(s)" | sed 's/.*, *\([0-9.]*\)%* id.*/\1/' | awk '{printf "%.1f", 100 - $1}')

print_header "ðŸ–¥ï¸  CPU Usage"
echo -e "Usage           : ${GREEN}${cpu_usage}%${RESET}"

# ------------------------ Memory Usage ------------------------

read -r total_memory available_memory <<< $(awk '/MemTotal/ {t=$2} /MemAvailable/ {a=$2} END {print t, a}' /proc/meminfo)
used_memory=$((total_memory - available_memory))

used_memory_percent=$(awk -v u=$used_memory -v t=$total_memory 'BEGIN { printf("%.1f", (u / t) * 100) }')
free_memory_percent=$(awk -v a=$available_memory -v t=$total_memory 'BEGIN { printf("%.1f", (a / t) * 100) }')

total_memory_gb=$(awk -v t=$total_memory 'BEGIN { printf("%.2f", t/1024/1024) }')
used_memory_gb=$(awk -v u=$used_memory 'BEGIN { printf("%.2f", u/1024/1024) }')
available_memory_gb=$(awk -v a=$available_memory 'BEGIN { printf("%.2f", a/1024/1024) }')

print_header "ðŸ§  Memory Usage"
printf "Total Memory    : ${YELLOW}%-10s GB${RESET}\n" "$total_memory_gb"
printf "Used Memory     : ${YELLOW}%-10s GB${RESET} (%s%%)\n" "$used_memory_gb" "$used_memory_percent"
printf "Free/Available  : ${YELLOW}%-10s GB${RESET} (%s%%)\n" "$available_memory_gb" "$free_memory_percent"

# ------------------------ Disk Usage ------------------------

print_header "ðŸ’¾ Disk Usage"

# Only check these mount points
mount_points=( "/" "/var" "/mounto" "/mnt" )

for mount_point in "${mount_points[@]}"; do
    if mount | grep -q "on $mount_point "; then
        df_output=$(df -h "$mount_point" | awk 'NR==2')
        df_output_raw=$(df "$mount_point" | awk 'NR==2')

        size_disk=$(echo "$df_output" | awk '{print $2}')
        used_disk=$(echo "$df_output" | awk '{print $3}')
        available_disk=$(echo "$df_output" | awk '{print $4}')

        size_kb=$(echo "$df_output_raw" | awk '{print $2}')
        used_kb=$(echo "$df_output_raw" | awk '{print $3}')
        avail_kb=$(echo "$df_output_raw" | awk '{print $4}')

        used_percent=$(echo "scale=1; $used_kb * 100 / $size_kb" | bc)
        avail_percent=$(echo "scale=1; $avail_kb * 100 / $size_kb" | bc)

        echo -e "\nMount Point     : ${CYAN}${mount_point}${RESET}"
        printf "Disk Size       : ${YELLOW}%-10s${RESET}\n" "$size_disk"
        printf "Used Space      : ${YELLOW}%-10s${RESET} (%s%%)\n" "$used_disk" "$used_percent"
        printf "Available Space : ${YELLOW}%-10s${RESET} (%s%%)\n" "$available_disk" "$avail_percent"
    else
        echo -e "\nMount Point     : ${CYAN}${mount_point}${RESET}"
        echo -e "${YELLOW}Not mounted or does not exist.${RESET}"
    fi
done

# ------------------------ Top Processes ------------------------

print_header "ðŸ”¥ Top 5 Processes by CPU"
ps -eo pid,user,%cpu,%mem,cmd --sort=-%cpu | head -n 6 | awk '{printf "%-8s %-8s %-6s %-6s ", $1, $2, $3, $4; for(i=5;i<=NF;i++) printf "%s ", $i; printf "\n"}'

print_header "ðŸ§  Top 5 Processes by Memory"
ps -eo pid,user,%cpu,%mem,cmd --sort=-%mem | head -n 6 | awk '{printf "%-8s %-8s %-6s %-6s ", $1, $2, $3, $4; for(i=5;i<=NF;i++) printf "%s ", $i; printf "\n"}'

print_header "âœ… Report saved to $log_file"
