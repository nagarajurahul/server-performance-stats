# 📊 Server Performance Stats

**`server-stats.sh`** is a Bash script that provides a quick snapshot of your Linux server’s performance. It monitors CPU usage, memory stats, disk usage, and the top resource-consuming processes.

---

## 🔧 Features

- ✅ **CPU Usage:** Real-time CPU utilization.
- ✅ **Memory Stats:** Total, used, and available memory, with usage percentages.
- ✅ **Disk Usage:** Disk space usage of the root (`/`) partition, with also percentage.
- ✅ **Top Processes:**
  - Top 5 processes by CPU usage
  - Top 5 processes by Memory usage

---

## 📁 Script Overview

- 💻 **CPU Usage** - Uses top, grep, sed, and awk to extract CPU idle percentage and calculate actual usage.

- 🧠 **Memory Usage** - Parses /proc/meminfo to get: MemTotal, MemAvailable.

- 💾 **Disk Usage** - Uses df -h / and df / to get:  Human-readable disk size and Used and available disk space in KB.

- 📌 **Top Processes** - Fetches the top 5 processes sorted by: CPU and Memory, through ps aux.

---

## 🚀 Usage

Make the script executable:

```
chmod +x server-stats.sh
```

Run the script:
```
./server-stats.sh
```

---

## 📦 Dependencies
This script uses standard Linux tools:
- top
- awk
- sed
- grep
- bc
- ps
- df

No external packages required.

---

## 🧪 Pro Tip

To monitor performance at intervals, set up a cron job like:

```
*/5* * * * /path/to/server-stats.sh >> /path/to/log.txt
```

## Feel free to customize or extend the script as needed!

Let me know if you want to include a table of contents, or sample screenshots!
