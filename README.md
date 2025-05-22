
# 🔧 Bash / Linux Troubleshoot Toolkit  

![image](https://github.com/user-attachments/assets/d3ddf94c-e630-4c1c-bab6-4cdf16f72470)

# Bash-Linux-Troubleshoot-and-Automation-Toolkit

## Overview
Effective Linux system administration and cybersecurity necessitate prompt diagnostics, comprehensive visibility, and intelligent automation. This repository consists of a collection of Bash scripts designed to empower Linux administrators, DevOps engineers, and security teams with immediate troubleshooting capabilities. These scripts are intended to capture system metrics, diagnose issues, automate health checks, and enhance operational awareness, all while employing standard Linux utilities without the need for external dependencies.

This toolkit is particularly suitable for system administrators managing Linux servers, professionals engaged in learning Linux system administration, and experienced IT professionals seeking lightweight and reliable utilities for live incident response or root cause analysis. Each script is modular, well-documented, parameterizable, and is safe for utilization across various Linux distributions on servers, workstations, or virtual machines.

---

## Guide

### 📚 Quick‑Start-Guide

Quick Start

To get started with the toolkit, simply clone the repository to your local machine using git. This allows you to immediately access all of the included scripts. Once downloaded, navigate into the directory and make the scripts executable using chmod. You can then run any script directly from your terminal by calling its filename with ./.

These scripts are designed to be portable and require no external libraries, making them ideal for environments with limited internet access or tight security controls. They are suitable for laptops, servers, and virtual machines. Most scripts include comments and examples to help new users understand their purpose and structure.


## Script-Catalogue

## Logs
### 1️⃣collect_system_logs.sh

In the investigation of incidents, comprehending the sequence of events is essential. This script automates the collection of pertinent system logs (e.g., syslog, auth.log, kern.log, or journalctl output) within a specified time frame. Rather than manually navigating through various log files or executing complex journalctl queries, this script produces organized output to facilitate analysis.

Operational Details:

**How it works**

> •	Accepts **`HoursBack`**, **`Logs`** (array of log names), and **`OutputDir`**.
> •	Creates the destination folder if it doesn’t exist.
> •	Uses **`Get‑WinEvent`** with a hashtable filter for efficiency (no slow `Where‑Object`).
> •	Selects the most actionable fields (timestamp, event ID, severity, message).
> •	Exports each log type to its own CSV for clean segregation.

**Usage Example**
./collect_system_logs.sh --hours 24 --logs "syslog,auth" --outputdir /var/tmp/incident_logs
# For journalctl specific query
./collect_system_logs.sh --journal_unit sshd --since "2 days ago" --outputdir /var/tmp/ssh_logs


```bash
Insert example here
```

### Code

```bash
Insert code here
```

---

## Integrity
### 2️⃣ check_system_integrity.sh

The integrity of system files and the presence of unexpected modifications may undermine stability and security. This script integrates various native Linux tools to verify the integrity of installed packages and optionally facilitates filesystem checks.

How it works (Conceptual)
> •	Builds a log directory to preserve historical runs.
> •	For RPM-based systems (e.g., CentOS, RHEL, Fedora): Executes rpm -Va to verify all installed packages.
> •	For Debian-based systems (e.g., Ubuntu, Debian): Executes debsums (if installed) or dpkg --verify (though dpkg --verify has limitations).
> •	Captures output in a timestamped log file.
> •	Optionally, it could provide information or reminders about running fsck on unmounted filesystems during maintenance windows.

**Usage Example**

```bash
Insert example here
```

### Code

```bash
Insert code here
```

---

## Connections
### 3️⃣ Get‑ActiveConnections

3️⃣ get_active_connections.sh

The presence of malware or unauthorized processes often corresponds with the establishment of network connections. This script displays all established TCP connections, identifying each one with the corresponding process name, PID, and the user who initiated it.

**How it works**

> •	Queries `Get‑NetTCPConnection` for **`State = Established`**.
> •	Resolves Process ID to friendly names using `Get‑Process`.
> •	Retrieves the owning username via CIM’s `Win32_Process.GetOwner()`.
> •	Outputs an alphabetised table ready for copy‑paste into a report or pasted into Grid View.

**Usage Example**

```bash
Insert example here
```


### Code

```bash
Insert code here
```

## System-Snapshot
## 4️⃣ get_system_health_snapshot.sh

Prior to troubleshooting, it is imperative to establish a baseline of system performance. This script captures real-time CPU load, memory usage, available disk space, and the number of pending system updates.
**How it works**

> • CPU Load: Uses uptime for load averages or mpstat / vmstat for more detailed CPU usage.
> •	Memory Usage: Parses output from free -m.
> •	Disk Space: Parses output from df -h.
> •	Pending Updates: * For Debian/Ubuntu: apt list --upgradable | wc -l (adjusting for header lines). * For RHEL/CentOS/Fedora (yum): yum check-update | grep -vc "^$" (approximate). * For RHEL/CentOS/Fedora (dnf): dnf check-update | wc -l (adjusting for header lines).
> •	Outputs everything as a formatted list or key-value pairs.


**How it works**

> •	CPU Load: Uses uptime for load averages or mpstat / vmstat for more detailed CPU usage.
> •	Memory Usage: Parses output from free -m.
> •	Disk Space: Parses output from df -h.
> •	Pending Updates: * For Debian/Ubuntu: apt list --upgradable | wc -l (adjusting for header lines). * For RHEL/CentOS/Fedora (yum): yum check-update | grep -vc "^$" (approximate). * For RHEL/CentOS/Fedora (dnf): dnf check-update | wc -l (adjusting for header lines).
> •	Outputs everything as a formatted list or key-value pairs.

**Usage Example**

```bash
Insert example here
```

*(Run it again after fixes and `Compare-Object` the two logs to quantify improvement.)*

---

### Code

```bash
Insert code here
```
---

## Detect
### 5️⃣ Detect‑BruteForceLogons

An increase in failed login attempts may indicate a brute-force attack. This script analyzes authentication logs (e.g., /var/log/auth.log or journalctl) for failed login attempts over a specified duration, aggregates them by source IP and account, and flags attempts that exceed a defined threshold.

**How it works**

> •	Accepts hours_back and threshold parameters.
> •	For journalctl: journalctl _SYSTEMD_UNIT=sshd.service --since "X hours ago" | grep "Failed password"
> •	For log files: grep "Failed password" /var/log/auth.log (and similar for other services like su, sudo).
> •	Uses awk, sed, grep to extract source IP addresses and usernames from log entries.
> •	Uses sort | uniq -c to count attempts per IP/username combination.
> •	Filters for combinations where count ≥ Threshold.
> •	Outputs a report, possibly to a CSV or formatted text.

**Usage Example**

```bash
Insert example here
```

### Code

```bash
Insert code here
```

---

## Listening-Ports
### 6️⃣ Get‑ListeningPorts

Understanding which services are listening for network connections is essential for ensuring security and conducting troubleshooting. This utility enumerates all TCP and UDP ports in a LISTEN state, correlating each with its respective process, PID, and executable path when feasible.

**How it works**

> •	Uses ss -tulnp or netstat -tulnp. The -l flag shows listening sockets, -t for TCP, -u for UDP, -n for numeric ports/hosts, -p to show PID/program name.
> • Parses the output to present: Protocol, Local Address:Port, PID/Program Name.
> •	The program name might include the path, or further lookup in /proc/[PID]/exe could be done.
> •	Outputs a sortable table.

**Usage Example**

```bash
Insert example here
```

### Code

```bash
Insert code here
```

---

## Audit
### 7️⃣ Audit‑LocalAdminMembers


Uncontrolled privileged access (root or sudo-capable users) poses a significant security risk. This script enumerates users with administrative privileges (UID 0 or members of sudo/wheel groups) and compares them against an expected list.

It parses the output to present the following information: Protocol, Local Address:Port, and PID/Program Name. The program name may include the path, or further lookup in `/proc/[PID]/exe` may be performed.

The output is presented in a sortable table.

### Usage Example
```
./get_listening_ports.sh | grep nginx
./get_listening_ports.sh --protocol tcp
```


**How it works**

> •	Checks /etc/passwd for users with UID 0: awk -F: '($3 == 0) { print $1 }' /etc/passwd.
> •	Checks members of privileged groups (e.g., sudo, wheel) by parsing /etc/group: grep -E '^sudo:|^wheel:' /etc/group | awk -F: '{print $4}' | tr ',' '\n'.
> •	Compares these lists against a predefined "safe list" of expected admin/sudo users.
> •	Flags any unexpected privileged accounts.

**Usage Example**

```bash
Insert example here
```

### Code

```bash
Insert code here
```

---

## Scan
### 8️⃣ Invoke‑WindowsDefenderScan

An on-demand antivirus scan may be necessary during an incident response or routine check. This utility facilitates initiating a scan using a standard Linux antivirus tool like ClamAV and summarizes findings.

**How it works**

> •	Checks if clamscan (or another specified AV tool) is installed and in PATH.
> •	Accepts parameters for scan type (e.g., --path /home or --full which might scan /).
> •	Executes clamscan -r [path] (recursive scan).
> •	Captures the output, specifically looking for infected files summaries.
> •	Prints a summary of threats found or a "no threats detected" message.


**Usage Example**

```bash
Insert example here
```

### Code

```bash
Insert code here
```

---
 
## Network
## 9️⃣ Test‑NetworkConnectivity

Quickly determining if network issues are local, with the gateway, DNS, or an external host, is crucial. This script tests reachability to specified targets using `ping` and either `traceroute` or `mtr`.

**How it works**

> •	Accepts a list of target hostnames or IP addresses.
> •	For each target: * Uses ping -c 4 <target> to check basic reachability and average RTT. * If ping fails or for more detail, uses traceroute -n <target> or mtr -n -r -c 1 <target> to show hops.
> •	Outputs a summary table: Target, Reachable (Yes/No), Avg RTT (ms), Hops (if traceroute run).


**Usage Example**

```bash
Insert example here
```

### Code

```bash
Insert code here
```
---

## FirewallRules
### 🔟 Export‑WindowsFirewallRules

Firewall configurations can change over time. This script exports the current firewall rules (e.g., from `iptables` or `nftables`) to a file for backup, auditing, or comparison.

**How it works**

>•	Detects which firewall system is likely in use (iptables or nftables).
> •	For iptables: Uses iptables-save > outputfile.txt.
> •	For nftables: Uses nft list ruleset > outputfile.txt. (For JSON: nft list ruleset -j > outputfile.json if supported and desired).
> •	Saves the output to a specified file.
> •	Provides a message indicating the export location.

**Usage Example**

```bash
Insert example here
```

### Code

```bash
Insert code here
```

---

## Conclusion

Conclusion
This toolkit provides a foundation for practical Bash scripting for Linux troubleshooting and automation. As these scripts are developed, they will be thoroughly documented. The goal is to empower administrators and security professionals to work more efficiently. Contributions, forks, and feature requests are welcome as the toolkit evolves. Security and system administration are collaborative efforts!
Next Steps: Star 

⭐ The future repository if you find this concept useful! As scripts are developed, issues with bugs or new features are raised. Happy scripting — and automate all the things! 


🔍 — Happy hunting and automate *all* the things! 
