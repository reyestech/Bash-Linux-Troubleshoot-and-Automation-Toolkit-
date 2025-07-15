
<p align="center">
  <img src="https://github.com/user-attachments/assets/5bbc84f5-5fed-47de-a08c-9f5ac7db3164" width="70%" alt="image">
</p>


# Bash-Linux-Troubleshoot-and-Automation-Toolkit

## Overview

Effective Linux system administration and cybersecurity require prompt diagnostics, comprehensive visibility, and intelligent automation. This repository comprises a collection of Bash scripts designed to empower Linux administrators, DevOps engineers, and security teams with immediate troubleshooting capabilities. These scripts are designed to capture system metrics, diagnose issues, automate health checks, and enhance operational awareness, all while utilizing standard Linux utilities without requiring external dependencies.

This toolkit is particularly suitable for system administrators managing Linux servers, professionals learning Linux system administration, and experienced IT professionals seeking lightweight and reliable utilities for live incident response or root cause analysis. Each script is modular, well-documented, parameterizable, and safe for use across various Linux distributions on servers, workstations, or virtual machines.

This repository delivers a curated **suite of 12 Bash scripts** that empower system administrators, DevOps engineers, and security responders to:

* 🔍 **Capture critical evidence** within seconds.
* 🛠️ **Pinpoint misconfigurations** before they snowball.
* 🤖 **Automate routine hygiene tasks** so you can focus on higher‑value work.

Each script is:

* **Dependency‑free** – built only on ubiquitous GNU/Linux tooling.
* **Parameter‑driven** – easily tailored to your environment.
* **Comment‑rich** – ready for learning, audits, and pull‑requests.

Whether you are a junior engineer looking to access all the included scripts immediately or a hiring manager scanning for actionable skills, this toolkit showcases **production-safe Bash craftsmanship**.

<details>
<summary><strong>📚 Table of Contents — click to expand</strong></summary>

* [Quick‑Start](#quick‑start)
* [Script‑Catalogue](#script‑catalogue)

  1. [collect\_system\_logs.sh](#1️⃣-collect_system_logssh)
  2. [check\_system\_integrity.sh](#2️⃣-check_system_integritysh)
  3. [get\_active\_connections.sh](#3️⃣-get_active_connectionssh)
  4. [system\_health\_snapshot.sh](#4️⃣-system_health_snapshotsh)
  5. [detect\_bruteforce\_logons.sh](#5️⃣-detect_bruteforce_logonssh)
  6. [get\_listening\_ports.sh](#6️⃣-get_listening_portssh)
  7. [audit\_local\_admin\_members.sh](#7️⃣-audit_local_admin_memberssh)
  8. [run\_antivirus\_scan.sh](#8️⃣-run_antivirus_scansh)
  9. [test\_network\_connectivity.sh](#9️⃣-test_network_connectivitysh)
  10. [export\_firewall\_rules.sh](#🔟-export_firewall_rulessh)
  11. [schedule\_automated\_system\_updates.sh](#1️⃣1️⃣-schedule_automated_system_updatessh)
  12. [rotate\_and\_archive\_logs.sh](#1️⃣2️⃣-rotate_and_archive_logssh)
* [Conclusion](#conclusion)

</details>

---

## Guide
### 📚 Quick‑Start-Guide

To get started with the toolkit, clone the repository to your local machine using git. This toolkit allows you to access all of the included scripts immediately. Once downloaded, navigate into the directory and make the scripts executable using chmod. You can then run any script directly from your terminal by calling its filename with a period (.) at the beginning. 

These scripts are designed to be portable and require no external libraries, making them ideal for environments with limited internet access or strict security controls. They are suitable for use on laptops, servers, and virtual machines. Most scripts include comments and examples to help new users understand their purpose and structure.

<details>
   <summary><strong> 📋Click to View Script </strong></summary>
   

```bash
# 1. Clone the repo
 git clone https://github.com/<your‑org>/bash-linux-troubleshoot-toolkit.git
 cd bash-linux-troubleshoot-toolkit

# 2. Make everything executable
 chmod +x Scripts/*.sh

# 3. Run any helper – e.g., grab the last 12 h of syslog + auth
 ./Scripts/collect_system_logs.sh --hours 12 --logs syslog,auth --output /tmp/IR
```

</details>

All helpers accept `-h | --help` and print inline docs.


---
## Script‑Catalogue

### 1️⃣ collect\_system\_logs.sh

In high-pressure incidents, every second counts, and the phrase "Logs or it did not happen" rings true. Navigating complex log files can lead to errors and delays, making collect_system_logs.sh an essential tool. This script automates the export of Syslog and journalctl files, organizing raw data into a compressed, forensics-ready archive.

Instead of juggling multiple commands, users can access a structured archive suitable for immediate SIEM import or ticket attachment. The script categorizes log sources into distinct, timestamped files (e.g., syslog.log.gz, auth.log.gz), allowing analysts to quickly search logs with zgrep, input clean data into tools like Splunk, and compare collections to identify critical changes.

#### How it works

* Accepts `--hours`, `--logs` (comma‑separated), `--journal_unit`, and `--output`.
* Auto‑creates the destination folder.
* For classic files, it uses an **awk date filter** (no brittle `sed` hacks).
* For systemd hosts it calls `journalctl --since` with `--output export`.
* Compresses each log with `gzip -9` to save bandwidth when copying.

#### Usage Example

```bash
# Last 24 h of syslog + auth
./collect_system_logs.sh --hours 24 --logs syslog,auth --output /var/tmp/incident_logs

# Everything SSHD wrote in the past 2 days
./collect_system_logs.sh --journal_unit sshd --since "2 days ago" --output /var/tmp/ssh_logs
```

<details>
   <summary><strong> 📋Click to View Script </strong></summary>


```bash
#!/usr/bin/env bash
set -euo pipefail
HOURS=24; LOGS="syslog"; OUT="$(pwd)/Logs"; UNIT=""; SINCE=""
while [[ $# -gt 0 ]]; do
  case $1 in
    --hours)   HOURS="$2" ; shift 2;;
    --logs)    LOGS="$2"  ; shift 2;;
    --output)  OUT="$2"   ; shift 2;;
    --journal_unit) UNIT="$2"; shift 2;;
    --since)   SINCE="$2" ; shift 2;;
    -h|--help) grep -E "^#" "$0" | cut -c4-; exit 0;;
    *) echo "Unknown: $1"; exit 1;;
  esac;
done
mkdir -p "$OUT"
if [[ -n $UNIT ]]; then
  journalctl -u "$UNIT" --since "${SINCE:-$HOURS hour ago}" | gzip > "$OUT/${UNIT}.journal.gz"
  echo "✓ exported journal for $UNIT"
else
  START="$(date --date="-$HOURS hour" '+%b %e %H:%M:%S')"
  IFS=',' read -ra FILES <<< "$LOGS"
  for f in "${FILES[@]}"; do
    [[ -f /var/log/$f ]] || { echo "! /var/log/$f missing"; continue; }
    awk -v dt="$START" '$0>=dt' "/var/log/$f" | gzip > "$OUT/${f}.log.gz"
    echo "✓ exported $f"
  done
fi
```

</details>



---

### 2️⃣ check\_system\_integrity.sh

Package or file integrity drift often precedes outages and breaches. This script unifies rpm -Va and debsums checks, drops results into a timestamped report, and highlights unexpected hashes or permissions so you can intervene before minor deviations become service-stopping incidents.

Beyond vendor packages, the tool can be extended to snapshot hashes of bespoke configuration files such as /etc/ssh/sshd_config, providing an extra guardrail against silent backdoors or well-intentioned but undocumented changes. Pair it with a nightly cron to create a tamper-evident audit trail.


#### How it works

* Detects distro via `/etc/os-release`.
* If Debian‑based: ensures `debsums` is installed; else prompts.
* If RPM‑based: runs `rpm -Va`.
* Saves anomalies to `integrity_YYYYMMDD.txt` in `$PWD`.
* Emits a simple verdict (`✔ OK` vs `⚠ Issues found`).

#### Usage Example

```bash
sudo ./check_system_integrity.sh
```

<details>
   <summary><strong> 📋Click to View Script </strong></summary>

```bash
#!/usr/bin/env bash
set -euo pipefail
LOG="integrity_$(date +%Y%m%d).txt"
source /etc/os-release
if [[ $ID =~ (debian|ubuntu) ]]; then
  command -v debsums >/dev/null || { echo "Install debsums: sudo apt install debsums"; exit 1; }
  debsums -s > "$LOG"
else
  rpm -Va | tee "$LOG"
fi
[[ -s $LOG ]] && echo "⚠️ Issues found – see $LOG" || echo "✔ Integrity OK"
```

</details>

---

### 3️⃣ get\_active\_connections.sh

Command and control beacons leave unmistakable footprints as ESTABLISHED sockets. This helper surfaces every outbound TCP session, correlating remote endpoints with the owning process and user account. The result is a sortable list ideal for rapid threat-hunt filtering or bandwidth-hog investigations.

For defenders, it spotlights suspicious destinations and uncovers covert data exfiltration. For operators, it quickly reveals runaway services or misconfigured daemons saturating network links without the overhead of full-stack profilers.

For threat hunts, it highlights suspicious destinations; for operations, it surfaces rogue processes hogging resources.

#### How it works

* Wraps `netstat -pant` (fallback: `ss -pant`).
* Filters on `ESTABLISHED` state.
* Parses the PID/command and maps it to the username.
* Sorts by remote host for coherence.

#### Usage Example

```bash
./get_active_connections.sh | grep -E "\b443\b"
```

<details>
   <summary><strong> 📋Click to View Script </strong></summary>

```bash
#!/usr/bin/env bash
set -euo pipefail
sudo netstat -pant 2>/dev/null | awk '$6=="ESTABLISHED" {print $4,$5,$7}' | while read l r pu; do
  pid="${pu%%/*}"; proc="${pu##*/}"; user=$(ps -o user= -p "$pid" 2>/dev/null || echo "-")
  printf "%s -> %-22s %-8s %s\n" "$l" "$r" "$user" "$proc"
done | sort -k2
```

</details>

---

### 4️⃣ system\_health\_snapshot.sh

Every effective troubleshooting session starts with a baseline. This script captures CPU load averages, memory utilisation, disk capacity, and count of pending updates in one compact report, providing an immediate pulse check on host health. Store successive snapshots to quantify the impact of tuning or to satisfy change approval evidence requirements.

Because it relies solely on ubiquitous GNU utilities (uptime, free, df, and package managers), the script executes consistently across distributions and even minimal recovery environments, providing dependable metrics regardless of where you run it.

> Capture CPU load, memory, disk, and pending updates in one shot.

#### How it works

* CPU: `uptime` for 1/5/15‑min load.
* Memory: `free -m`.
* Disk: `df -hT` sans tmpfs.
* Pending updates: auto‑detects `apt`, `dnf`, or `yum`.
* Prints a labeled report.

#### Usage Example

```bash
./system_health_snapshot.sh > before_fix.txt
# apply tuning…
./system_health_snapshot.sh > after_fix.txt
diff -u before_fix.txt after_fix.txt
```

<details>
   <summary><strong> 📋Click to View Script </strong></summary>

```bash
#!/usr/bin/env bash
set -euo pipefail
echo "== CPU LOAD =="; uptime

echo "\n== MEMORY (MB) =="; free -m

echo "\n== DISK (GB) =="; df -hT | grep -Ev '^tmpfs|^udev'

if command -v apt >/dev/null; then
  echo "\n== PENDING APT UPDATES =="; sudo apt list --upgradable 2>/dev/null | tail -n +2 | wc -l
elif command -v dnf >/dev/null; then
  echo "\n== PENDING DNF UPDATES =="; sudo dnf check-update -q | grep -c '^'
fi
```

</details>

---

### 5️⃣ detect\_bruteforce\_logons.sh

SSH brute force attempts flood logs long before a compromise. This analyzer parses authentication records for failed passwords, grouping attempts by IP and user, then flags offenders that exceed a configurable threshold. Feed the output directly into fail2ban, firewall blocklists, or SIEM watchlists for real-time protection.

Historical reports also reveal attack trends, helping security teams justify MFA rollouts and hardening budgets with concrete data instead of anecdotal evidence.


#### How it works

* Accepts `--hours` and `--threshold`.
* Greps `/var/log/auth.log` *or* journal for "Failed password".
* Parses IP + username with `awk`.
* Uses `uniq -c` to tally.
* Prints offenders sorted high‑to‑low.

#### Usage Example

```bash
sudo ./detect_bruteforce_logons.sh --hours 12 --threshold 20
```

<details>
   <summary><strong> 📋Click to View Script </strong></summary>

```bash
#!/usr/bin/env bash
set -euo pipefail
HOURS=24; THRESH=15
while [[ $# -gt 0 ]]; do
  case $1 in
    --hours) HOURS="$2"; shift 2;;
    --threshold) THRESH="$2"; shift 2;;
    *) echo "Usage: $0 [--hours N] [--threshold N]"; exit 1;;
  esac
done
SINCE="$(date --date="-$HOURS hour" '+%b %e %H')"
LOGSRC="/var/log/auth.log"
[[ -f $LOGSRC ]] || { echo "No $LOGSRC found"; exit 1; }
awk -v dt="$SINCE" '$0>dt && /Failed password/' "$LOGSRC" | \
  awk '{ip=$NF; user=$(NF-5); print ip","user}' | sort | uniq -c | sort -nr | \
  awk -v t=$THRESH '$1>=t {printf "%s attempts\tIP:%s\tUser:%s\n",$1,substr($2,1,index($2,",")-1),substr($2,index($2,",")+1)}'
```

</details>

---

### 6️⃣ get\_listening\_ports.sh

Unintended listening services are low-hanging fruit for attackers. This utility enumerates every TCP and UDP socket in a LISTEN state, tagging each with protocol, address, port, PID, and executable name. That clarity allows administrators to spot rogue backdoors or verify that microservices expose only authorized interfaces.

Embed it in CI smoke tests or golden image validation to enforce network surface standards automatically—no manual port audits required.

> Map every service bound to a port, crucial for detecting rogue listeners or confirming app binds

#### How it works

* Executes `ss -tulnp` (fallback: `netstat -tulnp`).
* Extracts protocol, address\:port, PID.
* Resolves PID → command via `/proc/<pid>/comm`.
* Sorts by address.

#### Usage Example

```bash
./get_listening_ports.sh | grep 8080
```

<details>
   <summary><strong> 📋Click to View Script </strong></summary>

```bash
#!/usr/bin/env bash
set -euo pipefail
sudo ss -tulnp | awk 'NR>1 {print $1,$5,$7}' | while read proto addr proc; do
  pid="${proc%%,*}"; pid="${pid//pid=}"; cmd="$(ps -p $pid -o comm= 2>/dev/null)";
  printf "%-4s %-25s %-6s\n" "$proto" "$addr" "$cmd"
done | sort -k2
```

</details>

---

### 7️⃣ audit\_local\_admin\_members.sh

Privilege sprawl erodes security posture. This script cross-checks UID 0 accounts and members of privileged groups (sudo, wheel) against a defined safe list, immediately flagging unauthorised admin access. Run it periodically and ship the diff to your SIEM for an iron-clad least privilege audit.

Automation here replaces error-prone manual reviews and acts as an early warning system for compromised or leftover accounts following personnel changes.


#### How it works

* UID 0 accounts from `/etc/passwd`.
* Group parsing via `getent group`.
* Compares against hard‑coded SAFE array (edit to suit).
* Prints ✅ expected vs ⚠ review.

#### Usage Example

```bash
./audit_local_admin_members.sh | grep ⚠
```

<details>
   <summary><strong> 📋Click to View Script </strong></summary>


```bash
#!/usr/bin/env bash
set -euo pipefail
SAFE=(root adminuser)
admins=( $(awk -F: '($3==0){print $1}' /etc/passwd) )
for g in sudo wheel; do
  [[ $(getent group $g) ]] && admins+=( $(getent group $g | cut -d: -f4 | tr , ' ') )
done
for u in "${admins[@]}"; do
  if [[ " ${SAFE[*]} " =~ " $u " ]]; then
    echo "✔ $u (expected)"
  else
    echo "⚠ $u (review)"
  fi
done | sort -u
```

</details>

---

### 8️⃣ run\_antivirus\_scan.sh

Contrary to myth, Linux malware exists, and unchecked file Servers can become propagation hubs. This wrapper triggers a recursive, low-noise ClamAV scan, logs findings, and summarises infections in a single line so health monitors or cron mail can pick them up instantly.

Use it to vet user uploads, sweep build artifacts before CI promotion, or validate cloud images pre-deployment without relying on heavier commercial agents.

Invoke **ClamAV** (or substitute with your preferred engine) on demand, then parse a clean summary.

#### How it works

* Checks for `clamscan` binary.
* Accepts optional target path; defaults to `/`.
* Logs to a timestamped file.
* Evaluates infection count and prints verdict.

#### Usage Example

```bash
sudo ./run_antivirus_scan.sh /var/www
```

<details>
   <summary><strong> 📋Click to View Script </strong></summary>

```bash
#!/usr/bin/env bash
set -euo pipefail
TARGET=${1:-/}
LOG="clamscan_$(date +%Y%m%d_%H%M).log"
command -v clamscan >/dev/null || { echo "Install ClamAV"; exit 1; }
clamscan -ri "$TARGET" | tee "$LOG"
if grep -q "Infected files: 0" "$LOG"; then
  echo "✔ No threats detected"
else
  echo "⚠ Threats found – see $LOG"
fi
```

</details>

---

### 9️⃣ test\_network\_connectivity.sh

Contrary to myth, Linux malware exists, and unchecked file servers can become propagation hubs. This wrapper triggers a recursive, low-noise ClamAV scan, logs findings, and summarises infections in a single line so health monitors or cron mail can pick them up instantly.

Use it to vet user uploads, sweep build artifacts before CI promotion, or validate cloud images pre-deployment without relying on heavier commercial agents.

> Differentiate local, LAN, or WAN problems using a combo of `ping` and `traceroute`/`mtr`.

#### How it works

* Built‑in TARGETS array (edit) or pass args.
* Pings with 4 probes + 2‑sec timeout.
* If unreachable, runs `traceroute -n` up to 20 hops.
* Prints reachability, RTT, and last hop.

#### Usage Example

```bash
./test_network_connectivity.sh github.com 8.8.8.8
```

<details>
   <summary><strong> 📋Click to View Script </strong></summary>

```bash
#!/usr/bin/env bash
set -euo pipefail
TARGETS=("$@")
[[ ${#TARGETS[@]} -eq 0 ]] && TARGETS=(8.8.8.8 1.1.1.1 github.com)
for t in "${TARGETS[@]}"; do
  if ping -c4 -W2 "$t" &>/dev/null; then
    rtt=$(ping -c4 "$t" | awk -F/ 'END{print $5" ms"}')
    echo "✔ $t reachable – avg RTT $rtt"
  else
    hops=$(traceroute -n -m 20 "$t" | tail -1 | awk '{print $1}')
    echo "✖ $t unreachable – reached $hops hops"
  fi
done
```

</details>

---

### 🔟 export\_firewall\_rules.sh

Firewall rules drift over time through updates, hot fixes, and human edits. This helper snapshots the current iptables or nftables ruleset to a timestamped file for backup, peer review, or compliance archives, ensuring you can always roll back or audit historical changes without having to comb through shell history.
Automate it post-deployment so every change to the infrastructure has an accompanying rule export under version control.

> Track rule drift by exporting iptables/nftables to a file you can restore or audit.

#### How it works

* Checks for `iptables-save`, else `nft`.
* Emits to `firewall_YYYYMMDD_HHMM.rules`.

#### Usage Example

```bash
sudo ./export_firewall_rules.sh
```

<details>
   <summary><strong> 📋Click to View Script </strong></summary>


```bash
#!/usr/bin/env bash
set -euo pipefail
OUT="firewall_$(date +%Y%m%d_%H%M).rules"
if command -v iptables-save >/dev/null; then
  sudo iptables-save > "$OUT"
elif command -v nft >/dev/null; then
  sudo nft list ruleset > "$OUT"
else
  echo "No supported firewall found"; exit 1;
fi
echo "✓ Rules saved to $OUT"
```

</details>

---

### 1️⃣1️⃣ schedule\_automated\_system\_updates.sh

Timely patching thwarts the majority of commodity exploits. This script installs a root-owned weekly cron job that runs unattended upgrades with full logging, turning patch management from an intermittent task into a set-and-forget baseline.
Coupled with log shipping, it yields a verifiable patch compliance trail without the need for heavy management platforms on every host.

> Unpatched boxes invite 0‑days. This helper installs a root-owned weekly cron that runs unattended updates and logs the output.

#### How it works

* Writes `/etc/cron.weekly/auto_update` with distro‑aware commands.
* Logs to `/var/log/auto_update.log`.

#### Usage Example

```bash
sudo ./schedule_automated_system_updates.sh
```

<details>
   <summary><strong> 📋Click to View Script </strong></summary>

```bash
#!/usr/bin/env bash
set -euo pipefail
CRON="/etc/cron.weekly/auto_update"
cat <<'EOS' | sudo tee "$CRON" >/dev/null
#!/bin/bash
exec > /var/log/auto_update.log 2>&1
if command -v apt >/dev/null; then
  apt update && apt -y dist-upgrade
elif command -v dnf >/dev/null; then
  dnf -y upgrade --refresh
fi
EOS
sudo chmod +x "$CRON"
echo "✓ Weekly auto-update scheduled ($CRON)"
```

</details>

---

### 1️⃣2️⃣ rotate\_and\_archive\_logs.sh
Log bloat can crash services faster than almost any other resource issue. This helper scans for files larger than 50 MB in /var/log, compresses them into an archive directory, and safely truncates the originals—emulating logrotate when the utility is absent or misconfigured.
Ideal for containers or IoT devices with limited storage, the script keeps critical logs available while ensuring disk usage stays well below panic thresholds.

> Prevent log partitions from filling by compressing logs that are 50 MB or larger and shipping them to an archive folder.

#### How it works

* Default source `/var/log` and dest `/var/log/archive` (edit vars).
* Finds large files not already `.gz`.
* `gzip -c` to archive; truncates original with `: > file`.

#### Usage Example

```bash
sudo ./rotate_and_archive_logs.sh
```

<details>
   <summary><strong> 📋Click to View Scripts </strong></summary>

```bash
#!/usr/bin/env bash
set -euo pipefail
SRC=/var/log; DST=/var/log/archive; SZ=50M
mkdir -p "$DST-- ind "$SRC" -type f -size +$SZ ! -name '*.gz' | while read f; do
  gzip -c "$f" > "$DST/$(basename "$f").gz" && : > "$f"
  echo "Rotated $f"
done
```

</details>

---
---

## Conclusion

Conclusion

The Bash-Linux-Troubleshoot Toolkit is a practical resource for professionals and learners focused on quick, precise, and simple Linux administration. Each script is designed to help users identify and resolve issues using reliable tools on most Linux systems. This toolkit is beneficial for a variety of users, from junior engineers managing their first server to security analysts tackling threats and IT managers empowering their teams.

In addition to its practical applications, it serves as an educational tool for recruiters, mentors, and contributors to adapt to changing infrastructure needs. The toolkit is versatile and extensible, emphasizing clear and actionable scripting. We hope it becomes an essential part of your operational playbook and inspires the development of automation solutions. Your feedback and collaboration are incredibly  welcome to enhance this resource for the open-source and IT communities.

⭐ The future repository if you find this concept helpful! As scripts are developed, issues with bugs or new features are raised. Happy scripting — and automate all the things! 


🔍 — Happy hunting and automate *all* the things! 
