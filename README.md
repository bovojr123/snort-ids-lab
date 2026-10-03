# IDS Deployment & Packet Analysis with Snort and Wireshark

> A hands-on SOC lab in which a Snort IDS on Ubuntu detects reconnaissance and brute-force traffic launched from Kali Linux, with every alert validated at packet level in Wireshark.

**Author:** Emuze Osaigbovo Glory  
**Role focus:** SOC Analyst (L1)  
**Type:** Personal home-lab project

---

## Table of Contents

1. [Overview](#1-overview)
2. [Lab Architecture](#2-lab-architecture)
3. [Setup and Configuration](#3-setup-and-configuration)
4. [Detection Rules](#4-detection-rules)
5. [Methodology](#5-methodology)
6. [Attack Scenarios and Results](#6-attack-scenarios-and-results)
7. [Packet Analysis with Wireshark](#7-packet-analysis-with-wireshark)
8. [Results Summary and MITRE ATT&CK Mapping](#8-results-summary-and-mitre-attack-mapping)
9. [Key Findings](#9-key-findings)
10. [How a SOC Analyst Would Respond](#10-how-a-soc-analyst-would-respond)
11. [Limitations](#11-limitations)
12. [Future Work](#12-future-work)
13. [Lessons Learned](#13-lessons-learned)
14. [Repository Structure](#14-repository-structure)
15. [Disclaimer](#15-disclaimer)

---

## 1. Overview

### Objective

Deploy an open-source Intrusion Detection System (Snort) on a Linux host, write custom detection rules, attack the host from a separate machine, and confirm each detection by analysing the raw packets. The project practises the core L1 SOC workflow: detect → investigate → explain → recommend a response.

### Summary of Outcome

| Test | Tool | Detected by Snort? |
|---|---|---|
| ICMP ping | `ping` | Yes |
| TCP SYN port scan | `nmap -sS` | Yes |
| Service/OS fingerprint scan | `nmap -sV -A` | Yes (custom rule and a built-in rule) |
| SSH brute force | `hydra` | Alert fired, but the login attempts never reached the SSH service |
| Web vulnerability scan | `nikto` | Not tested. Nikto could not reach a web server |

Results are reported as they happened, including the two tests that did not complete. Section 9 explains why.

---

## 2. Lab Architecture

Two virtual machines run in Oracle VirtualBox. Each VM has two network adapters:

| Adapter | Type | Purpose |
|---|---|---|
| Adapter 1 | Host-Only | Private lab network. This is the traffic Snort monitors. |
| Adapter 2 | NAT | Internet access for installing packages only. |

| Machine | Role | Lab IP (Host-Only) | Interface | Key Tools |
|---|---|---|---|---|
| Ubuntu | Defender and target | `192.168.56.103` | `enp0s3` | Snort 2.9.x, Wireshark, tcpdump, Apache, OpenSSH |
| Kali Linux | Attacker | `192.168.56.104` | `eth0` | Nmap 7.95, Nikto 2.5.0, Hydra 9.6, ping |

```text
   +------------------+      Host-Only 192.168.56.0/24      +--------------------------+
   |   Kali Linux     |  ---------------------------------> |   Ubuntu                 |
   |   (Attacker)     |   ping | nmap | nikto | hydra      |   Snort (IDS)            |
   |   .104           |                                     |   tcpdump / Wireshark    |
   +------------------+                                     |   Apache, OpenSSH (.103) |
                                                            +--------------------------+
```

> **Note on interface names:** On this setup, the host-only adapter is `enp0s3` on Ubuntu and `eth0` on Kali. Interface names differ between machines, so the interface was identified by its `192.168.56.x` address rather than by name.

**Resource limits:** To keep the host responsive, each VM was trimmed (Ubuntu: 2 to 3 GB RAM, 2 CPUs; Kali: 2 GB RAM). Traffic was captured with `tcpdump` during attacks and opened in Wireshark afterwards, which avoids the lag of live capture during a scan.

---

## 3. Setup and Configuration

### 3.1 Verify connectivity

From Kali, confirm the attacker can reach the defender over the host-only network:

```bash
ping -c 3 192.168.56.103
```

Result: 3 packets sent, 3 received, 0% loss.

### 3.2 Prepare the target (Ubuntu)

```bash
sudo apt update
sudo apt install apache2 openssh-server -y
sudo systemctl enable --now apache2 ssh
sudo adduser labuser
```

### 3.3 Configure Snort

Set the protected network in `/etc/snort/snort.conf`:

```conf
ipvar HOME_NET 192.168.56.0/24
```

Make sure the custom rule file is included:

```conf
include $RULE_PATH/local.rules
```

### 3.4 Validate the configuration

```bash
sudo snort -T -c /etc/snort/snort.conf -i enp0s3
```

Snort reported **"Snort successfully validated the configuration!"**, so the rules and settings load correctly. The alert log was then cleared so each test starts clean:

```bash
sudo truncate -s 0 /var/log/snort/alert
```

<img width="1366" height="715" alt="ids 4" src="https://github.com/user-attachments/assets/a6bec4af-d208-4f21-a85b-28e353d3aa18" />

*Figure 1: Snort configuration validated successfully, then the alert log cleared before testing.*

### 3.5 Troubleshooting note

The first rule file failed validation with `Rule options must be enclosed in '(' and ')'`. The cause was a rule that had been broken across two lines when pasted. Snort requires each rule on a single line. The fix was to clear `local.rules` and re-add the rules one at a time, validating after each, so the faulty line could be isolated.

---

## 4. Detection Rules

Custom rules in `/etc/snort/rules/local.rules`:

```conf
alert icmp any any -> $HOME_NET any (msg:"LAB ICMP ping detected"; itype:8; sid:1000001; rev:1;)
alert tcp any any -> $HOME_NET any (msg:"LAB possible SYN port scan"; flags:S; detection_filter:track by_src, count 20, seconds 3; sid:1000002; rev:1;)
alert tcp any any -> $HOME_NET 22 (msg:"LAB SSH Brute force attempt"; flags:S; detection_filter:track by_src, count 5, seconds 60; sid:1000003; rev:1;)
alert tcp any any -> $HOME_NET 80 (msg:"LAB Nikto web scan detected"; content:"Nikto"; nocase; sid:1000004; rev:1;)
```

| SID | Rule | What it does in plain English |
|---|---|---|
| 1000001 | ICMP ping | Alerts on every ICMP echo request (type 8) sent to the protected network. |
| 1000002 | SYN port scan | Alerts when one source sends 20 or more SYN packets within 3 seconds, which is far faster than normal use. |
| 1000003 | SSH brute force | Alerts when one source opens 5 or more new connections to port 22 within 60 seconds. |
| 1000004 | Nikto web scan | Alerts when the text "Nikto" appears in traffic to port 80 (Nikto's default User-Agent). |

**How to read a Snort alert:**

```text
[**] [1:1000002:1] LAB possible SYN port scan [**] [Priority: 0] {TCP} 192.168.56.104:64595 -> 192.168.56.103:2041
```

`1:1000002:1` is generator:SID:revision, followed by the message, priority, protocol, and `source:port -> destination:port`.

---

## 5. Methodology

For each attack the same procedure was used:

1. **Ubuntu, terminal 1:** clear the alert log, then start Snort in console mode.

   ```bash
   sudo truncate -s 0 /var/log/snort/alert
   sudo snort -A console -q -c /etc/snort/snort.conf -i enp0s3 -l /var/log/snort
   ```

2. **Ubuntu, terminal 2:** start a packet capture on the same interface.

   ```bash
   sudo tcpdump -i enp0s3 -w ~/snort-lab/pcaps/attack1.pcap
   ```

3. **Kali:** run the attack against `192.168.56.103`.
4. **Ubuntu:** screenshot the Snort alerts, then stop `tcpdump` with `Ctrl+C`.
5. **Ubuntu:** open the `.pcap` in Wireshark and verify the packets behind each alert.

---

## 6. Attack Scenarios and Results

### 6.1 Scenario summary

| # | Attack | Kali command |
|---|---|---|
| 1 | ICMP ping | `ping -c 4 192.168.56.103` |
| 2 | SYN port scan | `nmap -sS 192.168.56.103` |
| 3 | Service/OS fingerprinting | `nmap -sV -A 192.168.56.103` |
| 4 | Web vulnerability scan | `nikto -h http://192.168.56.103` |
| 5 | SSH brute force | `hydra -l labuser -P pass.txt ssh://192.168.56.103 -t 4` |

### 6.2 ICMP Ping

Four echo requests were sent from Kali. All four were answered (0% packet loss).

<img width="1366" height="715" alt="ping attack" src="https://github.com/user-attachments/assets/331780a3-2494-4c03-a7ce-16eed455c6d8" />


*Figure 2: Ping from Kali to the Ubuntu defender. 4 packets sent, 4 received.*

Snort raised one alert per request, one second apart, matching the ping interval.

<img width="1366" height="739" alt="ping result" src="https://github.com/user-attachments/assets/32753ade-4586-4fd4-b1ff-7aac9b500e14" />


*Figure 3: Snort raises `LAB ICMP ping detected` (SID 1000001) four times, once per echo request.*

**Result: detected.**

### 6.3 SYN Port Scan and Service/OS Scan

**SYN scan (`nmap -sS`).** Nmap sends a SYN to each of the 1,000 most common ports without completing the handshake. Nmap reported all 1,000 ports as `filtered (no-response)`: the target did not reply, which is consistent with a host firewall dropping the packets. The scan took 34.94 seconds.

<img width="1167" height="717" alt="syn sttack" src="https://github.com/user-attachments/assets/de7d1478-e91e-4123-a099-0808c365a0c6" />


*Figure 4: Nmap SYN scan (`-sS`) from Kali. All 1,000 ports are reported as filtered.*

Despite the target not replying, Snort still saw every probe and raised `LAB possible SYN port scan` (SID 1000002) rapidly across many different destination ports.

<img width="1366" height="714" alt="syn result" src="https://github.com/user-attachments/assets/517d7b01-1915-4980-9f30-e63380c89167" />


*Figure 5: Snort alerts for the SYN scan. The destination port changes with every alert (2041, 35500, 5280, 83, 7920 and so on), which is the signature of a port scan.*

**Service and OS scan (`nmap -sV -A`).** This heavier scan attempts version detection, OS fingerprinting and traceroute. It completed in 44.72 seconds. Nmap could not identify the OS ("too many fingerprints match") because no open ports were available to probe.

<img width="1366" height="716" alt="syn sttack 2" src="https://github.com/user-attachments/assets/979d5688-4dae-40ed-bc5b-3ab40a574a84" />


*Figure 6: The attacker machine runs `nmap -sS` and `nmap -sV -A` against the Ubuntu host. Both scans show the host is up, but all ports are filtered and OS details are inconclusive.*

This scan triggered **three** kinds of alert:

- `LAB ICMP ping detected` (custom SID 1000001) from Nmap's host-discovery ping.
- `LAB possible SYN port scan` (custom SID 1000002).
- `SCAN nmap XMAS` (built-in rule `1:1228:7`, classified *Attempted Information Leak*, priority 2). Nmap's OS-fingerprinting probes include packets with unusual flag combinations (FIN, PSH, URG set together), which this default rule recognises.

<img width="1365" height="711" alt="syn result 2" src="https://github.com/user-attachments/assets/881ce3a8-6735-437c-9ee5-f1e15a527175" />


*Figure 7: Snort detects the Nmap scan using the custom ICMP and SYN rules and a built-in XMAS detection rule, confirming that the scan was recognised at the network level.*

**Result: both scans detected.**

### 6.4 Web Vulnerability Scan (Nikto)

Nikto was run against the Ubuntu web server. Its output ended with `+ 0 host(s) tested`: Nikto could not reach a web server on port 80, so no scan traffic was generated and the Nikto rule (SID 1000004) was **not exercised**.

<img width="1366" height="708" alt="brute attack 1" src="https://github.com/user-attachments/assets/6de37bcf-2169-4167-a7f2-a544063231c7" />


*Figure 8: Nikto reports `0 host(s) tested`, while Hydra reports a timeout connecting to SSH. This shows that the target services were not reachable in the lab environment.*

**Result: inconclusive.** This is a lab-environment issue, not a Snort result.

### 6.5 SSH Brute Force (Hydra)

A 21-entry wordlist was built and Hydra was pointed at the SSH service:

```bash
seq 1 20 | sed 's/^/pass/' > pass.txt; echo labpass123 >> pass.txt
hydra -l labuser -P pass.txt ssh://192.168.56.103 -t 4
```
<img width="1366" height="708" alt="brute attack 1" src="https://github.com/user-attachments/assets/55778e3a-0add-4026-a10b-5638887c249b" />

Hydra could not complete a connection (`ERROR: could not connect ... Timeout connecting`), so no passwords were actually tested. Snort nevertheless raised `LAB SSH Brute force attempt` (SID 1000003), because the rule counts repeated connection attempts to port 22 and does not require a successful login.

<img width="1365" height="706" alt="brute result 1" src="https://github.com/user-attachments/assets/1b45a749-e86f-4bea-bdde-e869c8cef77e" />


*Figure 9: Snort `LAB SSH Brute force attempt` alerts. The timestamps are about 2, 4 and 8 seconds apart.*

The alert timestamps (17:08:14, :16, :20, :28) double in spacing each time, from the **same source port (57462)**. This is the pattern of a TCP client retransmitting an unanswered SYN with exponential back-off, which independently confirms that the SSH port never replied.

**Result: rule fired, but the brute-force itself did not run.**

---

## 7. Packet Analysis with Wireshark

The capture `attack1.pcap` (4,420 packets) was opened in Wireshark and filtered to traffic between the two lab machines:

```text
ip.addr eq 192.168.56.104 and ip.addr eq 192.168.56.103
```

This leaves 4,151 packets (93.9% of the capture). The remaining packets are background traffic from other protocols.

<img width="1304" height="696" alt="wire 1" src="https://github.com/user-attachments/assets/6bcc0929-95b5-4380-880c-4df2993fc663" />


*Figure 10: Wireshark view of `attack1.pcap`. ICMP echo request/reply pairs (top) are followed by a burst of TCP SYN packets to many ports (bottom).*

### What the packets show

| Observation | Evidence | Meaning |
|---|---|---|
| ICMP echo request and reply pairs, seq 1 to 4 | Frames 3 to 10, 98 bytes each, TTL 64 | The 4 pings, each answered. TTL 64 indicates a Linux host. |
| Burst of SYN packets from one source port to many destination ports | Frames 31 onward: `64595 → 554, 139, 25, 23, 22, 80, 256, 53 [SYN]` | Port scan. A normal client contacts one or two ports, not hundreds. |
| Identical SYN packet shape | `Seq=0 Win=1024 Len=0 MSS=1460`, 60 bytes | The fixed window size of 1024 is a recognisable Nmap SYN-scan fingerprint. |
| Almost no replies to the SYNs | See Figure 11 | Ports are filtered: the target is dropping probes silently. |

<img width="1307" height="696" alt="conver 1" src="https://github.com/user-attachments/assets/c5cf20e6-8918-47df-8c5a-eb99abefa08e" />


*Figure 11: Wireshark Statistics → Conversations. One IPv4 conversation of 4,151 packets (254 kB), with 4,020 separate TCP conversations.*

### Reading the conversation statistics

- **4,151 packets** in the single IPv4 conversation, of which **4,143 travel from Kali to Ubuntu**. Only **8 packets go back**. Four of those are the ICMP echo replies, so the target answered almost none of the scan traffic.
- **4,020 TCP conversations** from a single pair of hosts. Each probe used a different destination port, so each one became its own conversation. A real session would produce one or two.

### Cross-checking Snort against Wireshark

| Snort alert | Packet evidence in Wireshark |
|---|---|
| `LAB ICMP ping detected` | ICMP echo requests, type 8 |
| `LAB possible SYN port scan` | Thousands of SYN-only packets (`tcp.flags.syn==1 && tcp.flags.ack==0`) to varying ports |
| `LAB SSH Brute force attempt` | Repeated SYNs to `tcp.port==22` |

---

## 8. Results Summary and MITRE ATT&CK Mapping

| Attack | Command | Snort alert | Wireshark evidence | Outcome | MITRE ATT&CK |
|---|---|---|---|---|---|
| Ping | `ping -c 4` | LAB ICMP ping detected | ICMP echo request/reply pairs | Detected | T1595 Active Scanning |
| SYN scan | `nmap -sS` | LAB possible SYN port scan | SYN burst, Win=1024, many ports, no replies | Detected | T1046 Network Service Discovery |
| Service/OS scan | `nmap -sV -A` | SYN scan, ICMP and `SCAN nmap XMAS` (1:1228:7) | Probes with unusual flag combinations | Detected | T1046, T1595 |
| Web scan | `nikto` | None (not exercised) | n/a | Inconclusive: 0 hosts tested | T1595.002 Vulnerability Scanning |
| SSH brute force | `hydra` | LAB SSH Brute force attempt | Repeated SYN retransmissions to port 22 | Rule fired; login attempts did not run | T1110.001 Password Guessing |

---

## 9. Key Findings

1. **An IDS sees traffic that the host firewall blocks.** Nmap reported every port as filtered, yet Snort alerted on all of it. Snort reads packets from the network interface, which happens before the host firewall decides to drop them. A blocked scan is therefore still visible to a defender, which is valuable intelligence.
2. **Threshold rules separate scans from normal traffic.** The `detection_filter` option (count within a time window) lets a rule ignore a single connection but fire on a burst. This is what distinguishes the SYN-scan and brute-force rules from simply alerting on every SYN.
3. **Default rules complement custom ones.** A single `nmap -sV -A` scan triggered both my custom rules and Snort's built-in `SCAN nmap XMAS` rule, because OS-fingerprinting probes use unusual TCP flags. Layering custom and community rules improves coverage.
4. **Alerts need packet-level confirmation.** The SSH brute-force alert looked like a successful detection of an attack. Only the Hydra error and the doubling timestamps showed it was triggered by unanswered connection attempts. Checking the evidence behind an alert avoids misreporting an incident.
5. **Absence of replies is itself evidence.** Only 8 of 4,151 packets flowed back to the attacker, which confirms the target was dropping probes without relying on Nmap's summary alone.

---

## 10. How a SOC Analyst Would Respond

| Alert | Triage | Recommended action |
|---|---|---|
| ICMP ping | Low severity. Common and often legitimate (monitoring tools, admins). | Log. Escalate only if it comes from an unexpected source or is part of a sweep across many hosts. |
| SYN port scan | Medium. Reconnaissance that often precedes an attack. | Identify the source IP, check whether it is known or authorised, block it at the firewall, and watch for follow-up activity. |
| Nmap OS scan (XMAS) | Medium to high. Deliberate fingerprinting. | Treat as targeted reconnaissance. Block the source and review exposed services on the target. |
| SSH brute force | High if the target is reachable. | Block the source, review `auth.log` for successful logins, enforce key-based authentication and lockout (for example fail2ban), and reset any credential that may be exposed. |

---

## 11. Limitations

- **Two tests were incomplete.** Nikto reached no web server and Hydra could not connect to SSH, so the Nikto rule was never exercised and no real password guesses were made.
- **Detection only.** Snort ran in IDS mode: it alerts but does not block.
- **Encrypted traffic.** SSH payloads cannot be inspected, so detection relies on connection behaviour rather than content.
- **Simple, un-tuned rules.** The ICMP rule fires on every ping, including legitimate ones. No false-positive tuning was performed in this iteration.
- **Clock mismatch.** The two VMs had different system times (Ubuntu showed 2 October, Kali 3 October), so timestamps cannot be matched directly across machines. In a real investigation, synchronised time (NTP) is essential for correlating events.
- **Single, isolated lab.** Real networks have far more background noise than a two-host lab.

---

## 12. Future Work

- **Fix the target and re-run the two incomplete tests.** Check the firewall and services on Ubuntu (`sudo ufw status`, `sudo systemctl status apache2 ssh`, `ss -tlnp`), allow ports 22 and 80 from the lab network, then repeat Nikto and Hydra to exercise the web-scan and brute-force rules fully.
- **Tune the rules.** Document a false positive (for example, an administrator's ping), adjust the rule or thresholds, and record a before/after comparison.
- **Synchronise clocks** between the VMs.
- **Try Snort in IPS (inline) mode** to block as well as alert.
- **Forward alerts to a SIEM** such as Splunk or Wazuh for central monitoring and dashboards.
- **Migrate to Snort 3** and compare rule syntax and performance.

---

## 13. Lessons Learned

- Snort rules must be a single line and are strict about syntax. Adding rules one at a time and validating with `snort -T` makes errors easy to find.
- Network interface names differ between systems, so confirm the right one by IP address before pointing Snort at it.
- Two network adapters (Host-Only and NAT) solve the "no internet on an isolated lab" problem without exposing the lab network.
- A detection is only meaningful once the underlying packets confirm it.
- Reporting failed or inconclusive tests honestly is part of good security documentation.

---

## 14. Repository Structure

```text
snort-ids-lab/
├── README.md
├── rules/
│   └── local.rules
├── pcaps/
│   └── attack1.pcap
├── logs/
│   └── alert_snapshot.txt
├── screenshots/
│   ├── 01-snort-config-validated.png
│   ├── 02-ping-attack-kali.png
│   ├── 03-snort-icmp-alerts.png
│   ├── 04-nmap-syn-scan-kali.png
│   ├── 05-snort-syn-scan-alerts.png
│   ├── 06-nmap-service-os-scan-kali.png
│   ├── 07-snort-os-scan-alerts.png
│   ├── 08-nikto-hydra-kali.png
│   ├── 09-snort-ssh-alerts.png
│   ├── 10-wireshark-packet-list.png
│   └── 11-wireshark-conversations.png
├── LICENSE
└── docs/
    └── notes.md
```

---

## 15. Disclaimer

All testing was performed in an isolated virtual lab on systems I own. The attacks were launched only against my own virtual machine. Do not run these tools against networks or systems without explicit written permission.

---

## License

This project is provided for educational and lab-use purposes only.
