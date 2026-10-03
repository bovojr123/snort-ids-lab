# IDS Deployment & Packet Analysis with Snort and Wireshark

A hands-on SOC lab where Snort is deployed on Ubuntu to detect reconnaissance and brute-force activity initiated from Kali Linux, with each alert validated at packet level in Wireshark.

Author: Emuze Osaigbovo Glory  
Role focus: SOC Analyst (L1)  
Type: Personal home-lab project

## Overview

This project demonstrates a realistic intrusion detection workflow in a controlled lab environment. The goal is to:

- deploy Snort as an IDS on a Linux host
- create custom detection rules
- launch common offensive techniques from a separate attacker VM
- confirm each alert with packet-level evidence in Wireshark
- explain how a SOC analyst would respond to the detections

### Lab objective

The environment simulates a defender-attacker setup in which an Ubuntu host is monitored by Snort while a Kali Linux machine performs scanning and attack behaviour.

### Result summary

| Test | Tool | Detected by Snort? |
| --- | --- | --- |
| ICMP ping | `ping` | Yes |
| TCP SYN port scan | `nmap -sS` | Yes |
| Service/OS fingerprint scan | `nmap -sV -A` | Yes (custom rule + built-in rule) |
| SSH brute force | `hydra` | Alert fired, but login attempts did not reach the SSH service |
| Web vulnerability scan | `nikto` | Not exercised in this lab |

> Note: Some tests were inconclusive due to service availability and firewall conditions in the isolated lab. These are documented in the findings section below.

---

## Lab architecture

Two virtual machines were used inside Oracle VirtualBox. Each VM had two interfaces:

| Adapter | Type | Purpose |
| --- | --- | --- |
| Adapter 1 | Host-only | Private lab network used for IDS monitoring |
| Adapter 2 | NAT | Internet access for software installation only |

| Machine | Role | Lab IP (Host-only) | Interface | Key tools |
| --- | --- | --- | --- | --- |
| Ubuntu | Defender / target | `192.168.56.103` | `enp0s3` | Snort, Wireshark, tcpdump, Apache, OpenSSH |
| Kali Linux | Attacker | `192.168.56.104` | `eth0` | Nmap, Nikto, Hydra, ping |

```text
   +-------------------+      Host-only network      +----------------------+
   | Kali Linux        | -------------------------> | Ubuntu               |
   | Attacker          | ping | nmap | nikto | hydra | Snort IDS            |
   | 192.168.56.104    |                            | tcpdump / Wireshark  |
   +-------------------+                            | Apache + OpenSSH     |
                                                    +----------------------+
```

> The host-only network is the traffic Snort monitors. Interface names differ between distributions, so the environment was identified by IP range rather than interface name alone.

---

## Setup and configuration

### 1. Verify connectivity

From Kali:

```bash
ping -c 3 192.168.56.103
```

Expected outcome: 3 packets sent, 3 received, 0% loss.

### 2. Prepare the target (Ubuntu)

```bash
sudo apt update
sudo apt install apache2 openssh-server -y
sudo systemctl enable --now apache2 ssh
sudo adduser labuser
```

A weak, lab-only user account was created to support the brute-force test.

### 3. Configure Snort

Set the protected network in `/etc/snort/snort.conf`:

```conf
ipvar HOME_NET 192.168.56.0/24
```

Ensure the custom rule file is included:

```conf
include $RULE_PATH/local.rules
```

### 4. Validate the Snort configuration

```bash
sudo snort -T -c /etc/snort/snort.conf -i enp0s3
```

This completed successfully with the message:

```text
Snort successfully validated the configuration!
```

The alert log was cleared before each test to keep the evidence clean.

```bash
sudo truncate -s 0 /var/log/snort/alert
```

### 5. Troubleshooting note

The first custom rules file failed validation due to a syntax issue:

```text
Rule options must be enclosed in '(' and ')'
```

The cause was a custom rule broken across multiple lines while being pasted into the file. Snort requires each rule to be on a single line. The fix was to remove the broken rule and re-add it cleanly, then validate after each change.

---

## Detection rules

Custom rules were added to `/etc/snort/rules/local.rules`:

```conf
alert icmp any any -> $HOME_NET any (msg:"LAB ICMP ping detected"; itype:8; sid:1000001; rev:1;)
alert tcp any any -> $HOME_NET any (msg:"LAB possible SYN port scan"; flags:S; detection_filter:track by_src, count 20, seconds 3; sid:1000002; rev:1;)
alert tcp any any -> $HOME_NET 22 (msg:"LAB SSH Brute force attempt"; flags:S; detection_filter:track by_src, count 5, seconds 60; sid:1000003; rev:1;)
alert tcp any any -> $HOME_NET 80 (msg:"LAB Nikto web scan detected"; content:"Nikto"; nocase; sid:1000004; rev:1;)
```

### Rule interpretation

| SID | Rule | Meaning |
| --- | --- | --- |
| 1000001 | ICMP ping | Triggers on echo requests to the protected network |
| 1000002 | SYN port scan | Triggers when one source sends many SYNs in a short time |
| 1000003 | SSH brute force | Triggers when repeated connection attempts reach port 22 |
| 1000004 | Nikto web scan | Looks for the string `Nikto` in HTTP traffic to port 80 |

### Example alert

```text
[**] [1:1000002:1] LAB possible SYN port scan [**] [Priority: 0] {TCP} 192.168.56.104:64595 -> 192.168.56.103:2041
```

This is the standard Snort format of `generator:SID:revision` followed by the alert message, priority, protocol, and the source/destination tuple.

---

## Methodology

For each attack, the same investigation workflow was followed:

1. Ubuntu terminal 1: clear the alert log and start Snort in console mode.

```bash
sudo truncate -s 0 /var/log/snort/alert
sudo snort -A console -q -c /etc/snort/snort.conf -i enp0s3 -l /var/log/snort
```

2. Ubuntu terminal 2: start packet capture on the same interface.

```bash
sudo tcpdump -i enp0s3 -w ~/snort-lab/pcaps/attack1.pcap
```

3. Kali: run the attack against `192.168.56.103`.
4. Ubuntu: capture the Snort alert output and stop `tcpdump` with `Ctrl+C`.
5. Ubuntu: open the PCAP in Wireshark and confirm the packet-level evidence behind each alert.

---

## Attack scenarios and results

### 1. ICMP ping

From Kali:

```bash
ping -c 4 192.168.56.103
```

Four echo requests were sent and all four were answered. Snort raised one alert for each ping.

### 2. SYN port scan

From Kali:

```bash
nmap -sS 192.168.56.103
```

Nmap reported the target ports as filtered. Despite the lack of replies, Snort still detected the burst of SYNs. This is because Snort sees packets before the target chooses whether to accept or drop them.

### 3. Service and OS detection

From Kali:

```bash
nmap -sV -A 192.168.56.103
```

This triggered:

- the custom ICMP detection rule
- the custom SYN scan rule
- the built-in Snort rule `SCAN nmap XMAS` for unusual TCP flags

### 4. Web vulnerability scan (Nikto)

From Kali:

```bash
nikto -h http://192.168.56.103
```

Nikto returned `0 host(s) tested`, meaning no web server was reachable on port 80. The custom Nikto rule was therefore not exercised in this session.

### 5. SSH brute force (Hydra)

```bash
seq 1 20 | sed 's/^/pass/' > pass.txt
echo labpass123 >> pass.txt
hydra -l labuser -P pass.txt ssh://192.168.56.103 -t 4
```

Hydra failed to connect because the SSH service did not respond. The rule still fired because repeated unanswered connection attempts were seen, and the rule counts traffic patterns rather than successful logins.

---

## Packet analysis with Wireshark

The packet capture `attack1.pcap` was opened in Wireshark and filtered using:

```text
ip.addr eq 192.168.56.104 and ip.addr eq 192.168.56.103
```

This filtered the flow between the attacker and defender and allowed packet-level validation of the Snort alerts.

### Useful observations

| Observation | Meaning |
| --- | --- |
| ICMP echo requests and replies | Confirms ping traffic |
| High volume of SYNs to many destination ports | Port scanning behaviour |
| Repeated SYNs to port 22 | Possible brute-force activity |
| Very few replies to scan traffic | Target is filtering or dropping the probes |

### Key Wireshark findings

- Many TCP SYN packets were sent to different destination ports from the same source.
- Packet signatures show repeated connection attempts and scan behaviour.
- Connection attempts to port 22 were observed even when Hydra could not complete an SSH handshake.

This confirms that Snort alerts were not random—they were matched to genuine packet patterns visible in the capture.

---

## Results summary and MITRE ATT&CK mapping

| Attack | Command | Snort alert | Packet evidence | Outcome | MITRE ATT&CK |
| --- | --- | --- | --- | --- | --- |
| Ping | `ping -c 4` | `LAB ICMP ping detected` | ICMP echo requests and replies | Detected | T1595 Active Scanning |
| SYN scan | `nmap -sS` | `LAB possible SYN port scan` | Burst of SYNs to many ports | Detected | T1046 Network Service Discovery |
| Service / OS scan | `nmap -sV -A` | custom + built-in XMAS alert | Unusual flag combinations | Detected | T1595, T1046 |
| Web scan | `nikto` | none | not exercised | Inconclusive | T1595.002 |
| SSH brute force | `hydra` | `LAB SSH Brute force attempt` | Repeated SYNs to port 22 | Rule fired, attack did not complete | T1110.001 |

---

## Key findings

1. An IDS can observe traffic that is silently dropped by the host firewall.
2. Threshold-based rules are effective for isolating scan and brute-force behaviour from normal traffic.
3. Snort default rules complement custom ones and can catch additional reconnaissance techniques.
4. Alert validation with Wireshark is essential; it prevents false confidence in detections.
5. Inconclusive results are still useful—they show what was attempted and what the environment allowed.

---

## How a SOC analyst would respond

| Alert | Assessment | Response |
| --- | --- | --- |
| ICMP ping | Low severity | Log and review whether it is expected traffic |
| SYN port scan | Medium severity | Investigate source IP, block if necessary, review for follow-up behaviour |
| Nmap OS scan | Medium to high severity | Treat as active reconnaissance, isolate source, examine exposed services |
| SSH brute force | High severity if service is reachable | Block source, review authentication logs, enforce stronger access controls |

---

## Limitations

- Nikto was not able to reach a web service, so the web-scan rule was never exercised.
- Hydra did not reach the SSH service, so no real login attempt occurred.
- Snort was deployed in IDS mode only; it did not actively block traffic.
- System clocks in the lab were not synchronised, which can affect precise correlation.
- This lab is intentionally small and isolated; it does not reflect full enterprise network noise.

---

## Future work

- Re-run the failed tests after correcting service and firewall settings.
- Tune detection thresholds to reduce false positives.
- Synchronise clocks across all lab VMs.
- Explore Snort in IPS mode for blocking instead of alerting only.
- Forward alerts to a SIEM like Splunk or Wazuh.
- Migrate to Snort 3 for modern rule syntax and performance enhancements.

---

## Lessons learned

- Snort rules must be written carefully; syntax errors stop rule loading.
- Interface names differ across Linux distributions, so verifying the right interface by IP is important.
- Host-only networking is ideal for isolated lab testing.
- Packet analysis is the best way to validate whether an alert is real and actionable.
- Reporting both successful and inconclusive test results is part of professional security documentation.

---

## Repository structure

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

> You can add your screenshots and other evidence under `screenshots/`. I can help format them into the Markdown once you upload the images.

---

## Disclaimer

This project was conducted entirely in an isolated lab environment using systems owned by the author. The attacks were launched only against the lab machines and not against any external or unauthorised systems. Do not run intrusive scanning or brute-force tools against networks or hosts without explicit permission.

---

## License

This project is provided for educational and lab-use purposes only.

If you want, I can also help you:

- add your screenshots into this README as image blocks
- create a more polished GitHub project landing page
- write a short project summary for the repository description
- prepare a clean `rules/local.rules` file for direct upload
