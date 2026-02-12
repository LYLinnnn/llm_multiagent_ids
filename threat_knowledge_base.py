"""
Threat Knowledge Base for RAG-powered LLM IDS
Focused on CIC-IDS2018 observable flow features.

Each entry:
- attack description
- indicators (what LLM should look for)
- false-positive guidance
- MITRE mapping

Keep chunks short for better retrieval.
"""

THREAT_DOCS = [

# =========================================================
# BENIGN BASELINES (VERY IMPORTANT to reduce false positives)
# =========================================================

"""
Benign Traffic Baseline:
Most network traffic is normal.

Common benign patterns:
- Short DNS queries on UDP port 53
- Stable RDP sessions on port 3389
- Regular HTTPS browsing (443)
- Moderate packet/byte counts
- Long steady flows without bursts

Rules:
If behavior looks normal and lacks strong attack evidence → classify BENIGN.
False positives are worse than false negatives.
""",


# =========================================================
# DoS
# =========================================================

"""
DoS (Denial of Service):

Description:
Single source overwhelms a target.

Indicators:
- Extremely high packets per second OR bytes per second
- Very long or continuous flow duration
- Same source IP repeatedly hitting one destination
- Resource exhaustion behavior

Distinguishing:
If traffic spike is small or brief → likely benign.

MITRE: T1499 Endpoint DoS
Label: DoS
""",


# =========================================================
# DDoS
# =========================================================

"""
DDoS (Distributed Denial of Service):

Description:
Many sources flood one victim simultaneously.

Indicators:
- Massive packets/sec or bytes/sec
- Many connections or flows
- Same destination IP or port
- SYN/UDP flood patterns
- Very short repeated flows

Distinguishing:
Normal high-traffic websites may also have high volume.
Need sustained abnormal spikes.

MITRE: T1498 Network DoS
Label: DDoS
""",


# =========================================================
# SSH BRUTE FORCE
# =========================================================

"""
SSH Brute Force:

Description:
Repeated login attempts to SSH service.

Indicators:
- Destination port 22
- Many short connections
- Repeated attempts from same source
- Small packet sizes
- Rapid reconnect behavior

Distinguishing:
One long SSH session is normal and benign.

MITRE: T1110 Brute Force
Label: SSH Brute Force
""",


# =========================================================
# FTP BRUTE FORCE
# =========================================================

"""
FTP Brute Force:

Description:
Repeated authentication attempts against FTP server.

Indicators:
- Destination port 21
- Many short flows
- Same source IP
- Rapid repeated connections

Distinguishing:
Normal FTP transfers are long and high byte count.

MITRE: T1110 Brute Force
Label: FTP Brute Force
""",


# =========================================================
# WEB ATTACKS – SQL INJECTION
# =========================================================

"""
Web Attack – SQL Injection:

Description:
Malicious SQL payloads sent to web servers.

Indicators:
- Destination ports 80 or 443
- Many short HTTP requests
- Abnormal request frequency
- Small packet bursts

Flow-based clue:
Repeated short connections with little data.

Distinguishing:
Normal browsing has mixed request sizes and timing.

MITRE: T1190 Exploit Public-Facing Application
Label: SQL Injection
""",


# =========================================================
# WEB ATTACKS – XSS
# =========================================================

"""
Web Attack – Cross Site Scripting (XSS):

Description:
Malicious scripts injected into web requests.

Indicators:
- Many small HTTP requests
- Rapid repeated sessions
- Short payload traffic
- Abnormal request bursts

Flow-based clue:
High number of tiny flows to same server.

Distinguishing:
Normal browsing has longer and varied flows.

MITRE: T1059 Script Execution
Label: XSS
""",


# =========================================================
# WEB ATTACKS – COMMAND INJECTION
# =========================================================

"""
Web Attack – Command Injection:

Description:
Attacker executes OS commands through web app.

Indicators:
- Repeated short HTTP sessions
- Unusual request bursts
- Followed by larger outbound traffic

Distinguishing:
Normal traffic rarely shows burst → response → burst pattern.

MITRE: T1203 Exploitation for Execution
Label: Command Injection
""",


# =========================================================
# INFILTRATION / LATERAL MOVEMENT
# =========================================================

"""
Infiltration / Lateral Movement:

Description:
Compromised internal host spreading inside network.

Indicators:
- Internal-to-internal IP communication
- Access to many hosts
- Multiple service ports
- Irregular movement patterns

Distinguishing:
Normal clients usually talk to few servers only.

MITRE: T1021 Remote Services
Label: Infiltration
""",


# =========================================================
# BOTNET
# =========================================================

"""
Botnet Activity:

Description:
Compromised host communicating with command-and-control.

Indicators:
- Periodic beaconing traffic
- Regular intervals (e.g., every 30s/60s)
- Small consistent packet sizes
- External suspicious IPs
- Long-running background connections

Distinguishing:
Normal traffic is irregular, not perfectly periodic.

MITRE: T1071 Application Layer Protocol
Label: Botnet
""",


# =========================================================
# PORT SCANNING / RECON
# =========================================================

"""
Port Scanning / Reconnaissance:

Description:
Attacker probes many ports to discover services.

Indicators:
- Many short connections
- Very low byte counts
- Many different destination ports
- Sequential or random probing
- Short flow duration

Distinguishing:
Normal clients repeatedly use only a few ports.

MITRE: T1046 Network Service Discovery
Label: Port scanning and reconnaissance
""",
]
