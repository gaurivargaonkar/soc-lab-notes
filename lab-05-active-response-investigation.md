LAB 5: ACTIVE RESPONSE INVESTIGATION (WAZUH)

Date: 2026-08-25
Environment: Windows 11 Home (agent, Wazuh v4.14.6) → Ubuntu (Wazuh 
manager/indexer/dashboard)


SCENARIO
Investigated Wazuh's Active Response feature - its configuration, 
available built-in scripts, and internal logic - to understand how 
automated remediation works.


WHAT IS ACTIVE RESPONSE
Active Response is Wazuh's feature that allows automatic action to be 
taken the moment a rule fires, instead of only generating an alert for 
manual review. Example actions: blocking an IP, disabling a user 
account, killing a malicious process, or sending a notification. It is 
disabled by default in a fresh Wazuh install, since automated action 
based on a false positive can cause real business disruption.


INVESTIGATION STEPS AND FINDINGS

1. Checked existing Active Response configuration:
   Command: sudo grep -A 10 "active-response" /var/ossec/etc/ossec.conf
   Finding: Active Response was present only as a commented-out 
   placeholder example - confirmed it is disabled by default.

   Bonus finding (same file): discovered two additional active log 
   sources already configured:
   - Command-based monitoring: df -P run every 360 seconds (disk 
     space monitoring)
   - Syslog monitoring of /var/log/dpkg.log (tracks package 
     install/removal activity on the Ubuntu manager)

2. Listed available built-in Active Response scripts:
   Command: ls /var/ossec/active-response/bin/
   Finding: A library of pre-built response scripts exists, mostly 
   Linux/Unix-oriented:
   - firewall-drop / firewalld-drop (iptables/firewalld IP blocking)
   - host-deny (TCP wrapper-based blocking)
   - ipfw / npf / pf (BSD/macOS firewall blocking)
   - disable-account (disables a Linux user account)
   - restart-wazuh (recovery action)
   - route-null (null-routes an IP)
   - wazuh-slack (Slack notification integration)
   - kaspersky / kaspersky.py (AV integration)
   No Windows-native response scripts were found in this location - 
   Windows-specific active response scripts are packaged separately 
   inside the Windows agent installation itself, not on the manager.

3. Attempted to read a script's logic directly:
   Command: cat /var/ossec/active-response/bin/disable-account
   Finding: Output was unreadable garbled binary data - modern Wazuh 
   compiles active-response scripts into binaries rather than shipping 
   them as plain-text shell scripts (as older versions did).

4. Correctly identified the file type before further inspection:
   Command: file /var/ossec/active-response/bin/disable-account
   Finding: Confirmed as an ELF 64-bit LSB executable, dynamically 
   linked - a genuine compiled Linux program, not corrupted data.

5. Safely extracted readable content from the binary:
   Command: strings /var/ossec/active-response/bin/disable-account | head -30
   Finding: Revealed the script expects alert data as JSON, containing 
   fields such as srcip and dstuser. Also revealed internal safety 
   logic - a lock-file mechanism (check_keys, Unable to remove lock 
   folder, Killed process %d holding lock) to prevent multiple 
   active-response actions from running simultaneously and conflicting.


KEY FIELD UNDERSTANDING - dstuser
"dstuser" (destination user) is the standardized field Wazuh uses to 
identify which user account was the target of a logged event. When an 
Active Response script like disable-account is triggered, Wazuh passes 
this field's value to the script, which then attempts to disable a 
matching account on the system where the script runs.


RISK ASSESSMENT
Reasoning: disable-account operates on Linux accounts on the manager 
machine. A live test scenario originating on the Windows endpoint 
(e.g., a brute-force trigger) would pass a Windows username through 
the dstuser field. Risk exists only if that Windows username happens 
to match an existing Linux account on the Ubuntu manager - in which 
case a live test could disable manager login access, taking down the 
entire lab (manager, indexer, and dashboard run on the same machine).

Mitigation identified: take a full VM snapshot of the Ubuntu manager 
before any live test, and cross-check existing Linux accounts first 
using: cat /etc/passwd | grep -v nologin | grep -v false


PLANNED CONFIGURATION (documented and syntax-verified, not executed live)

<command>
  <name>disable-account</name>
  <executable>disable-account</executable>
  <timeout_allowed>yes</timeout_allowed>
</command>

<active-response>
  <disabled>no</disabled>
  <command>disable-account</command>
  <location>local</location>
  <rules_id>60122</rules_id>
  <timeout>600</timeout>
</active-response>

This configuration links Wazuh's brute-force correlation rule (60122) 
to the disable-account response, with a 600-second (10 minute) timeout 
before automatic re-enablement.


ANALYSIS
This investigation demonstrated understanding of Wazuh's automation 
capability beyond basic alerting, and the operational judgment to 
assess risk before executing an action that could affect system 
availability - weighing detection speed/automation benefits against 
disruption risk, a core SOC analyst consideration.


LESSONS LEARNED
- Active response scripts in current Wazuh versions are compiled 
  binaries, not plain shell scripts - file should be used to check 
  file type before attempting to read them, and strings is the safe 
  way to extract readable content from a binary
- Active Response is disabled by default specifically because 
  automated remediation carries real operational risk - production 
  deployment requires careful selection of which rules are reliable 
  enough to trust with automatic action
- Response scripts are OS/platform-specific (Linux scripts on the 
  manager vs separate Windows-native scripts on Windows agents)
- Assessing blast radius and having a rollback plan (VM snapshot) 
  before executing a potentially disruptive action is a practical, 
  low-cost risk mitigation step worth applying before any live 
  automated response test
