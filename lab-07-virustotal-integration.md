LAB 7: VIRUSTOTAL THREAT INTELLIGENCE INTEGRATION

Date: 2026-08-27
Environment: Windows 11 Home (agent, Wazuh v4.14.6) → Ubuntu (Wazuh 
manager/indexer/dashboard)


SCENARIO
Configured Wazuh's built-in VirusTotal integration, which automatically 
checks file hashes detected by FIM against VirusTotal's database of 
antivirus engine results, flagging known-malicious files.


CONFIGURATION APPLIED

<integration>
  <name>virustotal</name>
  <api_key>[REDACTED - regenerated after this session]</api_key>
  <group>syscheck</group>
  <alert_format>json</alert_format>
</integration>

Added to /var/ossec/etc/ossec.conf, inside <ossec_config>. XML syntax 
was correct (no attribute/tag errors, unlike previous rule-writing 
issues in Lab 4).


ISSUE ENCOUNTERED

Command: sudo systemctl restart wazuh-manager

Result:
  Job for wazuh-manager.service failed because a timeout was exceeded.
  Active: failed (Result: timeout)
  Duration: 39min 9.718s (service ran for ~39 minutes before timing out)

Notable: this was NOT an XML syntax error. The config parsed and 
loaded sub-processes normally - analysisd, syscheckd, remoted, 
logcollector, monitord, and modulesd all started and were running 
under the service's cgroup. The failure was a STARTUP TIMEOUT after 
prolonged runtime, a different failure category than the XML errors 
seen in Lab 4.


DIAGNOSIS PERFORMED
- sudo systemctl status wazuh-manager.service confirmed the timeout 
  result and listed all running sub-processes
- Hypothesis formed: the VirusTotal integration attempts an outbound 
  HTTPS call to VirusTotal's API. If the Ubuntu VM's network 
  configuration (NAT/host-only adapter, firewall rules) does not 
  permit outbound internet access, this call could hang rather than 
  fail quickly, contributing to the prolonged startup and eventual 
  timeout.


RESOLUTION APPLIED
To restore lab stability, the VirusTotal <integration> block was 
commented out in ossec.conf, and the manager was restarted 
successfully, confirmed active (running) via systemctl status. This 
prioritized restoring a working detection environment over continuing 
to troubleshoot the integration in the same session.

Additionally, since the VirusTotal API key was exposed in 
troubleshooting screenshots during this session, it was treated as 
compromised and regenerated from the VirusTotal account dashboard as 
a precaution.


ANALYSIS
This exercise distinguished two different categories of Wazuh manager 
failure: (1) XML/config syntax errors, which fail FAST and are 
diagnosed via journalctl pointing to a specific line/attribute (seen 
in Lab 4), versus (2) integration/connectivity issues, which can fail 
SLOWLY via timeout, since the service must exhaust a wait period for 
an external dependency before giving up.


LESSONS LEARNED
- Not all Wazuh manager failures are configuration syntax errors - 
  external integrations (like VirusTotal) introduce a dependency on 
  network connectivity that syntax validation alone cannot catch
- A slow timeout failure (minutes) is a different diagnostic signal 
  than an immediate failure (seconds) - the former often points to a 
  hanging external call or resource issue, the latter to a parsing/
  config error
- Before adding an integration requiring outbound API calls, verifying 
  basic connectivity (ping/curl to the target service) from the host 
  first would catch this type of issue proactively, rather than 
  discovering it via a failed service restart
- Handling a live credential exposure by treating it as compromised 
  and regenerating it immediately, rather than assuming low real-world 
  risk, is standard practice regardless of how the exposure occurred
- Restoring a stable, working environment takes priority over 
  continuing to debug a non-critical feature in the same session - 
  rolling back a change is a valid and often correct operational 
  decision
