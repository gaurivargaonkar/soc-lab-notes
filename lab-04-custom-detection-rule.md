LAB 4: CUSTOM DETECTION RULE (FILE INTEGRITY - TESTFOLDER)

Date: 2026-08-25
Environment: Windows 11 Home (agent, Wazuh v4.14.6) → Ubuntu (Wazuh 
manager/indexer/dashboard)


SCENARIO
Wrote and deployed a custom Wazuh detection rule to generate a 
targeted, high-signal alert specifically for file changes within 
C:\Users\Public\TestFolder, rather than relying on Wazuh's generic 
FIM alerts covering all monitored paths.


RULE DEVELOPMENT

Initial rule:
<rule id="100010" level="7">
  <if_sid>554</if_sid>
  <match>TestFolder</match>
  <description>Custom Alert: File change detected in critical TestFolder</description>
  <group>local,syscheck,</group>
</rule>

Issue found: Rule only fired for "added" events, since <if_sid>554</if_sid> 
scoped it to a single parent rule specific to file-creation events only. 
"Modified" events (parent rule 550) were not captured, falling back to 
Wazuh's default generic description instead of the custom one.

Fixed rule:
<rule id="100010" level="7">
  <if_group>syscheck</if_group>
  <match>TestFolder</match>
  <description>Custom Alert: File change detected in critical TestFolder</description>
  <group>local,syscheck,</group>
</rule>

Fix: Replaced <if_sid> (single parent rule) with <if_group>syscheck</if_group>, 
which matches any rule within the syscheck group - covering added, 
modified, and deleted events under one custom alert.


DETECTION - CONFIRMED WORKING

Event 1 - File Added:
- syscheck.event: added
- rule.id: 100010
- rule.description: Custom Alert: File change detected in critical TestFolder
- rule.level: 7

Event 2 - File Modified:
- syscheck.event: modified
- rule.id: 100010
- rule.description: Custom Alert: File change detected in critical TestFolder
- rule.level: 7


TROUBLESHOOTING NOTES (two separate issues resolved)

1. Rule scoping error (if_sid vs if_group):
   Custom rule initially only captured "added" events because if_sid 
   ties to one specific parent rule, not the full syscheck category. 
   Switched to if_group to capture all FIM event types.


ANALYSIS
- Classification: True Positive (self-simulated, intentional test)
- This demonstrates Wazuh's rule inheritance model: custom rules can 
  build on top of existing rules (if_sid) or entire rule groups 
  (if_group) to create targeted, high-priority alerts without 
  duplicating Wazuh's underlying detection logic.


LESSONS LEARNED
- Wazuh rule XML errors prevent the ENTIRE manager service from 
  starting, not just the broken rule - a single syntax mistake takes 
  down all detection capability until fixed
- Always check `systemctl status` and `journalctl` immediately after 
  a failed restart - the error output pinpoints the exact issue
- if_sid scopes to one specific parent rule ID; if_group scopes to an 
  entire category of rules - choosing the wrong one silently limits 
  what your custom rule actually catches
- Custom rules are the mechanism real SOC teams use to turn generic, 
  high-volume default alerts into targeted, business-relevant detections

