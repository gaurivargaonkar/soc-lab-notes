LAB 2: FILE INTEGRITY MONITORING (FIM)

Date: 2026-08-21
Environment: Windows 11 Home (agent, Wazuh v4.14.6) → Ubuntu (Wazuh manager/indexer/dashboard) 

SCENARIO
Enabled real-time FIM on a test folder (C:\Users\Public\TestFolder) and 
performed file creation, modification, and deletion to validate detection.

DETECTION
Event 1 - File Added:
- syscheck.path: c:\users\public\testfolder\test.txt
- syscheck.event: added
- rule.description: File added to the system.
- rule.level: 5

Event 2 - File Modified:
- syscheck.path: c:\users\public\testfolder\test.txt
- syscheck.event: modified
- rule.description: Integrity checksum changed.
- rule.level: 7

Event 3 - File Deleted:
- syscheck.path: c:\users\public\testfolder\test.txt
- syscheck.event: deleted
- rule.description: File deleted.
- rule.level: 7

ANALYSIS
- rule.mitre.id  : T1070.004 , T1485
-rule.mitre.tactic : Defense evasion , Impact
-rule.mitre.techniques : File deletion , File Destruction
- Modification and deletion carry higher severity (level 7) than 
  addition (level 5) — reflects greater risk of tampering/data loss



TROUBLESHOOTING NOTE (valuable real-world lesson)
Initial FIM setup failed silently due to a malformed XML closing tag 
(<directories> instead of </directories>) in ossec.conf. This caused 
the entire syscheck configuration block to fail loading, with no 
error shown in the dashboard — only visible by checking ossec.log 
directly on the agent. Lesson: always verify agent-side logs when 
a SIEM feature appears silently non-functional; the dashboard only 
shows what data actually arrives, not configuration failures.

RESPONSE RECOMMENDATION
- Investigate who/what modified or deleted the file
- Cross-reference with process creation logs around 
  the same timestamp to identify the responsible process/user
- If unauthorized, restore from backup and review access permissions

LESSONS LEARNED
- Real-time FIM detects add/modify/delete within seconds once properly configured
- Wazuh tracks file hash changes (md5/sha1) to confirm actual content 
  modification, not just timestamp changes
- A single missing character in XML config can silently break an 
  entire monitoring feature — config validation is a critical skill

