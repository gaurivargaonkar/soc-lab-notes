LAB 1: BRUTE FORCE DETECTION VIA FAILED LOGINS

Date: 2026-08-20
Environment: Windows 11 Home (agent, Wazuh v4.14.6) → Ubuntu (Wazuh manager/indexer/dashboard) 


SCENARIO
Simulated a brute-force login attempt by entering an incorrect password 
4-5 times on the Windows endpoint's login screen, followed by a successful 
login with the correct password.


DETECTION
- Rule ID: 60122
- Rule Description: Logon Failure - Unknown user or bad password
- Severity Level (rule.level): 5
- Event ID(s): 4625 (failed logon) 5, 4624 (successful logon) 6
- Log Source: Windows Security Event Log
- Target Account: SecLab 


ADDITIONAL OBSERVATION
After approximately 4-5 failed login attempts, Windows displayed an 
additional security challenge — a code (e.g., "A1B2C3") that had to be 
entered before another password attempt was allowed. This is a native 
Windows account-lockout / verification control, separate from Wazuh's 
detection. Demonstrates defense-in-depth: OS-level protection working 
alongside SIEM-level log-based detection.


ANALYSIS
- Classification: True Positive (self-simulated test)
- MITRE ATT&CK Tactic: Impact (T1531)
- MITRE ATT&CK Technique: T1110 - Brute Force
- Reasoning: Multiple rapid authentication failures followed by a 
  successful login is a classic brute-force / password-guessing pattern.


RESPONSE RECOMMENDATION
- Temporarily lock or monitor the affected account
- Verify the successful login was legitimate (confirm with account owner)
- Recommend enabling MFA on the account if not already active
- Review source of login attempts (local vs remote) for further context

LESSONS LEARNED
- Wazuh correlates repeated 4625 events into a single higher-severity 
  alert (rule 60122) rather than just logging isolated events
- Windows has its own built-in brute-force protection (lockout/code 
  verification) independent of the SIEM — both layers work together


