LAB 3: PRIVILEGE ESCALATION DETECTION

Date: 2026-08-24
Environment: Windows 11 Home (agent, Wazuh v4.14.6) → Ubuntu (Wazuh manager/indexer/dashboard) 


SCENARIO
Created a standard test user account and added it to the local 
Administrators group to simulate a privilege escalation attempt, 
validating detection via Wazuh.


DETECTION

Event - Member Added to Administrators Group:
- Event ID: 4732 (Member added to security-enabled local group)
- rule.id: 60154 
- rule.description: Administrators Group Changed 
- rule.level: 12 
- Member Security ID: S-1-5-21-3422731786-1317582444-2929230245-1005
- Member Account Name:testUser
- Group Name: Administrators
- Group Security ID: S-1-5-32-544
- Group Domain: Builtin
- Subject User Name (who performed the action): gauri 


ANALYSIS
- Classification: True Positive (self-simulated test)
- MITRE ATT&CK ID:T1484 
- MITRE ATT&CK Tactic: Defense Evasion, Privilege Escalation 
- MITRE ATT&CK Technique: Domain Policy Modification 
- Reasoning: A standard user account was granted membership in the 
  built-in Administrators group, immediately elevating its permissions 
  from limited/standard access to full administrative control. This 
  mirrors real-world vertical privilege escalation, where an attacker 
  who has compromised a low-privilege account seeks to gain admin/root 
  rights to install malware, disable defenses, or access sensitive data.



TROUBLESHOOTING NOTE
Raw event initially showed a blank Account Name field for the added 
member, displaying only the Security ID (SID). This is a known Windows 
behavior where SID-to-username resolution doesn't always populate 
immediately in the raw log, particularly for recently created local 
accounts. Verified the SID manually using:
  wmic useraccount where name='testuser' get sid



RESPONSE RECOMMENDATION
- Verify whether this group membership change was authorized (e.g., 
  matches an approved IT change request)
- If unauthorized, immediately remove the account from the 
  Administrators group and investigate how/why the change occurred
- Review recent logon activity for the affected account for further 
  suspicious behavior
- Check for follow-up indicators of compromise (new processes, 
  outbound connections, additional account changes)


LESSONS LEARNED
- Any addition to the Administrators group generates Event ID 4732, 
  regardless of whether the action was legitimate or malicious - 
  context and authorization records determine true vs false positive
- Privilege escalation detection relies on monitoring group membership 
  changes as a key indicator, since this is a common attacker objective 
  after gaining initial access


