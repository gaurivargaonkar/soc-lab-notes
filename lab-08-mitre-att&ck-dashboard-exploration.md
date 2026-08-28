LAB 8: MITRE ATT&CK DASHBOARD EXPLORATION

Date: 2026-08-27 Environment: Windows 11 Home (agent, Wazuh v4.14.6) → Ubuntu (Wazuh manager/indexer/dashboard)

SCENARIO 
Explored Wazuh's dedicated MITRE ATT&CK module (Dashboard, Framework, and Events tabs) to visualize detection coverage across the MITRE framework, using advanced search queries to investigate specific findings.

ADVANCED SEARCH QUERIES TESTED

rule.id: 100010 AND rule.level: >=7 combined with rule.mitre.id: exists filter -> demonstrated how AND logic and pre-existing filters combine, sometimes narrower than intended (e.g., TestFolder wildcard search returned 0 results when combined with a MITRE-exists filter, since not all TestFolder FIM events carry a MITRE tag)
rule.mitre.id:* -> 177 hits; revealed manager self-monitoring events (agent 000/"gubun") via T1078 (Valid Accounts, Defense Evasion) and T1548.003 (Privilege Escalation) from PAM logins and sudo usage on the Ubuntu manager itself - confirming Wazuh monitors its own host, not only registered agents
rule.level: >7 AND agent.id: 001 -> 2 hits, both T1098 (Account Manipulation) mapped to "Persistence" tactic (rule.id: 60110) - notable because Lab 3's privilege escalation test also produced T1098, but mapped to "Privilege Escalation" tactic instead, confirming the same MITRE technique can map to different tactics depending on the specific rule/context
data.win.system.eventID: 4625 OR 4624 -> 7 hits, definitively confirming rule 60122 (brute-force correlation, from Lab 1) maps to T1531 (Account Access Removal) under the Impact tactic - resolving the T1531 vs T1110 uncertainty noted in Lab 1's original documentation

MITRE DASHBOARD (AGGREGATE VIEW)

Top tactics overall: Privilege Escalation, Defense Evasion, Persistence, Initial Access
"Top tactics by agent" revealed the majority of MITRE-tagged activity (~45 each for Privilege Escalation and Defense Evasion) originated from the Ubuntu manager's own routine administrative activity (sudo usage, valid account logins), not the deliberately triggered Windows labs - highlighting that legitimate admin work can itself generate significant MITRE-mapped alert volume, a real consideration for alert tuning in production
Built-in "Generate report" feature available to export MITRE findings as a formatted document
MITRE FRAMEWORK MATRIX (WINDOWS AGENT SPECIFIC, agent.id: 001) Tactics with alerts: Persistence: 3 Privilege Escalation: 3 Defense Evasion: 2 Tactics with zero alerts (untested coverage): Credential Access, Execution, Impact, Lateral Movement, Exfiltration, Discovery, Collection, Resource Development Specific techniques triggered on Windows agent: T1098 - Account Manipulation (2) T1484 - Domain Policy Modification (2) T1543.003 - Windows Service (1)
ANALYSIS The MITRE Framework matrix view functions as a practical detection coverage gap-analysis tool, not just an alert-labeling reference - it visually shows which attack categories have been tested/detected versus which remain unaddressed. In this lab, 8 of 11 MITRE tactics show zero coverage on the Windows endpoint, providing a clear, prioritized list for expanding future lab scenarios (e.g., Discovery via recon commands, Execution via running a flagged process, Credential Access via credential dumping simulation).

LESSONS LEARNED

Decoders and rules follow the same inheritance pattern (parent/child relationships), just applied to log parsing versus alert logic respectively
Combining multiple active filters/queries can produce narrower results than intended if not all target events share every filtered field (e.g., not every FIM event carries a MITRE tag)
Wazuh's default ruleset monitors the manager host itself as an implicit agent, generating real detections from ordinary administrative activity - this is a genuine, useful discovery about default alert volume/noise in production environments
The same MITRE technique ID can legitimately map to different tactics depending on the specific triggering rule and context - MITRE mapping is not always a rigid one-to-one relationship
Direct, targeted search queries (filtering by specific Event IDs) are more reliable for resolving specific technical questions than broad exploratory dashboard browsing - this definitively resolved Lab 1's open MITRE mapping question
The MITRE Framework matrix is best used as a coverage-gap analysis tool to plan future detection testing, not merely a post-hoc labeling reference for alerts already generated

