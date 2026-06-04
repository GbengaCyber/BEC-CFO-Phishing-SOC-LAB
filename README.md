# BEC CFO Phishing SOC LAB

## Overview

This project documents a full Business Email Compromise simulation and SOC investigation conducted inside a Microsoft 365 E5 tenant. The scenario targets the Chief Financial Officer of a fictitious organisation, Eagle Secure IT, using a credential harvest phishing campaign. The investigation follows the NIST 800-61 incident response lifecycle from detection through containment and closure.

The goal was to demonstrate real-world SOC analyst capabilities including phishing triage, KQL threat hunting across multiple Microsoft security platforms, and identity-based remediation — skills directly applicable to SOC Tier 1/2 and IAM security roles.

---

## The Business Scenario

The CFO received what appeared to be a Microsoft OneDrive file share notification regarding an outstanding invoice. The email came from a lookalike domain designed to impersonate a trusted Microsoft service. After clicking the link, the account was marked as compromised. Shortly after, an attacker logged into the account from an overseas VPN and set up three inbox rules to forward financial emails, delete security alerts, and hide payment conversations in a hidden folder — a textbook Business Email Compromise persistence play.

The security team detected the anomalous sign-in via a custom Sentinel detection rule, triaged the incident in Microsoft Defender XDR, hunted attacker activity across four log tables, and completed full containment.

---

## Environment

| Component | Details |
|---|---|
| Microsoft 365 E5 | Attack Simulator, Defender for Office 365, Defender XDR |
| Microsoft Entra ID | Identity management, Conditional Access, Identity Protection |
| Microsoft Sentinel | SIEM, custom analytics rules, KQL threat hunting |
| Exchange Online | Mailbox forensics, inbox rule analysis |
| Victim account | cfo@eagle****.com — Sarah Mitchell, Chief Financial Officer |

---

## MITRE ATT&CK Coverage

| Technique | ID | What happened |
|---|---|---|
| Phishing: Spearphishing Link | T1566.002 | Invoice-themed phishing email delivered to CFO inbox |
| Valid Accounts | T1078 | Attacker authenticated using harvested CFO credentials from a VPN |
| Email Forwarding Rule | T1114.003 | All incoming mail silently forwarded to attacker Gmail |
| Email Hiding Rules | T1564.008 | Security alerts auto-deleted, financial emails moved to hidden folder |
| Email Collection | T1114 | Attacker browsed CFO mailbox reading financial conversations |

---

## Attack Flow

```
Phishing email delivered to CFO inbox
        |
CFO clicks link — credential harvest recorded by Attack Simulator
        |
Attacker logs in from overseas VPN (Andorra, IP 62.197.152.196)
        |
Attacker creates 3 inbox rules:
  Sync    — forward all mail to external Gmail
  Cleanup — auto-delete security alerts and MFA notifications
  Sort    — move invoice and payment emails to hidden RSS Feeds folder
        |
Custom Sentinel rule fires — IAM: CFO sign-in from unmanaged device
        |
SOC analyst assigned — NIST 800-61 triage begins
        |
KQL hunting across EmailEvents, SigninLogs, CloudAppEvents, OfficeActivity
        |
Full containment — account disabled, sessions revoked, rules deleted, IOCs blocked
```

---

## Phase 01 — Environment Setup

A dedicated CFO account was provisioned in Microsoft Entra ID with no admin roles, assigned an M365 E5 license, and given the title Chief Financial Officer in the Finance department. This reflects real-world BEC targeting — Finance and C-suite accounts are the primary victims in the majority of BEC incidents reported to the FBI IC3.

During setup, a critical IAM gap was discovered. Despite eleven active Conditional Access policies in the tenant, the CFO account was not in scope for any of them. This meant the account had no MFA requirement, no device compliance check, and no sign-in risk policy applied — a single account exclusion that became the root cause of the entire incident.

![CFO account provisioned in Entra ID](screenshots/Account_Provision.png)

![CFO account excluded from all CA policies — the IAM gap](screenshots/Excluded_from_CA_policies.png)

---

## Phase 02 — Detection Rules Built Before the Simulation

Five custom analytics rules were deployed in Microsoft Sentinel before the simulation ran. This is the correct order — detection engineering should precede the attack, not follow it. Building rules first and watching them fire against real telemetry is how you validate that detection logic actually works.

| Rule | MITRE | What it detects |
|---|---|---|
| BEC: Inbox forwarding to external domain | T1114.003 | Inbox rule with ForwardTo pointing outside the tenant |
| BEC: Inbox rule auto-deleting keyword emails | T1564.008 | Rules deleting security and alert keyword emails |
| IAM: CFO sign-in from unmanaged device | T1078 | Successful CFO login from non-enrolled device |
| BEC: Impossible travel detected | T1078 | Sign-ins from geographically impossible locations |
| BEC: Mass mailbox access for CFO | T1114 | Unusual MailItemsAccessed volume on CFO mailbox |

The IAM sign-in rule fired during the simulation and created Incident 107 automatically — exactly as designed.

![All five custom detection rules active in Sentinel before simulation](screenshots/Detection_Rules.png)

---

## Phase 03 — Attack Delivery

A credential harvest payload was created in Attack Simulator impersonating a Microsoft 365 OneDrive file share. The sender domain microsoft-365alerts.com was chosen deliberately as a lookalike — close enough to fool a busy executive, different enough to fail email authentication checks against the real microsoft.com domain.

The email landed in the CFO inbox and Outlook flagged it as coming from an unknown sender. This is the only visible warning the user received. The email was not quarantined because Attack Simulator bypasses spam filtering via a tenant whitelist, reflected in the SCL of -1 found in the raw headers.

The headers were extracted and analysed via MXToolbox. No SPF, DKIM, or DMARC results appeared because the SCL -1 bypass prevented authentication evaluation entirely. In a real attack from the same domain, DMARC would have failed due to misalignment with microsoft.com and the email would have been quarantined under an enforced policy.

![Phishing email landed in CFO inbox](screenshots/Email_landed_in_inbox.png)

![MXToolbox header analysis — SCL -1 confirmed, no authentication evaluated](screenshots/SPF_dkim_Results.png)

---

## Phase 04 — CFO Clicks the Link

Logged in as the CFO, the phishing link was clicked. Attack Simulator displayed the security awareness debrief page confirming the simulation event was recorded. The campaign results page in Attack Simulator showed Compromised: Yes for Sarah Mitchell.

UrlClickEvents in Defender XDR confirmed the click at 11:43 AM with the phishing URL from attemplate.com — Attack Simulator's credential harvest infrastructure.

![Attack Simulator debrief page — Sarah Mitchell was phished](screenshots/cfo_clicked.png)

![Campaign results showing Compromised: Yes](screenshots/Campaign_Evidence_-_Compromised.png)

---

## Phase 05 — CFO Reports the Email

The CFO used the built-in Outlook Report button to report the email as phishing. The report surfaced in Defender XDR under Submissions — User reported tab. Defender correctly identified it as a simulation, shown by Simulations: 1 in the counter.

In a real incident this same workflow would generate Threats: 1 and trigger automatic incident creation. Documenting this step shows the full SOC intake process — user reports the email, it enters the analyst queue, investigation begins.

![Defender XDR Submissions tab showing user reported phishing entry](screenshots/Submission.png)

---

## Phase 06 — XDR Alert Fires and SOC Triage Begins

Before the phishing click even happened, the custom IAM detection rule had already fired at 8:32 AM when the attacker signed in from the VPN during lab setup. Incident 107 was created automatically in Defender XDR with High severity.

The incident was assigned to the analyst, tagged with BEC-Lab and CFO-Targeting, and classified as True Positive — Phishing. This follows the NIST 800-61 Detection and Analysis phase — the analyst validates the alert, gathers context, and begins formal investigation.

![Incident 107 in Defender XDR — High severity, created by custom detection rule](screenshots/XDR_-Incident_view.png)

![Incident assigned to analyst with BEC-Lab and CFO-Targeting tags](screenshots/Incident_Assigned_-Tagged.png)

---

## Phase 07 — Attacker Post-Compromise: Inbox Rule Persistence

Using the CFO account credentials and connected via VPN to simulate an overseas attacker, three inbox rules were created directly inside OWA. This represents what a real BEC actor does immediately after gaining mailbox access — establishing persistent, covert visibility into financial conversations.

Email forwarding was enabled pointing to an external Gmail address, giving the attacker a live feed of all incoming mail. A Cleanup rule was created to auto-delete any emails containing keywords like security alert, password reset, MFA, or unusual sign-in — ensuring the real user never sees Microsoft security notifications about the compromised account. A Sort rule was created to silently route any email mentioning invoice, payment, wire transfer, bank, or ACH into a hidden folder called RSS Feeds, where the attacker monitors for payment conversations to intercept.

![Attacker enabled forwarding to external Gmail from within OWA settings](screenshots/Attacker_Enabled_forwarding.png)

![PowerShell Get-InboxRule confirming all three attacker rules with full configuration](screenshots/EMAIL_MAINUPULATION_RULES.png)

---

## Phase 08 — Threat Hunting with KQL

Four data tables were queried across Defender XDR Advanced Hunting and Microsoft Sentinel to build the complete attacker timeline.

SigninLogs in Sentinel confirmed two successful authentications for the CFO account. The first was from a Canadian IPv6 address matching the victim's legitimate device. The second was from IP 62.197.152.196 in Andorra — the attacker's VPN exit node — with ConditionalAccessStatus of notApplied, confirming no CA policy intercepted the login.

OfficeActivity confirmed three New-InboxRule operations from IP 62.197.152.180 within a six-minute window, along with a MailItemsAccessed operation showing the attacker browsed the mailbox before creating the rules. CloudAppEvents showed the same events from the same IP independently, providing dual-source confirmation of the attacker's persistence activity.

![SigninLogs — two sign-ins for CFO account, second from Andorra VPN IP](screenshots/Attacker_Sign_in_-__KQL.png)

![OfficeActivity — New-InboxRule and MailItemsAccessed operations from attacker IP](screenshots/Office_Activity.png)

---

## Phase 09 — Containment and Eradication

All containment was completed through the Microsoft 365 security portal. The sequence matters — the account was disabled first to cut attacker access, sessions were revoked to kill any live tokens, and only then were the cleanup actions completed.

The most commonly missed step in BEC containment is inbox rule removal. Resetting a password does not delete inbox rules — they survive password changes and continue forwarding mail until explicitly removed. All three attacker rules were deleted and the forwarding setting was disabled. The phishing email was hard deleted from the mailbox with Approval ID 97983e logged in the action center.

The phishing sender address and both attacker domains were added to the Tenant Allow/Block List to prevent future delivery.

![CFO account disabled in Entra ID](screenshots/Account_Disabled.png)

![OWA Rules page empty — all attacker inbox rules removed](screenshots/Rules_Deleted.png)

![Tenant Allow/Block List — phishing domains and sender address blocked](screenshots/IOCS_BLOCKED.png)

![Phishing email hard deleted from CFO mailbox — action confirmed](screenshots/Harddelete_email.png)

---

## Phase 10 — Incident Closure

Incident 107 was resolved with classification True Positive — Phishing. All containment actions were documented in the closure comment. The Conditional Access gap was escalated as a separate finding for the IAM team — ensuring the CFO account and all C-suite accounts are brought into CA policy scope with phishing-resistant MFA enforced.

![Incident 107 closed — True Positive, Phishing, all containment actions completed](screenshots/Incident_Closed.png)

---

## Key Findings

The CFO account was excluded from all Conditional Access policies. An attacker with only a stolen password was able to authenticate from an unmanaged device in a foreign country without any challenge. This is the most common IAM failure pattern in real-world BEC incidents — a single account exclusion that negates an otherwise mature CA posture.

The tenant DMARC policy was in monitoring mode at the time of the simulation. A real lookalike domain attack would have reached the inbox unchallenged. Moving to enforcement removes this delivery vector entirely.

The inbox rules created by the attacker survived a password reset. Any BEC response that stops at credential remediation without checking for mailbox persistence leaves the attacker's foothold intact.

---

## Lessons Learned

Conditional Access policy scope needs to be audited regularly. Exclusions accumulate over time during rollout and exceptions that were temporary become permanent. Finance and C-suite accounts should be treated as highest priority for CA enforcement, not last.

DMARC enforcement is a low-effort, high-impact control. The difference between p=none and p=reject is a configuration change that eliminates an entire class of spoofing and lookalike domain attacks at the email layer.

Detection rules built before an attack and validated against live telemetry are meaningfully more reliable than rules written after the fact. The custom IAM sign-in rule fired and generated the incident automatically — the analyst did not have to find it manually.

---

## Tools Used

Microsoft 365 E5 · Microsoft Entra ID · Microsoft Defender XDR · Microsoft Sentinel · Exchange Online · Attack Simulator · MXToolbox · KQL

---

## Author

Gbenga Abraham  
SOC and IAM Security Portfolio Project  
June 2026
