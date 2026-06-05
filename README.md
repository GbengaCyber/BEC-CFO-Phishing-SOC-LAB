# BEC CFO Phishing SOC LAB

## Why This Project Exists

Business Email Compromise is the most financially damaging cybercrime category in the world. The FBI Internet Crime Complaint Center reported over 2.9 billion dollars in BEC losses in 2023 alone — more than ransomware, more than data theft, more than any other category of cybercrime. The attacks are not technically sophisticated. They do not require malware or zero-day exploits. They exploit trust, urgency, and the fact that Finance teams process payment requests under time pressure every single day.

The typical attack looks like this. A CFO or Finance employee receives an email that appears to come from a trusted source — a vendor, a Microsoft service, or even their own CEO. The email contains a link or a request. The employee acts on it. By the time anyone realises something is wrong, a wire transfer has left the organisation and landed in an account the attacker controls. Recovery is rare. Most of the money is never returned.

This project simulates that exact scenario inside a controlled Microsoft 365 E5 environment and documents the full SOC investigation — from the moment the phishing email landed in the CFO inbox to the moment the attacker's foothold was removed and the incident was closed.



## The Financial Reality of BEC

A Finance employee processes dozens of payment requests, invoice approvals, and vendor communications every week. BEC attackers study this. They time their attacks to coincide with month-end close, acquisition activity, or periods when the CFO is travelling. They craft emails that match the tone and format of legitimate business correspondence. The ask is always plausible — a vendor changed their bank account details, an urgent wire transfer needs same-day approval, a shared document needs sign-off before a deal closes.

What makes this so damaging is that no technical control on the victim's device is involved. The employee does not execute a file. They do not install software. They simply respond to what looks like a normal business request. By the time the Finance team realises the vendor's bank details were fraudulent, the payment is gone.

The three controls that stop most BEC attacks before they start are not complicated. Multi-factor authentication prevents an attacker from using stolen credentials even if a phishing link is clicked. Email authentication enforcement via DMARC prevents lookalike domains from reaching the inbox in the first place. Payment verification procedures — a phone call to a known number before processing any change to payment details — stop the fraud even when the email reaches the employee. None of these require advanced technology. They require consistent implementation.



## The Scenario

The CFO of Eagle Secure IT received an email appearing to come from the Microsoft 365 Security Team, warning of an unusual sign-in and asking her to verify her identity via a shared document link. The email came from security-alert@microsoft-365alerts.com — a domain registered to impersonate Microsoft's legitimate services.

She clicked the link. Her credentials were recorded by the credential harvest landing page. Within hours, an attacker authenticated to her account from an overseas VPN, read through her inbox, identified active payment conversations, and set up three inbox rules designed to give persistent covert access to her mailbox — forwarding everything to an external Gmail, silently deleting any security alerts from Microsoft, and routing invoice and payment emails to a hidden folder the attacker could monitor.

The attacker's next step, in a real incident, would have been to intercept an invoice payment and redirect it to a controlled account. That step was caught by the SOC before it happened.



## Environment

| Component | Details |
|---|---|
| Microsoft 365 E5 | Attack Simulator, Defender for Office 365, Defender XDR |
| Microsoft Entra ID | Identity management, Conditional Access, Identity Protection |
| Microsoft Sentinel | SIEM, custom analytics rules, KQL threat hunting |
| Exchange Online | Mailbox forensics, inbox rule analysis |
| Victim account | cfo@eagle****.com — Sarah Mitchell, Chief Financial Officer |



## MITRE ATT&CK Coverage

| Technique | ID | What happened in this incident |
|---|---|---|
| Phishing: Spearphishing Link | T1566.002 | Invoice-themed phishing email delivered to CFO inbox |
| Valid Accounts | T1078 | Attacker authenticated using harvested CFO credentials |
| Email Forwarding Rule | T1114.003 | All incoming mail silently forwarded to attacker Gmail |
| Email Hiding Rules | T1564.008 | Security alerts deleted, financial emails hidden |
| Email Collection | T1114 | Attacker read through CFO mailbox before setting rules |



## Attack and Investigation Flow

```
Phishing email delivered to CFO inbox (microsoft-365alerts.com lookalike)
        |
CFO clicks link — credentials harvested
        |
Attacker authenticates from Andorra VPN — IP 62.197.152.196
        |
Three inbox rules created within 6 minutes:
  Sync    — forward all mail to attacker Gmail
  Cleanup — delete security alerts and MFA notifications
  Sort    — route payment emails to hidden folder
        |
Custom Sentinel rule fires automatically
        |
Incident 107 created in Defender XDR — High severity
        |
SOC analyst assigned — NIST 800-61 triage
        |
KQL hunting across EmailEvents, SigninLogs, CloudAppEvents, OfficeActivity
        |
Containment — account disabled, rules deleted, IOCs blocked, email purged
```



## Phase 01 — Environment Setup

The CFO account was provisioned in Microsoft Entra ID as a standard member with no admin roles. Finance staff do not need administrative access — they need the authority to approve payments, which exists in business process rather than in system permissions. Limiting admin roles to those who genuinely require them is a basic identity hygiene control that reduces the blast radius of any compromise.

During setup, an IAM gap was identified that became the root cause of the entire incident. Despite eleven active Conditional Access policies — including a strong MFA requirement, a sign-in risk block, and a compliant device requirement — the CFO account was not in scope for any of them. This is a common failure pattern in enterprise environments. CA policies are often rolled out incrementally, and exclusions that were meant to be temporary become permanent as organisations move on to other priorities.

The result was a C-suite Finance account with no MFA, no device compliance check, and no sign-in risk protection. A stolen password was all an attacker needed to walk in.

![CFO account provisioned in Entra ID — standard member, no admin roles](screenshots/Account_Provision.png)

![Eleven active CA policies — CFO account excluded from all of them](screenshots/Excluded_from_CA_policies.png)



## Phase 02 — Detection Rules Built Before the Simulation

Five custom detection rules were deployed in Microsoft Sentinel before the phishing campaign launched. In a real security programme, detection rules are built based on known attacker behaviour — not written in response to an incident that already happened. Building rules first and validating them against live telemetry is how a security team knows their detection actually works.

Each rule was mapped to a specific MITRE ATT&CK technique matching a stage of the BEC attack chain.

| Rule | MITRE | What it detects |
|---|---|---|
| BEC: Inbox forwarding to external domain | T1114.003 | Inbox rule forwarding mail outside the tenant |
| BEC: Inbox rule auto-deleting keyword emails | T1564.008 | Rules deleting security and alert keyword emails |
| IAM: CFO sign-in from unmanaged device | T1078 | Successful CFO login from non-enrolled device |
| BEC: Impossible travel detected | T1078 | Sign-ins from geographically impossible locations |
| BEC: Mass mailbox access for CFO | T1114 | Unusual MailItemsAccessed volume on CFO mailbox |

The IAM sign-in rule fired during the simulation and created Incident 107 in Defender XDR automatically — no analyst had to find it manually.

![All five custom detection rules active in Sentinel before the simulation ran](screenshots/Detection_Rules.png)



## Phase 03 — Attack Delivery

The phishing email was built to look like a legitimate Microsoft 365 OneDrive notification about a shared document titled Outstanding Invoice. The sender display name read Microsoft 365 Security Team. The actual sending address was security-alert@microsoft-365alerts.com — a domain specifically registered to impersonate Microsoft branding.

This is exactly how real BEC lures work. The display name is trusted. The context is plausible for a CFO. The urgency is embedded in the subject matter. A busy executive reviewing email between meetings is unlikely to hover over the sender address to check the domain.

Outlook flagged the email as coming from a sender not in the Safe senders list — the only visible warning the CFO received. The email was not quarantined or blocked because Attack Simulator uses a tenant whitelist, confirmed by the SCL of -1 found in the raw email headers. In a real attack from the same domain, a DMARC enforcement policy would have prevented delivery entirely.

![Phishing email landed in CFO inbox from lookalike domain](screenshots/Email_landed_in_inbox.png)

![MXToolbox header analysis — SCL -1 confirmed, authentication bypassed by simulator whitelist](screenshots/SPF_dkim_Results.png)



## Phase 04 — Credential Harvest

The CFO clicked the link. Attack Simulator recorded the event and displayed the security awareness debrief page. The campaign results confirmed Compromised: Yes for the account. UrlClickEvents in Defender XDR logged the click at 11:43 AM with the full phishing URL.

From the attacker's perspective, this is the moment they have what they need. The credential harvest page captured the account details entered on the fake Microsoft login. The attacker now has a valid username and password for a CFO account with no MFA protection.

Phishing-resistant MFA — FIDO2 security keys or Windows Hello for Business — would have made this credential useless to the attacker even after capture. These methods bind authentication to the origin domain, meaning a credential harvested on a fake site cannot be replayed on the real service. Standard MFA methods like SMS or authenticator app push notifications do not provide this protection and can be bypassed by adversary-in-the-middle proxy attacks.

![Attack Simulator debrief page confirming Sarah Mitchell was phished](screenshots/cfo_clicked.png)

![Campaign results — Compromised: Yes, Clicked message link confirmed](screenshots/Campaign_Evidence_-_Compromised.png)



## Phase 05 — User Reports the Email

The CFO reported the email as phishing using the built-in Outlook Report button. The report appeared in Defender XDR under the Submissions page with a counter showing Simulations: 1 — Defender correctly identified it as a simulation. In a real incident this would read Threats: 1 and trigger automatic incident correlation.

User reporting is an undervalued detection signal. When an employee reports a phishing email, it tells the security team that the email reached at least one inbox, the user recognised something was wrong, and the email may have reached other recipients who did not report it. A well-configured user submission policy routes these reports directly into the SOC queue for triage.

![Defender XDR Submissions — user reported phishing entry from CFO account](screenshots/Submission.png)



## Phase 06 — Incident Triage

Incident 107 was created automatically by the custom IAM detection rule when the attacker first signed in from an unmanaged device. The incident appeared in Defender XDR with High severity, tagged BEC-Lab and CFO-Targeting, and was assigned to the analyst.

This is the NIST 800-61 Detection and Analysis phase in practice. The analyst validates the alert, reviews the evidence panel, checks the affected user for other recent alerts, and forms a working hypothesis before touching any containment controls. Acting too quickly on a misclassified alert wastes time and can disrupt legitimate users. Acting too slowly on a confirmed compromise gives the attacker more time to establish persistence.

The hypothesis here was clear. A CFO account had signed in from an overseas VPN with no CA policy applied. Combined with the phishing campaign telemetry already visible in Attack Simulator, this was a confirmed credential compromise.

![Incident 107 in Defender XDR — High severity, auto-created by custom detection rule](screenshots/XDR_-Incident_view.png)

![Incident assigned to analyst — tagged and classified](screenshots/Incident_Assigned_-Tagged.png)



## Phase 07 — Attacker Establishes Persistence

Logged into the CFO account via VPN to simulate the attacker's perspective, three inbox rules were created inside OWA. The rule names were chosen to look innocuous — Sync, Cleanup, Sort — because real attackers name rules to avoid raising suspicion if the account owner happens to check their settings.

The forwarding rule sent every incoming email to an external Gmail address. The attacker now had a live feed of everything the CFO received — vendor invoices, payment approvals, board communications, banking notifications. The Cleanup rule deleted any email from Microsoft about security alerts, password resets, MFA prompts, or unusual sign-in activity. The real user would never see a notification that their account had been flagged. The Sort rule silently moved any email mentioning invoice, payment, wire transfer, bank, or ACH into a hidden folder called RSS Feeds — a folder the attacker monitored, waiting for the right payment conversation to intercept.

This is the moment in a real BEC incident where the organisation becomes vulnerable to the actual financial loss. The attacker is now positioned to reply to a vendor invoice thread, change the payment details, and wait for Finance to process the transfer.

![Attacker enabled email forwarding to external Gmail from within OWA](screenshots/Attacker_Enabled_forwarding.png)

![PowerShell Get-InboxRule output confirming all three attacker rules with full configuration visible](screenshots/EMAIL_MAINUPULATION_RULES.png)



## Phase 08 — Threat Hunting with KQL

Four data tables were queried across Defender XDR and Microsoft Sentinel to build the complete attacker timeline and confirm the persistence activity with two independent data sources.

SigninLogs in Sentinel showed two successful authentications for the CFO account. The first came from a Canadian IPv6 address matching the victim's legitimate device. The second came from 62.197.152.196 in Andorra — the attacker's VPN exit node. The ConditionalAccessStatus field for the second login showed notApplied, confirming no policy intercepted the authentication.

OfficeActivity confirmed three New-InboxRule operations from IP 62.197.152.180 within a six-minute window, along with a MailItemsAccessed operation showing the attacker read through the mailbox before creating the rules. CloudAppEvents recorded the same inbox rule events from the same IP independently. Two separate log sources confirming the same attacker action from the same foreign IP is the kind of evidence that holds up in an incident report and leaves no room for doubt.

![SigninLogs — two sign-ins for CFO, second from Andorra VPN with ConditionalAccess notApplied](screenshots/Attacker_Sign_in_-__KQL.png)

![OfficeActivity — New-InboxRule and MailItemsAccessed from attacker IP 62.197.152.180](screenshots/Office_Activity.png)



## Phase 09 — Containment and Eradication

Containment followed a deliberate sequence. The account was disabled first to immediately cut the attacker's access. Sessions were revoked next to invalidate any access tokens the attacker was holding in an active browser session. Only then were the cleanup actions completed — password reset, inbox rule removal, forwarding disabled, email purged, IOCs blocked.

The sequence matters because an attacker with an active session can continue operating in the mailbox even after a password reset if the session tokens are not separately revoked. And inbox rules persist independently of credentials — a password reset does not remove them. An attacker who retains working inbox rules continues to receive forwarded emails even after losing the ability to authenticate directly.

The phishing email was permanently removed from the mailbox via hard delete in Defender XDR, confirmed with Approval ID 97983e in the action center audit trail. The sender address and both attacker-controlled domains were added to the Tenant Allow/Block List to prevent future delivery to any mailbox in the organisation.

![CFO account disabled in Entra ID — attacker access cut immediately](screenshots/Account_Disabled.png)

![OWA Rules page empty — all three attacker inbox rules removed](screenshots/Rules_Deleted.png)

![Tenant Allow/Block List — phishing domains blocked at tenant level](screenshots/IOCS_BLOCKED.png)

![Phishing email hard deleted from CFO mailbox — action logged in audit trail](screenshots/Harddelete_email.png)



## Phase 10 — Incident Closure

Incident 107 was closed as True Positive — Phishing with all containment actions documented in the closure notes. The Conditional Access gap was escalated separately to the IAM team as a priority finding, with a recommendation to audit all C-suite and Finance accounts for CA policy scope and enforce phishing-resistant MFA as the authentication standard for those accounts.

![Incident 107 resolved — True Positive, Phishing, all actions completed](screenshots/Incident_Closed.png)



## What Would Have Stopped This Attack

**Phishing-resistant MFA on the CFO account.** A FIDO2 security key or Windows Hello for Business would have made the harvested credential completely useless. The attacker had a valid username and password and still could not have authenticated. This is the single highest-impact control for preventing BEC credential compromise.

**DMARC enforcement on the receiving domain.** The phishing email came from a lookalike domain. Under a DMARC policy of p=reject, that email would have been refused by the receiving mail server before it ever reached the CFO inbox. The attack has no entry point if the lure never arrives.

**Conditional Access scoped to include all Finance and C-suite accounts.** The tenant had strong CA policies. The CFO account was excluded from all of them. CA policy scope audits should be a regular control — at minimum quarterly — to catch exclusions that have outlived their original justification.

**Inbox rule monitoring.** The three rules the attacker created would have been invisible without the custom detection rules deployed in Sentinel. A scheduled query checking for new inbox rules with external forwarding or keyword deletion, running every hour, surfaces this activity the same day it happens rather than weeks later when Finance notices money is missing.

**Payment verification procedures.** Technical controls stop most attacks. Business process controls stop the rest. A policy requiring a phone call to a known, verified number before processing any change to vendor payment details — regardless of how legitimate the email looks — breaks the final step in the BEC kill chain even when everything else fails.



## Lessons Learned

The CFO account had no MFA, no device compliance requirement, and no sign-in risk policy. Eleven CA policies were active in the tenant and none of them covered this account. A single exclusion in an otherwise mature identity posture was enough for the attacker to walk in with only a password. CA policy exclusions should be reviewed on a fixed schedule and justified in writing. Any account with payment authority or access to financial systems should be treated as highest priority for identity protection controls.

The DMARC policy for the tenant was in monitoring mode. A lookalike domain email reached the inbox without any challenge. The move from p=none to p=reject is a configuration change that takes less than an hour and eliminates an entire class of spoofing attacks permanently.

Inbox rules created during a compromise survive password resets. Any BEC response that stops at credential remediation without auditing mailbox configuration leaves the attacker's most valuable persistence mechanism intact. The three rules in this incident would have continued forwarding financial emails to the attacker's Gmail for days or weeks after the password was changed, until someone noticed.

Detection rules built before an attack and validated against live telemetry are meaningfully more reliable than rules written in response to an incident. The IAM sign-in rule in this project fired and created the incident automatically. The analyst did not find the compromise — the detection engineering found it.



## Tools Used

Microsoft 365 E5 · Microsoft Entra ID · Microsoft Defender XDR · Microsoft Sentinel · Exchange Online · Attack Simulator · MXToolbox · KQL



## Author

Gbenga Abraham  
SOC and IAM Security Portfolio Project  
June 2026
