# BEC: CFO - Phishing SOC LAB

## Why This Project Exists

Business Email Compromise cost organisations over 2.9 billion dollars in 2023 according to the FBI IC3, more than ransomware and more than any other cybercrime category. The attacks require no malware and no technical sophistication. They exploit trust, urgency, and the fact that Finance teams process payment requests under pressure every single day.
A CFO receives an email that looks like it came from a vendor or a Microsoft service. She clicks a link. By the time anyone realises something is wrong, a wire transfer has left the organisation and landed in an account the attacker controls. Recovery is rare.
This project simulates that exact scenario inside a Microsoft 365 E5 tenant and documents the full SOC investigation from the moment the phishing email landed in the CFO inbox to the moment the attacker's foothold was removed and the incident was closed.



## The Financial Reality of BEC

BEC works because it looks like normal business. Attackers time campaigns around month end close or periods when the CFO is travelling. The request is always plausible, a vendor updated their bank details, an invoice needs same day approval, a document needs sign off before a deal closes. No malware is involved. The employee simply responds to what looks like routine correspondence and the money is gone before anyone realises.
Three controls stop most BEC attacks before they cause damage. Phishing-resistant MFA makes stolen credentials useless even after a successful phish. DMARC enforcement blocks lookalike domain emails before they reach the inbox. Payment verification procedures,  a call to a known number before changing any payment details, break the final step even when everything else fails.

## The Scenario

The CFO of Eagle Secure IT received what looked like a Microsoft OneDrive notification about an outstanding invoice. She clicked the link, her credentials were harvested, and within hours an attacker logged in from an overseas VPN and set up inbox rules to forward all her mail externally, delete security alerts, and hide payment conversations in a folder they could monitor silently.
The SOC caught it through a custom Sentinel detection rule that fired on the anomalous sign-in. The investigation that followed used KQL across four data tables to confirm the full attack chain and complete containment the same day.


## Environment

| Component | Details |
|---|---|
| Microsoft 365 E5 | Attack Simulator, Defender for Office 365, Defender XDR |
| Microsoft Entra ID | Identity management, Conditional Access, Identity Protection |
| Microsoft Sentinel | SIEM, custom analytics rules, KQL threat hunting |
| Exchange Online | Mailbox forensics, inbox rule analysis |
| Victim account | cfo@ea****.com, Sarah Mitchell, Chief Financial Officer |



## MITRE ATT&CK Coverage

| Technique | ID | What happened in this incident |
|---|---|---|
| Phishing: Spearphishing Link | T1566.002 | Invoice themed phishing email delivered to CFO inbox |
| Valid Accounts | T1078 | Attacker authenticated using harvested CFO credentials |
| Email Forwarding Rule | T1114.003 | All incoming mail silently forwarded to attacker Gmail |
| Email Hiding Rules | T1564.008 | Security alerts deleted, financial emails hidden |
| Email Collection | T1114 | Attacker read through CFO mailbox before setting rules |



## Attack and Investigation Flow

```
Phishing email delivered to CFO inbox (microsoft-365alerts.com lookalike)
        |
CFO clicks link - credentials harvested
        |
Attacker authenticates from Andorra VPN — IP 62.197.152.XXX
        |
Three inbox rules created within 6 minutes:
  Sync    - forward all mail to attacker Gmail
  Cleanup - delete security alerts and MFA notifications
  Sort    - route payment emails to hidden folder
        |
Custom Sentinel rule fires automatically
        |
Incident 107 created in Defender XDR - High severity
        |
SOC analyst assigned - NIST 800-61 triage
        |
KQL hunting across EmailEvents, SigninLogs, CloudAppEvents, OfficeActivity
        |
Containment : account disabled, rules deleted, IOCs blocked, email purged
```



## Phase 01: Environment Setup

The CFO account was created in Microsoft Entra ID as a standard member with no admin roles. Finance staff need payment authority, not system permissions. Keeping admin roles limited to those who genuinely require them reduces the blast radius of any compromise.
During setup an IAM gap was discovered that became the root cause of the entire incident. The tenant had eleven active Conditional Access policies including MFA, sign-in risk block, and compliant device requirements. The CFO account was excluded from all of them. CA exclusions that start as temporary workarounds have a way of becoming permanent. The result was a C-suite Finance account a stolen password was all an attacker needed to access.

---
<img width="800"  alt="image" src="https://github.com/user-attachments/assets/380fad99-816d-4988-95c8-4f2bba8e6d2c" />

---

<img width="800"  alt="image" src="https://github.com/user-attachments/assets/3a1d00f3-5098-454b-95fb-344454f35047" />


---

## Phase 02: Detection Rules Built Before the Simulation

Five custom detection rules were deployed in Microsoft Sentinel before the phishing campaign launched. In a real security programme, detection rules are built based on known attacker behaviour, not written in response to an incident that already happened. Building rules first and validating them against live telemetry is how a security team knows their detection actually works.

Each rule was mapped to a specific MITRE ATT&CK technique matching a stage of the BEC attack chain.

| Rule | MITRE | What it detects |
|---|---|---|
| BEC: Inbox forwarding to external domain | T1114.003 | Inbox rule forwarding mail outside the tenant |
| BEC: Inbox rule auto-deleting keyword emails | T1564.008 | Rules deleting security and alert keyword emails |
| IAM: CFO sign-in from unmanaged device | T1078 | Successful CFO login from non-enrolled device |
| BEC: Impossible travel detected | T1078 | Sign-ins from geographically impossible locations |
| BEC: Mass mailbox access for CFO | T1114 | Unusual MailItemsAccessed volume on CFO mailbox |

The IAM sign-in rule fired during the simulation and created Incident 107 in Defender XDR automatically, no analyst had to find it manually.

---
<img width="800" alt="image" src="https://github.com/user-attachments/assets/6e540fc1-0ed8-4070-9f28-5a3d031ad2a5" />

---
## Phase 03: Attack Delivery

The phishing email was built to look like a legitimate Microsoft 365 OneDrive notification about a shared document titled Outstanding Invoice. The sender display name read Microsoft 365 Security Team. The actual sending address was security-alert@microsoft-365alerts.com, a domain specifically registered to impersonate Microsoft branding.

This is exactly how real BEC lures work. The display name is trusted. The urgency is embedded in the subject matter. A busy executive reviewing email between meetings is unlikely to hover over the sender address to check the domain.

Outlook flagged the email as coming from a sender not in the Safe senders list, the only visible warning the CFO received. The email was not quarantined or blocked because Attack Simulator uses a tenant whitelist, confirmed by the SCL of -1 found in the raw email headers. In a real attack from the same domain, a DMARC enforcement policy would have prevented delivery entirely.

---
<img width="800"  alt="image" src="https://github.com/user-attachments/assets/ecd56463-5b46-4c2c-8698-16f88cc3b351" />

---

<img width="800" alt="image" src="https://github.com/user-attachments/assets/3a260833-9637-4a25-bf3e-44c1b038a40d" />

---

## Phase 04: Credential Harvest

The CFO clicked the link. Attack Simulator recorded the event and displayed the security awareness debrief page. The campaign results confirmed Compromised: Yes for the account. UrlClickEvents in Defender XDR logged the click at 11:43 AM with the full phishing URL.

From the attacker's perspective, this is the moment they have what they need. The credential harvest page captured the account details entered on the fake Microsoft login. The attacker now has a valid username and password for a CFO account with no MFA protection.

Phishing-resistant MFA, FIDO2 security keys or Windows Hello for Business, would have made this credential useless to the attacker even after capture. These methods bind authentication to the origin domain, meaning a credential harvested on a fake site cannot be replayed on the real service. Standard MFA methods like SMS or authenticator app push notifications do not provide this protection and can be bypassed by adversary-in-the-middle proxy attacks.

---

<img width="800" alt="image" src="https://github.com/user-attachments/assets/c7a49c51-284f-44eb-a834-312010b09ae0" />


---

<img width="800"  alt="image" src="https://github.com/user-attachments/assets/dd8ef0fe-72c9-448b-82e9-a2eb4955c229" />


---

## Phase 05: User Reports the Email

The CFO reported the email as phishing using the builtin Outlook Report button. The report appeared in Defender XDR under the Submissions page with a counter showing Simulations: 1: Defender correctly identified it as a simulation. In a real incident this would read Threats: 1 and trigger automatic incident correlation.

User reporting is an undervalued detection signal. When an employee reports a phishing email, it tells the security team that the email reached at least one inbox, the user recognised something was wrong, and the email may have reached other recipients who did not report it. A well-configured user submission policy routes these reports directly into the SOC queue for triage.

---

<img width="800"  alt="image" src="https://github.com/user-attachments/assets/79317ea7-c2fa-4396-98dd-1f21ca7b6fb9" />


--

## Phase 06: Incident Triage

Incident 107 was created automatically by the custom IAM detection rule when the attacker first signed in from an unmanaged device. The incident appeared in Defender XDR with High severity, tagged BEC-Lab and CFO-Targeting, and was assigned to the analyst.

This is the NIST 800-61 Detection and Analysis phase in practice. The analyst validates the alert, reviews the evidence panel, checks the affected user for other recent alerts, and forms a working hypothesis before touching any containment controls. Acting too quickly on a misclassified alert wastes time and can disrupt legitimate users. Acting too slowly on a confirmed compromise gives the attacker more time to establish persistence.

The hypothesis here was clear. A CFO account had signed in from an overseas VPN with no CA policy applied. Combined with the phishing campaign telemetry already visible in Attack Simulator, this was a confirmed credential compromise.

---

<img width="2098"  alt="image" src="https://github.com/user-attachments/assets/9796f887-fe15-4c0d-82a5-1c461f20baa7" />


---

<img width="800"  alt="image" src="https://github.com/user-attachments/assets/fa7ac8fe-e03c-42b2-a0fc-deb8663e00d8" />


---

## Phase 07: Attacker Establishes Persistence

Logged into the CFO account via VPN to simulate the attacker's perspective, three inbox rules were created inside OWA. The rule names were chosen to look real: Sync, Cleanup, Sort, because real attackers name rules to avoid raising suspicion if the account owner happens to check their settings.

The forwarding rule sent every incoming email to an external Gmail address. The attacker now had a live feed of everything the CFO received,  vendor invoices, payment approvals, board communications, banking notifications. The Cleanup rule deleted any email from Microsoft about security alerts, password resets, MFA prompts, or unusual sign-in activity. The real user would never see a notification that their account had been flagged. The Sort rule silently moved any email mentioning invoice, payment, wire transfer, bank, or ACH into a hidden folder called RSS Feeds, a folder the attacker monitored, waiting for the right payment conversation to intercept.

This is the moment in a real BEC incident where the organisation becomes vulnerable to the actual financial loss. The attacker is now positioned to reply to a vendor invoice thread, change the payment details, and wait for Finance to process the transfer.

---

<img width="800" alt="image" src="https://github.com/user-attachments/assets/59f3e3df-ec6b-4e10-972b-5899b377b83a" />


---

<img width="800"  alt="image" src="https://github.com/user-attachments/assets/4fdfe87a-ab0c-479d-8a2d-515ad023aad9" />


---

## Phase 08: Threat Hunting with KQL

Four data tables were queried across Defender XDR and Sentinel to build the complete attacker timeline.
SigninLogs showed two successful logins for the CFO account. The first was from a Canadian IPv6 address matching her legitimate device. The second was from Andorra, the attacker's VPN exit node, with ConditionalAccessStatus showing notApplied confirming no policy challenged the login.
OfficeActivity confirmed three New-InboxRule operations from the attacker IP within six minutes, plus a MailItemsAccessed entry showing the attacker read through the mailbox before setting the rules. CloudAppEvents recorded the same events independently. Two separate data sources confirming the same action from the same foreign IP leaves no room for doubt in the incident record

---

<img width="800"  alt="image" src="https://github.com/user-attachments/assets/ff0af282-5e12-4f51-9427-660bdd6d03bd" />

---

<img width="800"  alt="image" src="https://github.com/user-attachments/assets/ca97557b-b1db-4d05-a3ca-e1eef1cc4aa8" />


---

## Phase 09: Containment and Eradication

Containment followed a deliberate sequence. The account was disabled first, sessions were revoked second, and cleanup followed. The order matters because an attacker holding an active session token can keep operating in the mailbox even after a password reset. Inbox rules also persist independently of credentials, so resetting the password without removing the rules leaves the forwarding active.
All three inbox rules were deleted and forwarding was disabled. The phishing email was hard deleted from the mailbox with Approval ID 97983e logged in the action center. The sender address and both attacker domains were added to the Tenant Allow/Block List to block future delivery across the entire organisation.

---
<img width="894"  alt="image" src="https://github.com/user-attachments/assets/65e10c90-30f0-4500-b961-799182a7d571" />


---

<img width="800"  alt="image" src="https://github.com/user-attachments/assets/dc0e1fdc-a5cb-48ab-9929-02b64480efee" />


---

<img width="956"  alt="image" src="https://github.com/user-attachments/assets/2af4a359-2884-4751-9f0d-2afa555c20bd" />

---
<img width="800"  alt="image" src="https://github.com/user-attachments/assets/b282e000-8548-48ac-9e9d-ef0d579b1662" />


----



## Phase 10: Incident Closure

Incident 107 was closed as True Positive Phishing with all containment actions documented in the closure notes. The Conditional Access gap was escalated separately to the IAM team as a priority finding, with a recommendation to audit all C-suite and Finance accounts for CA policy scope and enforce phishing-resistant MFA as the authentication standard for those accounts.

---

<img width="2108" height="1282" alt="image" src="https://github.com/user-attachments/assets/095e7d87-f332-407f-a9e9-537e67ea24b5" />


---

## What Would Have Stopped This Attack

**Phishing-resistant MFA on the CFO account.** A FIDO2 security key or Windows Hello for Business would have made the harvested credential completely useless. The attacker had a valid username and password and still could not have authenticated. This is the single highest-impact control for preventing BEC credential compromise.

**DMARC enforcement on the receiving domain.** The phishing email came from a lookalike domain. Under a DMARC policy of p=reject, that email would have been refused by the receiving mail server before it ever reached the CFO inbox. The attack has no entry point if the lure never arrives.

**Conditional Access scoped to include all Finance and C-suite accounts.** The tenant had strong CA policies. The CFO account was excluded from all of them. CA policy scope audits should be a regular control, at minimum quarterly, to catch exclusions that have outlived their original justification.

**Inbox rule monitoring.** The three rules the attacker created would have been invisible without the custom detection rules deployed in Sentinel. A scheduled query checking for new inbox rules with external forwarding or keyword deletion, running every hour, surfaces this activity the same day it happens rather than weeks later when Finance notices money is missing.

**Payment verification procedures.** Technical controls stop most attacks. Business process controls stop the rest. A policy requiring a phone call to a known, verified number before processing any change to vendor payment details, regardless of how legitimate the email looks, breaks the final step in the BEC kill chain even when everything else fails.



## Lessons Learned

The CFO account had no MFA, no device compliance check, and no sign-in risk policy despite eleven active CA policies in the tenant. Any account with payment authority should be the first priority for identity protection, not an afterthought during policy rollout.
DMARC was in monitoring mode. Moving from p=none to p=reject takes less than an hour and permanently blocks an entire class of lookalike domain attacks.

Inbox rules survive password resets. A BEC response that stops at credential remediation leaves the attacker's forwarding rules running silently for days or weeks until someone notices the mail is going somewhere it should not.
Detection rules built before an attack and validated against real telemetry are far more reliable than rules written after the fact. The custom IAM sign-in rule created the incident automatically. The analyst did not find the compromise. The detection engineering did.



## Tools Used

Microsoft 365 E5 · Microsoft Entra ID · Microsoft Defender XDR · Microsoft Sentinel · Exchange Online · Attack Simulator · MXToolbox · KQL



## Author

Gbenga Abraham  
SOC and IAM Security Portfolio Project  
June 2026
