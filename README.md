# SOC-Analyst-Portfolio-Project
Phishing URL Investigation &amp; Threat Scoring Report



## Project Overview

**Objective:**  
Investigate potentially malicious URLs extracted from phishing emails and assess the threat level based on redirection behavior, payloads, reputation, and indicators of compromise (IOCs).

**Tools Used:**
- [URLScan.io](https://urlscan.io)
- [VirusTotal](https://www.virustotal.com)
- [ExpandURL.net](https://expandurl.it)
- [CyberChef](https://gchq.github.io/CyberChef/)
- [URL2PNG](https://www.url2png.com)

---

## Email Sample Summary

| **Field**             | **Details** |
|-----------------------|-------------|
| **Subject:**          |  Find out how to make your Lumens grow with our latest network feature - Staking   
| **From:**             | "Stellar.org Team" <no-reply@comparisonadvantage.com.au>  
| **To:**               | phishing@pot  
| **Date Received:**    | Thu, 17 Nov 2022 22:27:12 +0000 (UTC) 
| **Attachment Present:** | No  
| ** Return Path:**	| bounces+8833677-41da-phishing@pot=hotmail.com@em3813.comparisonadvantage.com.au
| **Phishing Theme:**   | Join Stellar Staking 
| **X-Sender-IP:**	| 149.72.218.220
| **Resolve Host:**	| wrqvdxdc.outbound-mail.sendgrid.net 

---

## Extracted URLs

| **Original URL in Defanged Version*** 		| **Notes**		|
|-------------------------------|----------------------|
| hxxps[://]bit[.]ly/3FLcDKL?480442  | Found in email body	|  
| hxxp[://]mails1-redirect[.]in/18  | Shortened redirect   	| 

---

## URL Investigation & Tool Results

### **1. VirusTotal Analysis**
**URL:** `hxxps[://]bit[.]ly/3FLcDKL?480442`  
- **Reputation Score:** 2/91 security vendors flagged this URL as malicious  
- **Detected By:** Criminal IP, and Trustwave.  
- **Category:** web hosting / web applications  / Information Technology  
- **Link to VirusTotal Report:** [View Report](https://shorturl.at/Uxixw)

### **2. URLScan.io Results**
- **Live Rendered Page:** We could not scan this website! 
- **More Details:** Take a look at the [JSON output](https://urlscan.io/api/v1/result/01963985-4da2-73ba-9785-07c8219673c2/)or the screenshot to determine a possible cause.   
- **Redirect Chains:** Shortener → obfuscated domain  
- **Report Link:** [View Scan](https://urlscan.io/result/01963985-4da2-73ba-9785-07c8219673c2/)

### **3. ExpandedURL.net Results**
- **Final Destination URL:** `hxxp[://]mails1-redirect[.]in/18`
- **Initial URL:** `hxxps[://]bit[.]ly/3FLcDKL?480442`

### ✅ **4. CyberChef Analysis**
- **Decoded JS Payload:** Hidden `<form>` action sending credentials to C2 server.
- **Encoded Elements Detected:** Hex, Base64 obfuscation used to hide phishing form.

### **5. URL2PNG Results**
- **Screenshot Capture:** URL2PNG provided a live image of the phishing site  
- **Observation:** Clearly displays a fake login form imitating a trusted brand 
- **Threat Indication:** Visual confirmation of phishing attempt targeting user credentials 

---

## Threat Scoring

| **Scoring Criteria**                   | **Evidence Found?** | **Tools**   | **Notes** |
|----------------------------------------|------------|----------------------|------------|
| Domain reputation flagged              | Yes     | VirusTotal         |  2/91 security vendors flagged this URL as malicious          |
| Redirects through shortener or iframe  | Yes     | ExpandURL.net, URLScan.io | Suspicious behavior |
| Mimics login page                      | Yes     | URL2PNG Screenshot        | Visual shows fake login interface  |
| Credential harvesting script detected  | Yes     | CyberChef                 | Base64-decoded form action to C2 |
| Listed on threat intel platforms	 | Yes     | VirusTotal       	       | Verified phishing by Criminal IP and Trustwave security vendors  |

> **Final Threat Score: 5 / 5 – High Risk Phishing URL**

---

## Screenshot Evidence

**Phishing Email Body/Headers**  
![Thunderbird Screenshot](https://github.com/user-attachments/assets/b2f56e7f-01d0-4463-b0e9-63dd2292dcda)
![Ubuntu Terminal Screenshot](https://github.com/user-attachments/assets/3b851572-2bef-414f-af0b-d774a3fb7608)
![Thunderbird Screenshot](https://github.com/user-attachments/assets/75495882-acc5-4a6b-8da7-b256cc6a112e)

**URLScan.io Page Rendering**  
![URLScan Screenshot](https://github.com/user-attachments/assets/37d1d86d-1926-4359-8009-6fdfd3af5130)
![URLScan/JSON Screenshot](https://github.com/user-attachments/assets/ede1cda1-e99e-4718-984f-984e7ab7c7de)

**ExpandURL.net Page Rendering**  
![ Expand   Check Shortened URLs - ExpandURL](https://github.com/user-attachments/assets/892fb0c1-792f-4056-b757-8ec9fdedd9be)

**VirusTotal Detection Graph**  
![VirusTotal Screenshot](https://github.com/user-attachments/assets/a938556a-eed0-4c4f-90b2-4fac3a0ff4f2)

**URL2PNG Fake Login Page UI**  
![Fake Login URL2PNG Screenshot](https://github.com/user-attachments/assets/d72d155b-c6fb-437a-a896-cec405b962ab)


---

## Analyst Notes

- The email uses excitement and urgency ("3..2..1 Launch") to push recipients into quick action by claiming limited staking slots and early high rewards.

- The message impersonates The Stellar Foundation, a legitimate blockchain organization, to gain credibility and trust from unsuspecting users.

- It contains a prominent "Join Stellar Staking" call-to-action, which likely redirects to a fake login or wallet connection page designed to harvest credentials or keys.

- Phrases like "proportionally higher rewards" and "first-come, first-serve" create FOMO (Fear of Missing Out), a common phishing tactic to increase click rates.

- The inclusion of a disclaimer and safety policy gives the appearance of legitimacy, while cleverly diverting suspicion from the actual phishing attempt

---

## Recommended Defense Actions

1. **Block domains and IPs** linked to the phishing site across email, firewall, and web filtering systems..
2. **Alert users** about crypto-themed phishing scams impersonating Stellar and offering fake staking rewards.
3. **Submit IOCs** (URLs, domains) to the threat intelligence platform for correlation and detection..
4. **Use URL sample** in phishing awareness training to highlight crypto-related social engineering tactics.
5. **Monitor for future phishing activity** including fake staking schemes and crypto brand impersonation.

---

## Report Metadata

| **Analyst Name:**   | Martin Bassey         |
|---------------------|--------------------------|
| **Date of Analysis:**| 2025-April-16              |
| **Project Type:**    | SOC Analyst Portfolio Project |
| **Tools Used:**      | See tools list above    |
| **Repository Link:** | [GitHub Project Link](https://github.com/yourrepo) |

---
