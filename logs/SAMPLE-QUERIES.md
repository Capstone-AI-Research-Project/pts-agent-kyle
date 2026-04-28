# CASA Sample Log Test Queries

Pair each query below with its corresponding log file(s) when submitting to Open WebUI.
For dual-input workflows (host + network), attach both log files with a single query.

---

## 1. Auth Anomaly
**Attach:** `auth-anomaly-host.log` + `auth-anomaly-network.log`

> We're seeing a spike in failed login events from several external IPs hitting our RDS gateway and SSH endpoints. At least one account appears to have been successfully compromised after repeated brute force attempts. The attacker may have used the compromised credentials to access internal systems. Please analyze the authentication logs and network connection data for indicators of credential stuffing or password spray activity.

---

## 2. Beaconing
**Attach:** `beaconing-network.log`

> Our IDS flagged periodic outbound HTTPS connections from WS-FIN04 to an external IP at roughly 60-second intervals. We're also seeing unusual DNS queries to domains that look algorithmically generated, including some TXT record lookups with encoded subdomains. Can you analyze this network traffic for signs of C2 beacon activity or DNS tunneling?

---

## 3. Exfiltration
**Attach:** `exfiltration-host.log` + `exfiltration-network.log`

> We noticed unusual after-hours activity between 2am and 4am on a Finance workstation. The host logs show large file archiving operations and a USB device insertion, while the network logs show significant outbound data transfers to cloud storage providers like Dropbox and Mega. Please investigate whether sensitive data was staged and exfiltrated from the network.

---

## 4. Lateral Movement
**Attach:** `lateral-movement-host.log` + `lateral-movement-network.log`

> A compromised workstation in Marketing appears to be the source of unusual east-west traffic across our internal network. We're seeing the same admin credentials authenticating to file servers, database servers, and domain controllers in rapid succession. The network team flagged SMB and RDP connections between hosts that don't normally communicate. Analyze these logs for lateral movement patterns.

---

## 5. Privilege Escalation
**Attach:** `privilege-escalation-host.log` + `privilege-escalation-network.log`

> A standard user account on WS-DEV03 suddenly started receiving special privilege assignments and spawning elevated processes. We suspect UAC bypass techniques may have been used, and our Linux admin noticed suspicious sudo commands on one of the web servers. Please review the process creation and privilege assignment events for evidence of privilege escalation.

---

## 6. Persistence
**Attach:** `persistence-host.log` + `persistence-network.log`

> During an incident response sweep, we discovered new scheduled tasks, registry Run key modifications, and a suspicious service installation on multiple hosts. One of our Linux servers also has unexpected cron entries. We need to determine what persistence mechanisms the attacker established and whether any backdoors are still active. Analyze the attached host and network logs.

---

## 7. Ransomware
**Attach:** `ransomware-host.log` + `ransomware-network.log`

> We have a critical incident. Shadow copies were deleted, boot recovery was disabled, and files across multiple network shares are being renamed with an .encrypted extension. Ransom notes titled README_TO_DECRYPT.txt are appearing in every directory. We also suspect data was exfiltrated before the encryption started. Please perform a full analysis of the attack timeline and identify indicators of the ransomware variant.

---

## 8. Insider Threat
**Attach:** `insider-threat-host.log` + `insider-threat-network.log`

> HR flagged a Finance employee who recently submitted their resignation and is reportedly joining a competitor. We're seeing this user accessing file shares outside their department scope during after-hours sessions, and large volumes of data appear to have been copied to USB and uploaded to personal cloud storage. Investigate the attached logs for policy violations and potential data theft.

---

## 9. Vulnerability Exploitation
**Attach:** `vulnerability-exploitation-host.log` + `vulnerability-exploitation-network.log`

> Our web server SRV-WEB01 started returning 500 errors after what appears to be an external scanning campaign. Shortly after, we detected cmd.exe processes being spawned by the web service, and a suspicious .aspx file appeared in the uploads directory. The attacker may have exploited a known vulnerability to gain remote code execution. Analyze the web server and network logs for the exploitation chain.

---

## 10. Comprehensive — APT Campaign
**Attach:** `comprehensive-01-apt-campaign.log`

> Something is wrong across multiple systems. We found a web shell on a public-facing server, internal hosts are communicating over SMB in unusual patterns, new registry entries appeared on several workstations, and there's a large outbound data transfer that happened after hours last night. We need a full investigation — this may be a coordinated campaign.

---

## 11. Comprehensive — Ransomware Incident
**Attach:** `comprehensive-02-ransomware-incident.log`

> Multiple alerts fired overnight. It started with a burst of failed login attempts against the admin accounts, then someone managed to get elevated privileges, and now files on the shared drives are encrypted. The security log on one of the servers was cleared. We need to understand the full timeline from initial access to encryption.

---

## 12. Comprehensive — Insider Exfiltration
**Attach:** `comprehensive-03-insider-exfil.log`

> We're investigating an employee who may be stealing company data. There are failed logins from an unusual IP that could be their personal device, after-hours access to file shares they shouldn't be touching, and what looks like bulk data uploads to external cloud services. Determine the full scope of unauthorized access and data loss.

---

## 13. Comprehensive — Supply Chain
**Attach:** `comprehensive-04-supply-chain.log`

> After a vendor software update last week, one of our servers started making periodic outbound connections to an unfamiliar domain. We also found suspicious files in the web root and unusual SMB traffic spreading across the internal network. Could this be a supply chain compromise? Analyze the network and host indicators.

---

## 14. Comprehensive — Full Spectrum
**Attach:** `comprehensive-05-full-spectrum.log`

> We're seeing a mess of alerts across the board — failed authentication attempts, what looks like regular beacon traffic to an external C2, data being staged and compressed for exfil, new cron jobs on Linux boxes, and now files are getting encrypted on the file server. We need a comprehensive analysis of everything happening — this might be a full-blown breach from initial access through ransomware deployment.
