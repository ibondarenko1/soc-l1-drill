"""
Glossary: the entities an L1 must recognize on sight.
Used by /reference (full study page) and by study mode (annotates the alert
with only the entries that actually appear in it).

Covers the full corpus (93 templates): original Windows/PowerShell/Sysmon/
Defender/Sentinel set plus the expansion (lockout/spray, DCSync, NTDS, service
install, log clear, WMI/pipe/DNS/driver/DLL Sysmon events, LOLBins, and the
Entra identity attacks).
"""

import re

# key -> (pattern to detect in alert text, short title, explanation)
GLOSSARY = {
    # ---------- Windows Security — Event IDs ----------
    "4624": (r"EventID:\s*4624", "4624 — Successful logon",
        "An account logged on. Always read together with Logon Type and Source "
        "Network Address: WHO, from WHERE, HOW."),
    "4625": (r"EventID:\s*4625", "4625 — Failed logon",
        "Logon failure. One = noise. Dozens from one source at machine speed = "
        "brute force. Check whether a successful 4624 follows from the same source."),
    "4662": (r"EventID:\s*4662", "4662 — Directory object operation",
        "An operation on an AD object. The DCSync tell: a NON-DC account requesting "
        "DS-Replication-Get-Changes-All. Only real domain controllers should replicate."),
    "4672": (r"EventID:\s*4672", "4672 — Special privileges assigned",
        "A privileged (admin-equivalent) logon occurred. Fires constantly for "
        "service accounts — the signal is WHO and WHEN, not the event itself."),
    "4688": (r"EventID:\s*4688", "4688 — Process created",
        "New process with command line (if auditing enabled). Read parent -> child: "
        "who spawned whom is often the whole story."),
    "4720": (r"EventID:\s*4720", "4720 — User account created",
        "New account. Benign when IT does it inside a change window. Persistence "
        "when it happens off-hours + gets admin (4732) + password-never-expires (4738)."),
    "4728": (r"EventID:\s*4728", "4728 — Member added to global group",
        "Account added to a security-enabled GLOBAL group. Severity = the group: "
        "Remote Desktop Users during onboarding is noise; Domain Admins off-hours "
        "with no ticket is an incident."),
    "4732": (r"EventID:\s*4732|\b4732\b", "4732 — Member added to local group",
        "Account added to a LOCAL group. Added to Administrators right after account "
        "creation is a persistence pattern."),
    "4740": (r"EventID:\s*4740", "4740 — Account locked out",
        "Lockout after too many failures. One account looping = often a stale cached "
        "password on a phone. MANY accounts, one source, 1-2 tries each = password spray."),
    "1102": (r"EventID:\s*1102|audit log was cleared", "1102 — Security log cleared",
        "The Security event log was wiped. Almost no routine reason outside a "
        "documented reimage. Treat as anti-forensics; pull Sysmon/EDR for the gap."),
    "7045": (r"EventID:\s*7045|A new service was installed", "7045 — New service installed",
        "A service was installed. PSEXESVC or random 8-char names appearing across "
        "several hosts in an hour = PsExec-style lateral movement."),

    # ---------- Windows Security — Logon Types ----------
    "logon_type_2": (r"Logon Type:\s*2\b", "Logon Type 2 — Interactive",
        "Physically at the keyboard (or console). A brute force over the network "
        "cannot be Type 2."),
    "logon_type_3": (r"Logon Type:\s*3\b", "Logon Type 3 — Network",
        "Access over the network: SMB shares, some RDP configs, remote auth. "
        "Most brute-force attempts arrive as Type 3."),
    "logon_type_5": (r"Logon Type:\s*5\b", "Logon Type 5 — Service",
        "A service started under an account. Expected for service accounts; "
        "interactive logon by a service account is the anomaly, not this."),
    "logon_type_10": (r"Logon Type:\s*10\b", "Logon Type 10 — RemoteInteractive (RDP)",
        "A full RDP session. Ask: is the source IP inside the expected VPN/admin "
        "range, and does this account do RDP normally?"),
    "domain_admins": (r"Domain Admins", "Domain Admins group",
        "The crown-jewel AD group. Any add to it off-hours, from a non-admin host, "
        "or without a change ticket is high-severity until proven otherwise."),
    "dcsync": (r"DS-Replication|DCSync", "DS-Replication-Get-Changes (DCSync)",
        "The right to replicate directory changes = pull password hashes from the DC. "
        "Legitimately used only BY domain controllers. A user account doing it = domain compromise."),

    # ---------- Sysmon ----------
    "sysmon_1": (r"Sysmon EventID:\s*1\b", "Sysmon 1 — Process Create",
        "Like 4688 but richer: hashes, full parent chain. Parent->child is the key "
        "read: Office spawning cmd/powershell is a top phishing tell."),
    "sysmon_3": (r"Sysmon EventID:\s*3\b", "Sysmon 3 — Network Connection",
        "Which process talked to which IP:port. Regular-interval connections "
        "(every 60 s) = beaconing."),
    "sysmon_6": (r"Sysmon EventID:\s*6\b|Driver Loaded", "Sysmon 6 — Driver Loaded",
        "A kernel driver loaded. BYOVD: a validly-SIGNED but known-vulnerable driver "
        "(RTCore64, dbutil) loaded from Temp gives attackers kernel R/W to kill EDR. "
        "'Signed: true' is not a clearance here."),
    "sysmon_7": (r"Sysmon EventID:\s*7\b|Image Loaded", "Sysmon 7 — Image (DLL) Loaded",
        "A module loaded into a process. Sideloading: a signed exe in an odd folder "
        "loading an UNSIGNED DLL of the same name next to it. The signature on the exe "
        "is the decoy; the DLL is the payload."),
    "sysmon_8": (r"Sysmon EventID:\s*8\b", "Sysmon 8 — CreateRemoteThread",
        "One process created a thread inside another — the core of code injection. "
        "Very few legitimate producers."),
    "sysmon_10": (r"Sysmon EventID:\s*10\b", "Sysmon 10 — ProcessAccess",
        "One process opened a handle to another. The classic hunt: anything "
        "opening lsass.exe. Judged by GrantedAccess mask + who the source is."),
    "sysmon_11": (r"Sysmon EventID:\s*11\b", "Sysmon 11 — FileCreate",
        "File written. Watch executable drops in Temp/AppData and dump files "
        "like lsass.dmp."),
    "sysmon_13": (r"Sysmon EventID:\s*13\b", "Sysmon 13 — Registry value set",
        "Registry write. The persistence read: Run keys pointing at user-profile "
        "paths (AppData) impersonating system components."),
    "sysmon_17": (r"Sysmon EventID:\s*17\b|Pipe Created", "Sysmon 17 — Named Pipe Created",
        "A named pipe was created. Frameworks (Cobalt Strike) use default pipe names "
        "(msagent_##) for internal comms. Argless rundll32 hosting a matching pipe + "
        "jittered beacon = injected C2."),
    "sysmon_21": (r"Sysmon EventID:\s*21\b|WmiEvent|CommandLineEventConsumer", "Sysmon 21 — WMI Event Subscription",
        "A WMI consumer/filter binding. A CommandLineEventConsumer running hidden/"
        "encoded PowerShell at startup is stealth persistence that lives in the WMI "
        "repo, not on disk. Almost never a legit ad-hoc action."),
    "sysmon_22": (r"Sysmon EventID:\s*22\b|QueryName", "Sysmon 22 — DNS Query",
        "A process resolved a name. Thousands of high-entropy TXT lookups to a young "
        "domain = DNS tunneling. Random labels under a major CDN (A records, low "
        "volume, from a browser) = cache keys, not exfil."),
    "dns_txt": (r"QueryType:\s*TXT", "DNS TXT query",
        "TXT records carry arbitrary text — the preferred carrier for DNS tunneling. "
        "High volume of TXT queries with random subdomains is a strong exfil/C2 tell."),
    "granted_access": (r"GrantedAccess", "GrantedAccess — access mask",
        "What rights the handle got. Against lsass.exe: 0x1400 = query only "
        "(AV/EDR noise), 0x1010/0x1410/0x1FFFFF = memory read -> credential "
        "dumping intent."),
    "lsass": (r"lsass\.exe", "lsass.exe",
        "Holds credentials in memory. Reading its memory = stealing credentials. "
        "The only legitimate readers are signed security products with limited masks."),
    "vssadmin": (r"vssadmin|ntds\.dit|shadow", "vssadmin / shadow copy / NTDS.dit",
        "Volume shadow copies snapshot locked files. On a DC, 'vssadmin create shadow' "
        "then copying ntds.dit + the SYSTEM hive extracts every domain credential "
        "offline. On a workstation, 'delete shadows' precedes ransomware."),

    # ---------- PowerShell / LOLBins ----------
    "4104": (r"EventID:\s*4104", "4104 — PowerShell Script Block Logging",
        "The actual PowerShell code that ran, even if obfuscated or -EncodedCommand "
        "(it logs decoded). Your single best PowerShell visibility source."),
    "enc_flag": (r"-enc|EncodedCommand", "-EncodedCommand",
        "Base64-wrapped PowerShell. Legitimate automation sometimes uses it for "
        "quoting — DECODE first, then judge the CONTENT, not the flag alone."),
    "hidden_flag": (r"-w hidden|-WindowStyle Hidden", "-w hidden",
        "Hide the window from the user. Admin scripts don't care about being seen; "
        "malware does."),
    "nop_flag": (r"-nop|-NoProfile", "-nop",
        "Skip profile loading. Alone it's nothing; combined with -enc and "
        "-w hidden it completes the malware trio."),
    "iex_download": (r"IEX|Invoke-Expression|DownloadString", "IEX + DownloadString — download cradle",
        "Fetch code from the internet and execute it in memory, no file on disk. "
        "Near-zero legitimate use on user workstations."),
    "tcpclient": (r"TCPClient|Net\.Sockets", "TCPClient reverse shell",
        "New-Object Net.Sockets.TCPClient piped into iex is a reverse shell — a live "
        "interactive socket back to the attacker. No benign version on a user's box. "
        "Port 4444 = Metasploit default."),
    "certutil": (r"certutil", "certutil as downloader",
        "Certificate tool abused to download files (-urlcache -f URL). A signed "
        "Windows binary doing an attacker's job = LOLBin."),
    "rundll32_js": (r"rundll32.*javascript:", "rundll32 + javascript:",
        "Executing script via rundll32's protocol handler. No legitimate use. "
        "If you see it — that alone decides the verdict."),
    "regsvr32": (r"regsvr32|scrobj\.dll|\.sct", "regsvr32 + .sct (Squiblydoo)",
        "regsvr32 /i:http fetching a remote .sct scriptlet via scrobj.dll runs "
        "attacker script through a signed Windows binary. Essentially zero legit use."),
    "amsi": (r"amsiInitFailed|AmsiUtils", "AMSI bypass",
        "Disabling PowerShell's malware scanning interface via reflection. "
        "Only two producers: pentesters and attackers. Verify which one is on the calendar."),
    "defender_tamper": (r"Add-MpPreference|Set-MpPreference|ExclusionPath", "Defender exclusion (Add-MpPreference)",
        "Carving a scan exclusion. Benign from Intune/SCCM against a signed app dir; "
        "malicious from a user shell against a user-writable Temp path that then "
        "receives a payload. Origin + target path decide it."),
    "schtasks": (r"schtasks", "schtasks — scheduled task",
        "Persistence workhorse. Judged by what the task RUNS and from WHERE: "
        "Program Files + signed = software updater; AppData/Temp = suspect."),
    "psexec": (r"PSEXESVC|PsExec", "PsExec / PSEXESVC",
        "Remote execution tool. Legitimate for admins, but a PSEXESVC service "
        "appearing from a non-admin host and spreading across servers = lateral movement."),

    # ---------- Defender / EDR ----------
    "asr": (r"\bASR\b|Attack Surface Reduction", "ASR — Attack Surface Reduction rule",
        "Rules that block risky behaviour (e.g. Office spawning children). BLOCK mode "
        "prevents it (benign, contained); AUDIT mode only LOGS it — the payload still "
        "ran. Always check the mode before you close it."),
    "smartscreen": (r"SmartScreen", "SmartScreen reputation block",
        "Warned on a low-reputation download. Verdict rides on one pivot: did the user "
        "click through and RUN it, or dismiss it? No execution = benign."),
    "pua": (r"\bPUA\b|potentially unwanted", "PUA — potentially unwanted app",
        "Flags DUAL-USE tools (RustDesk, remote-admin), not confirmed malware. Same "
        "binary is benign on an approved IT host and an incident on a random workstation "
        "with external connections. Entirely context."),
    "eicar": (r"EICAR", "EICAR test file",
        "The industry-standard HARMLESS antivirus test string. If it's EICAR from a "
        "security-team validation, it's a false positive — not your own team's test "
        "turned into an incident."),
    "quarantine": (r"Quarantined|remediation", "Quarantine — did it run first?",
        "AV quarantined a real threat, so it is NOT a false positive. The one question "
        "that decides close vs escalate: was it blocked pre-execution (contained, benign) "
        "or did it run BEFORE detection? Check dwell time, egress, and persistence that "
        "survived the quarantine."),
    "ransomware": (r"\.locked|ransom|Data Encrypted|encryption", "Ransomware behaviour",
        "High-rate renames to a new extension + shadow-copy deletion + ransom notes + "
        "reach into mapped drives = live encryption. Highest urgency: isolate now, no "
        "'watch and confirm'."),

    # ---------- Identity / cloud (Sentinel / Entra) ----------
    "legacy_auth": (r"IMAP|legacy auth|legacy", "Legacy authentication (IMAP/POP/SMTP)",
        "Old protocols that cannot enforce MFA. A valid password + legacy auth "
        "= MFA silently bypassed. Top BEC entry path."),
    "inbox_rule": (r"inbox rule|forward all|forwarding rule", "Suspicious inbox rule",
        "Post-compromise classic: auto-forward or hide mail. Rule named like "
        "'RSS Feeds' forwarding externally = attacker maintaining access."),
    "token_replay": (r"token|MFA claim|replay", "Token theft / replay",
        "Session token stolen via AiTM phishing and reused. MFA was satisfied "
        "ONCE by the victim; password reset alone does not kill the token — "
        "sessions must be revoked."),
    "impossible_travel": (r"[Ii]mpossible travel", "Impossible travel",
        "Two sign-ins geographically impossible to combine. Verify before judging: "
        "corporate VPN/SWG egress IPs cause constant false positives. Same device "
        "ID + MFA on both legs usually = proxy artifact."),
    "oauth_consent": (r"OAuth|consent|Scopes:", "OAuth consent grant",
        "A user/admin granted an app delegated access. Consent-phishing: an unverified "
        "app with Mail.Read/Send + offline_access gets persistent mailbox access that "
        "bypasses password AND MFA. Revoke the grant, not just the password."),
    "mfa_fatigue": (r"MFA (push|request|notification|prompt)|push bombing", "MFA fatigue / push bombing",
        "Attacker has the password and spams MFA prompts until the user taps Approve. "
        "The tell: a burst the user did not initiate, then one approval, then a new "
        "authenticator device registered for persistence."),
    "conditional_access": (r"Conditional Access", "Conditional Access policy change",
        "The tenant-wide control enforcing MFA/device compliance. Disabling 'Require "
        "MFA' off-hours with no change ticket = attacker weakening auth. Crown-jewel change."),
    "pim_role": (r"\bPIM\b|Global Admin|privileged role|role assign", "Privileged role / PIM",
        "PIM grants privileged roles just-in-time with approval. A PERMANENT direct "
        "Global Admin grant that bypasses PIM, to a non-IT user, off-hours = attacker "
        "cementing tenant control."),
    "spray": (r"password spray|spray|distributed sign-in", "Password spray",
        "Few attempts against MANY accounts (vs many against one = brute force). "
        "Breadth of targeted accounts + one common source is the tell. Any SUCCESS "
        "turns it from noise into a foothold."),
    "external_share": (r"anonymous link|external sharing|anonymous 'anyone|guest", "Mass external sharing",
        "Bulk anonymous 'anyone with the link' shares of sensitive data, especially "
        "from an unusual session, = exfiltration through the sharing feature. Kill the "
        "links, revoke the session, involve DLP."),
    "service_principal": (r"service principal|sp-", "Service principal sign-in",
        "A non-human app identity. Signing in from an Azure datacenter range is EXPECTED "
        "for cloud automation — 'unfamiliar sign-in' fires because it compares against "
        "human geography. Match against the SP's baseline, scopes, and schedule."),
    "mass_delete": (r"file deletion|files deleted|Data Destruction", "Mass file deletion",
        "Before reacting to a bulk delete, verify where the files WENT. A folder MOVE "
        "shows matching creates elsewhere + an intact recycle bin (benign reorg); "
        "rename-to-extension / encryption patterns = ransomware. Check the CREATE side "
        "before the DELETE side."),

    # ---------- Windows Security — AD attacks & lateral movement (batch 2) ----------
    "4648": (r"EventID:\s*4648", "4648 — Explicit-credential logon",
        "A logon using explicitly-supplied creds (runas /netonly). Benign from an admin PAW; "
        "lateral movement when a normal user wields admin creds across many hosts."),
    "4698": (r"EventID:\s*4698", "4698 — Scheduled task created",
        "Judge by ACTION + TRIGGER: hidden/encoded PowerShell on a logon trigger = persistence; "
        "a signed vendor binary on a daily schedule = software."),
    "4738": (r"EventID:\s*4738", "4738 — User account changed",
        "Setting 'password never expires' / 'cannot change password' on a service or foothold "
        "account is persistence hardening."),
    "4769": (r"EventID:\s*4769", "4769 — Kerberos service ticket (Kerberoasting)",
        "Many requests for distinct SPNs with RC4 (0x17) in seconds = Kerberoasting (harvesting "
        "crackable service-account hashes for offline cracking)."),
    "4768": (r"EventID:\s*4768", "4768 — Kerberos TGT (AS-REP roasting)",
        "Pre-Auth Type 0 (not required) for multiple accounts from one host with RC4 = AS-REP "
        "roasting (crackable hashes of preauth-disabled accounts)."),
    "4776": (r"EventID:\s*4776", "4776 — NTLM validation (Pass-the-Hash)",
        "NTLM (not Kerberos) for a privileged account from a user host to many targets = "
        "pass-the-hash lateral movement."),
    "5145": (r"EventID:\s*5145", "5145 — Network share access check",
        "Rapid sequential C$/ADMIN$ access across many hosts = automated share enumeration "
        "(recon before lateral movement)."),
    "4964": (r"EventID:\s*4964", "4964 — Special-groups logon",
        "Logon by a member of a watched privileged group. Signal is WHO+WHERE+WHEN: PAW during "
        "a change window = expected; external/off-hours = suspect."),
    "runas": (r"runas|/netonly", "runas / explicit credentials",
        "Running a process under another account's creds. Normal from the admin PAW; suspicious "
        "when a standard user runs it against servers."),
    "rc4_downgrade": (r"0x17 \(RC4|RC4-HMAC", "RC4 (0x17) ticket downgrade",
        "Attackers force RC4 Kerberos tickets because they crack far faster than AES (0x12). "
        "Bulk RC4 service/TGT requests are the roasting signature."),
    "mshta": (r"mshta", "mshta — remote HTA execution",
        "mshta.exe running a remote http .hta is a signed-binary proxy-execution LOLBin with no "
        "legitimate desktop use; a common phishing step."),
    "wmic_node": (r"wmic|WMIC", "wmic — WMI query / remote exec",
        "Read-only WMI (Win32_Product) is inventory. `wmic /node ... process call create` "
        "launching hidden PowerShell is remote WMI lateral movement."),
    "bloodhound": (r"BloodHound|SharpHound|Get-Domain|PowerView", "BloodHound / PowerView — AD recon",
        "Graph collection mapping the path to Domain Admin. On a non-IT box it is adversary "
        "reconnaissance; the JSON/zip output is the artifact."),
    "ps_v2": (r"-version 2", "PowerShell -version 2 downgrade",
        "Forcing the v2 engine drops AMSI and modern script-block logging so later commands run "
        "unseen. On a user desktop it is evasion, not compatibility."),

    # ---------- Sysmon (batch 2) ----------
    "sysmon_2": (r"Sysmon EventID:\s*2\b|creation time", "Sysmon 2 — File creation time changed",
        "Timestomping: backdating a freshly-dropped file to blend with OS files and defeat "
        "timeline analysis. Nothing legitimate rewrites creation times to the past."),
    "sysmon_9": (r"Sysmon EventID:\s*9\b|RawAccessRead", "Sysmon 9 — Raw disk access",
        "Reading the raw volume (\\\\.\\C:) bypasses file locks to grab ntds.dit / hives. On a "
        "DC by an unusual binary = direct-volume credential theft."),
    "sysmon_15": (r"Sysmon EventID:\s*15\b|FileCreateStreamHash", "Sysmon 15 — Alternate data stream",
        "An executable written into an NTFS ADS (file:stream) hides from tools scanning only the "
        "primary file. Execution from a stream is defense evasion."),
    "sysmon_25": (r"Sysmon EventID:\s*25\b|Process Tampering", "Sysmon 25 — Process tampering",
        "Hollowing/herpaderping: a suspended trusted process's image is replaced so malicious "
        "code runs under a legitimate name (svchost from a Temp parent)."),

    # ---------- Defender / EDR (batch 2) ----------
    "tamper_protection": (r"Tamper Protection", "Tamper Protection",
        "Guard that blocks changes to Defender's own settings. A BLOCKED disable attempt is "
        "good, but the attempt means active malware is trying to blind AV — escalate."),
    "cfa": (r"Controlled Folder Access", "Controlled Folder Access (anti-ransomware)",
        "Blocks unauthorized writes to protected folders. A high-rate block is live ransomware; "
        "it does NOT cover mapped drives, so a block is not full containment."),
    "network_protection": (r"Network Protection", "Network Protection (C2 block)",
        "Blocks connections to malicious domains. A blocked C2 callback means an implant is "
        "already resident and beaconing — the block stops egress, not the infection."),

    # ---------- Identity / Cloud (batch 2) ----------
    "tor_anon": (r"Tor|anonymous IP|anonymizer|anonymizing", "Anonymizer / Tor sign-in",
        "Sign-in from Tor / an anonymizing network hides the attacker. A SUCCESSFUL one, "
        "especially with a new MFA method registered after, is account takeover."),
    "golden_saml": (r"federat|MsolDomainAuthentication|Golden SAML|IssuerUri|signing cert", "Federation change (Golden SAML)",
        "Adding an attacker-controlled federation config / token-signing cert lets the adversary "
        "forge SAML tokens for ANY user — full tenant impersonation."),
    "app_secret": (r"client secret|new secret|app registration", "Credential added to app registration",
        "A new secret/cert on a privileged app registration is a durable, MFA-immune backdoor "
        "identity — especially on an app with tenant-wide Graph write."),
    "azure_owner": (r"Role: Owner|Azure role assignment|/subscriptions/", "Azure RBAC role assignment",
        "Owner at subscription/management-group scope is full control of the cloud estate. A "
        "direct grant outside PIM, off-hours, to a non-cloud user is an incident."),
    "keyvault": (r"Key Vault|SecretGet|kv-prod", "Key Vault access",
        "Bulk SecretGet from one principal in minutes = secret harvesting; the retrieved keys "
        "enable broad onward access. Rotate what was read."),
    "storage_public": (r"public blob|public access|anonymous read", "Storage public exposure",
        "Enabling public/anonymous blob access exposes cloud data. If external anonymous reads "
        "follow the change, exfiltration is already happening."),
    "4103": (r"EventID:\s*4103", "4103 — PowerShell Module Logging",
        "Logs pipeline/module execution. Captures a lot of benign automation (DSC, config mgmt); "
        "judge by the cmdlets + context, not the mere presence of logging."),
    "risky_signin": (r"risky sign-in|leaked credential|Risk:\s*'Leaked|risk detection", "Entra risk detection",
        "A risk signal (leaked creds / unfamiliar sign-in). A since-reset password + MFA + the "
        "user's normal device = remediated/benign; unusual origin + a new MFA method = live compromise."),
}


def annotate(alert_text):
    """Return glossary entries that actually appear in the given alert."""
    hits = []
    for key, (pattern, title, expl) in GLOSSARY.items():
        if re.search(pattern, alert_text, re.IGNORECASE):
            hits.append({"title": title, "expl": expl})
    return hits


# grouping for the /reference page
REFERENCE_SECTIONS = [
    ("Windows Security — Event IDs",
     ["4624", "4625", "4662", "4672", "4688", "4720", "4728", "4732", "4740", "1102", "7045"]),
    ("Windows Security — Logon Types & AD",
     ["logon_type_2", "logon_type_3", "logon_type_5", "logon_type_10", "domain_admins", "dcsync"]),
    ("Sysmon",
     ["sysmon_1", "sysmon_3", "sysmon_6", "sysmon_7", "sysmon_8", "sysmon_10", "sysmon_11",
      "sysmon_13", "sysmon_17", "sysmon_21", "sysmon_22", "dns_txt", "granted_access", "lsass", "vssadmin"]),
    ("PowerShell & LOLBins",
     ["4104", "4103", "enc_flag", "hidden_flag", "nop_flag", "iex_download", "tcpclient", "certutil",
      "rundll32_js", "regsvr32", "amsi", "defender_tamper", "schtasks", "psexec"]),
    ("Defender / EDR",
     ["asr", "smartscreen", "pua", "eicar", "quarantine", "ransomware"]),
    ("Identity / Cloud (Sentinel / Entra)",
     ["legacy_auth", "inbox_rule", "token_replay", "impossible_travel", "oauth_consent",
      "mfa_fatigue", "conditional_access", "pim_role", "spray", "external_share",
      "mass_delete", "service_principal"]),
    ("AD attacks & lateral movement",
     ["4648", "4698", "4738", "4769", "4768", "4776", "5145", "4964", "runas",
      "rc4_downgrade", "mshta", "wmic_node", "bloodhound", "ps_v2"]),
    ("Sysmon & Defender (advanced)",
     ["sysmon_2", "sysmon_9", "sysmon_15", "sysmon_25", "tamper_protection",
      "cfa", "network_protection"]),
    ("Cloud identity & Azure (advanced)",
     ["tor_anon", "golden_saml", "app_secret", "azure_owner", "keyvault", "storage_public", "risky_signin"]),
]


def reference_data():
    out = []
    for section, keys in REFERENCE_SECTIONS:
        items = [{"title": GLOSSARY[k][1], "expl": GLOSSARY[k][2]} for k in keys]
        out.append({"section": section, "items": items})
    return out
