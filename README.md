# ServiceAccount-Audit

Service account security auditing for Active Directory environments.

## The Problem

Service accounts are the forgotten attack surface. They are created during application deployments, configured with "Password Never Expires," granted elevated privileges "just to get it working," and then never touched again. Years pass. The person who created the account leaves the company. The application may even be decommissioned, but the account persists -- enabled, privileged, with a password that has not changed since the Obama administration.

These accounts are everywhere:

- **Passwords set 5+ years ago** that no one has rotated because "it might break something"
- **In Domain Admins** because someone needed it to work quickly during a late-night deployment
- **Running on 20+ servers** with the same credential, meaning one compromise cascades everywhere
- **No documented owner** -- no one knows who is responsible or what the account actually does
- **Service Principal Names registered** making them trivially Kerberoastable by any authenticated user

This module finds them all and puts the risk in a single report.

## Why Kerberoasting Matters

Any authenticated domain user (including a compromised workstation) can request a Kerberos service ticket (TGS) for any Service Principal Name in the domain. The ticket is encrypted with the service account's NTLM password hash. The attacker takes that ticket offline and cracks it -- no lockout threshold, no failed login alerts, no detection.

If your service accounts have:
- SPNs registered on **user accounts** (not computer accounts)
- **RC4 encryption** enabled (or no encryption type specified, which defaults to RC4)
- **Old passwords** that were set when password complexity requirements were weaker

...then they are at serious risk. This module identifies every one of them.

## Quick Start

```powershell
# Import the module
Import-Module .\ServiceAccount-Audit.psd1

# Basic audit -- discover all service accounts in the domain
Get-ServiceAccountInventory

# Find accounts with dangerously old passwords
Get-ServiceAccountAge -DaysOldThreshold 730

# Check which servers are running these accounts
$servers = Get-ADComputer -Filter "OperatingSystem -like '*Server*'" | Select-Object -ExpandProperty Name
Get-ServiceAccountUsage -ComputerName $servers

# Find Kerberoastable accounts
Get-SPNReport

# Full audit with HTML dashboard
Invoke-ServiceAccountAudit `
    -ComputerName $servers `
    -OutputPath "C:\Reports\ServiceAccountAudit.html" `
    -DaysOldThreshold 365
```

## Functions

| Function | Purpose |
|---|---|
| `Invoke-ServiceAccountAudit` | Orchestrator. Runs all functions, generates HTML dashboard. |
| `Get-ServiceAccountInventory` | Discovers service accounts via name pattern, PasswordNeverExpires, Service Account OUs, and SPNs. |
| `Get-ServiceAccountAge` | Focused password age analysis with CRITICAL/HIGH/MEDIUM/LOW risk ratings. |
| `Get-ServiceAccountUsage` | Scans remote servers to find where service accounts are running as Windows services. |
| `Get-SPNReport` | Identifies Kerberoastable accounts -- user accounts with SPNs, weak encryption, old passwords. |

## Example Output

**Summary Cards**

```
Service Accounts: 47    Critical Passwords: 12    Kerberoastable: 8
Privileged: 6           No Owner: 31              Servers Scanned: 24
```

**Password Age Risk Ratings**

| Account | Password Age | Risk |
|---|---|---|
| svc-sqlprod | 1858 days (2021-01-15) | CRITICAL |
| svc-exchange | 2066 days (2020-06-22) | CRITICAL |
| svc-jenkins | 991 days (2023-06-01) | HIGH |
| svc-crm | 819 days (2023-11-20) | HIGH |

**Findings**

```
svc-sqlprod: PASSWORD OLD; NEVER EXPIRES; IN PRIVILEGED GROUP; NO OWNER; NO DESCRIPTION
svc-exchange: KERBEROASTABLE; WEAK ENCRYPTION; OLD PASSWORD + SPN; PASSWORD NEVER EXPIRES
svc-legacy-app: DISABLED BUT IN GROUPS (still in Backup Operators)
```

See `Samples/sample-report.html` for a complete HTML dashboard.

## Requirements

- **PowerShell 5.1** or later
- **ActiveDirectory RSAT module** (`Install-WindowsFeature RSAT-AD-PowerShell` on servers, or install RSAT from Windows Settings on workstations)
- **WinRM** enabled on target servers for remote service scanning (`Get-ServiceAccountUsage`)
- Account running the audit needs:
  - Read access to Active Directory (for account discovery)
  - Admin rights on target servers (for WinRM service enumeration)

## Design Decisions

**Read-only operations.** This module never modifies Active Directory, never changes passwords, never disables accounts. It is purely a reporting tool. The output tells you what to fix; you decide when and how to fix it.

**Combines AD data with live service scans.** Most AD audit tools only look at the directory. This module also connects to servers and checks what is actually running. An account might look benign in AD, but if it is running as a service on 21 SQL servers with a 5-year-old password, that context changes the risk calculus entirely.

**Multiple discovery strategies.** Service accounts are not always named `svc-*`. The module looks for accounts by name pattern, PasswordNeverExpires flag, placement in Service Account OUs, and presence of SPNs. This catches accounts that were created outside of naming conventions.

**Findings, not scores.** Instead of computing an opaque risk score, the module attaches concrete findings to each account: `PASSWORD OLD`, `IN PRIVILEGED GROUP`, `KERBEROASTABLE`, `NO OWNER`. These are actionable and auditable. You can filter, sort, and report on them directly.

## License

MIT License. See [LICENSE](LICENSE) for details.
