BeforeAll {
    $ModuleRoot = Split-Path -Path $PSScriptRoot -Parent
    $ModuleName = 'ServiceAccount-Audit'
    $ManifestPath = Join-Path -Path $ModuleRoot -ChildPath "$ModuleName.psd1"

    # Remove module if already loaded, then import fresh
    Get-Module -Name $ModuleName -ErrorAction SilentlyContinue | Remove-Module -Force
    Import-Module $ManifestPath -Force -ErrorAction Stop
}

AfterAll {
    Get-Module -Name 'ServiceAccount-Audit' -ErrorAction SilentlyContinue | Remove-Module -Force
}

Describe 'Module: ServiceAccount-Audit' {

    Context 'Module Loading' {

        It 'Should import without errors' {
            $Module = Get-Module -Name 'ServiceAccount-Audit'
            $Module | Should -Not -BeNullOrEmpty
        }

        It 'Should export exactly 5 public functions' {
            $Module = Get-Module -Name 'ServiceAccount-Audit'
            $Module.ExportedFunctions.Count | Should -Be 5
        }

        It 'Should export Invoke-ServiceAccountAudit' {
            $Module = Get-Module -Name 'ServiceAccount-Audit'
            $Module.ExportedFunctions.Keys | Should -Contain 'Invoke-ServiceAccountAudit'
        }

        It 'Should export Get-ServiceAccountInventory' {
            $Module = Get-Module -Name 'ServiceAccount-Audit'
            $Module.ExportedFunctions.Keys | Should -Contain 'Get-ServiceAccountInventory'
        }

        It 'Should export Get-ServiceAccountAge' {
            $Module = Get-Module -Name 'ServiceAccount-Audit'
            $Module.ExportedFunctions.Keys | Should -Contain 'Get-ServiceAccountAge'
        }

        It 'Should export Get-ServiceAccountUsage' {
            $Module = Get-Module -Name 'ServiceAccount-Audit'
            $Module.ExportedFunctions.Keys | Should -Contain 'Get-ServiceAccountUsage'
        }

        It 'Should export Get-SPNReport' {
            $Module = Get-Module -Name 'ServiceAccount-Audit'
            $Module.ExportedFunctions.Keys | Should -Contain 'Get-SPNReport'
        }

        It 'Should not export private functions' {
            $Module = Get-Module -Name 'ServiceAccount-Audit'
            $Module.ExportedFunctions.Keys | Should -Not -Contain 'New-HtmlDashboard'
        }
    }

    Context 'Manifest Validation' {

        It 'Should have a valid manifest' {
            { Test-ModuleManifest -Path $ManifestPath -ErrorAction Stop } | Should -Not -Throw
        }

        It 'Should have the correct GUID' {
            $Manifest = Test-ModuleManifest -Path $ManifestPath
            $Manifest.GUID.ToString() | Should -Be 'b2c3d4e5-9f80-4b6c-ad7e-3f4a5b6c7d8e'
        }

        It 'Should require PowerShell 5.1' {
            $Manifest = Test-ModuleManifest -Path $ManifestPath
            $Manifest.PowerShellVersion.ToString() | Should -Be '5.1'
        }

        It 'Should have the correct author' {
            $Manifest = Test-ModuleManifest -Path $ManifestPath
            $Manifest.Author | Should -BeLike '*Larry Roberts*'
        }

        It 'Should have security-related tags' {
            $Manifest = Test-ModuleManifest -Path $ManifestPath
            $Manifest.PrivateData.PSData.Tags | Should -Contain 'Security'
            $Manifest.PrivateData.PSData.Tags | Should -Contain 'ServiceAccount'
            $Manifest.PrivateData.PSData.Tags | Should -Contain 'SPN'
        }

        It 'Should have a ProjectUri' {
            $Manifest = Test-ModuleManifest -Path $ManifestPath
            $Manifest.PrivateData.PSData.ProjectUri | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Parameter Validation' {

        It 'Invoke-ServiceAccountAudit should have SearchBase parameter' {
            $Cmd = Get-Command -Name 'Invoke-ServiceAccountAudit'
            $Cmd.Parameters.Keys | Should -Contain 'SearchBase'
        }

        It 'Invoke-ServiceAccountAudit should have ComputerName parameter as string array' {
            $Cmd = Get-Command -Name 'Invoke-ServiceAccountAudit'
            $Cmd.Parameters['ComputerName'].ParameterType.Name | Should -Be 'String[]'
        }

        It 'Invoke-ServiceAccountAudit should have OutputPath parameter' {
            $Cmd = Get-Command -Name 'Invoke-ServiceAccountAudit'
            $Cmd.Parameters.Keys | Should -Contain 'OutputPath'
        }

        It 'Invoke-ServiceAccountAudit DaysOldThreshold should default to 365' {
            $Cmd = Get-Command -Name 'Invoke-ServiceAccountAudit'
            $Cmd.Parameters['DaysOldThreshold'].DefaultValue | Should -Be 365
        }

        It 'Invoke-ServiceAccountAudit should have IncludeMSA switch' {
            $Cmd = Get-Command -Name 'Invoke-ServiceAccountAudit'
            $Cmd.Parameters['IncludeMSA'].SwitchParameter | Should -BeTrue
        }

        It 'Get-ServiceAccountInventory NamingPattern should default to svc*,service*' {
            $Cmd = Get-Command -Name 'Get-ServiceAccountInventory'
            $Cmd.Parameters['NamingPattern'].DefaultValue | Should -Be 'svc*,service*'
        }

        It 'Get-ServiceAccountInventory should have IncludeMSA switch' {
            $Cmd = Get-Command -Name 'Get-ServiceAccountInventory'
            $Cmd.Parameters['IncludeMSA'].SwitchParameter | Should -BeTrue
        }

        It 'Get-ServiceAccountInventory should have IncludeGMSA switch' {
            $Cmd = Get-Command -Name 'Get-ServiceAccountInventory'
            $Cmd.Parameters['IncludeGMSA'].SwitchParameter | Should -BeTrue
        }

        It 'Get-ServiceAccountAge DaysOldThreshold should default to 365' {
            $Cmd = Get-Command -Name 'Get-ServiceAccountAge'
            $Cmd.Parameters['DaysOldThreshold'].DefaultValue | Should -Be 365
        }

        It 'Get-ServiceAccountUsage ComputerName should be mandatory' {
            $Cmd = Get-Command -Name 'Get-ServiceAccountUsage'
            $Cmd.Parameters['ComputerName'].Attributes |
                Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] } |
                ForEach-Object { $_.Mandatory } |
                Should -Contain $true
        }

        It 'Get-ServiceAccountUsage ComputerName should accept string array' {
            $Cmd = Get-Command -Name 'Get-ServiceAccountUsage'
            $Cmd.Parameters['ComputerName'].ParameterType.Name | Should -Be 'String[]'
        }

        It 'Get-SPNReport should have IncludeComputers switch' {
            $Cmd = Get-Command -Name 'Get-SPNReport'
            $Cmd.Parameters['IncludeComputers'].SwitchParameter | Should -BeTrue
        }
    }

    Context 'Get-ServiceAccountInventory Mock Tests' {

        BeforeAll {
            # Build mock AD user objects
            $MockServiceAccounts = @(
                # Old password, no owner, no description, in privileged group
                [PSCustomObject]@{
                    SAMAccountName       = 'svc-sqlprod'
                    DisplayName          = 'SQL Production Service'
                    DistinguishedName    = 'CN=svc-sqlprod,OU=ServiceAccounts,DC=contoso,DC=com'
                    Enabled              = $true
                    PasswordLastSet      = (Get-Date).AddDays(-1825)
                    PasswordNeverExpires = $true
                    LastLogonDate        = (Get-Date).AddDays(-1)
                    MemberOf             = @('CN=Domain Admins,CN=Users,DC=contoso,DC=com')
                    ServicePrincipalName = @('MSSQLSvc/sql01.contoso.com:1433')
                    Description          = $null
                    ManagedBy            = $null
                    ObjectClass          = 'user'
                    'msDS-ManagedPasswordInterval' = $null
                }
                # Disabled but still in groups
                [PSCustomObject]@{
                    SAMAccountName       = 'svc-legacy'
                    DisplayName          = 'Legacy Service'
                    DistinguishedName    = 'CN=svc-legacy,OU=ServiceAccounts,DC=contoso,DC=com'
                    Enabled              = $false
                    PasswordLastSet      = (Get-Date).AddDays(-2000)
                    PasswordNeverExpires = $true
                    LastLogonDate        = (Get-Date).AddDays(-400)
                    MemberOf             = @('CN=Backup Operators,CN=Builtin,DC=contoso,DC=com')
                    ServicePrincipalName = $null
                    Description          = 'Old backup service'
                    ManagedBy            = $null
                    ObjectClass          = 'user'
                    'msDS-ManagedPasswordInterval' = $null
                }
                # Clean account (recent password, has owner, has description)
                [PSCustomObject]@{
                    SAMAccountName       = 'svc-webapp'
                    DisplayName          = 'Web Application Service'
                    DistinguishedName    = 'CN=svc-webapp,OU=ServiceAccounts,DC=contoso,DC=com'
                    Enabled              = $true
                    PasswordLastSet      = (Get-Date).AddDays(-30)
                    PasswordNeverExpires = $false
                    LastLogonDate        = (Get-Date).AddDays(-1)
                    MemberOf             = @('CN=WebAppPool,OU=Groups,DC=contoso,DC=com')
                    ServicePrincipalName = $null
                    Description          = 'IIS App Pool identity for web app'
                    ManagedBy            = 'CN=John Smith,OU=Users,DC=contoso,DC=com'
                    ObjectClass          = 'user'
                    'msDS-ManagedPasswordInterval' = $null
                }
            )

            Mock Get-ADUser -ModuleName 'ServiceAccount-Audit' -MockWith {
                param($Filter, $Identity, $Properties, $SearchBase)
                if ($Identity) {
                    return $MockServiceAccounts | Where-Object { $_.SAMAccountName -eq $Identity }
                }
                return $MockServiceAccounts
            }

            Mock Get-ADOrganizationalUnit -ModuleName 'ServiceAccount-Audit' -MockWith {
                return @()
            }

            Mock Get-ADServiceAccount -ModuleName 'ServiceAccount-Audit' -MockWith {
                return @()
            }
        }

        It 'Should return discovered service accounts' {
            $Results = Get-ServiceAccountInventory
            $Results | Should -Not -BeNullOrEmpty
            $Results.Count | Should -BeGreaterOrEqual 1
        }

        It 'Should flag PASSWORD OLD for accounts with old passwords' {
            $Results = Get-ServiceAccountInventory
            $OldAccount = $Results | Where-Object { $_.SAMAccountName -eq 'svc-sqlprod' }
            $OldAccount.Finding | Should -Match 'PASSWORD OLD'
        }

        It 'Should flag NEVER EXPIRES for PasswordNeverExpires accounts' {
            $Results = Get-ServiceAccountInventory
            $NeverExpires = $Results | Where-Object { $_.SAMAccountName -eq 'svc-sqlprod' }
            $NeverExpires.Finding | Should -Match 'NEVER EXPIRES'
        }

        It 'Should flag IN PRIVILEGED GROUP for Domain Admins membership' {
            $Results = Get-ServiceAccountInventory
            $Privileged = $Results | Where-Object { $_.SAMAccountName -eq 'svc-sqlprod' }
            $Privileged.Finding | Should -Match 'IN PRIVILEGED GROUP'
        }

        It 'Should flag NO OWNER for accounts without ManagedBy' {
            $Results = Get-ServiceAccountInventory
            $NoOwner = $Results | Where-Object { $_.SAMAccountName -eq 'svc-sqlprod' }
            $NoOwner.Finding | Should -Match 'NO OWNER'
        }

        It 'Should flag NO DESCRIPTION for accounts without Description' {
            $Results = Get-ServiceAccountInventory
            $NoDesc = $Results | Where-Object { $_.SAMAccountName -eq 'svc-sqlprod' }
            $NoDesc.Finding | Should -Match 'NO DESCRIPTION'
        }

        It 'Should flag DISABLED BUT IN GROUPS for disabled accounts with group membership' {
            $Results = Get-ServiceAccountInventory
            $Disabled = $Results | Where-Object { $_.SAMAccountName -eq 'svc-legacy' }
            $Disabled.Finding | Should -Match 'DISABLED BUT IN GROUPS'
        }

        It 'Should detect HasSPN for accounts with ServicePrincipalName' {
            $Results = Get-ServiceAccountInventory
            $WithSPN = $Results | Where-Object { $_.SAMAccountName -eq 'svc-sqlprod' }
            $WithSPN.HasSPN | Should -BeTrue
        }

        It 'Should calculate PasswordAge correctly' {
            $Results = Get-ServiceAccountInventory
            $Account = $Results | Where-Object { $_.SAMAccountName -eq 'svc-sqlprod' }
            $Account.PasswordAge | Should -BeGreaterThan 1800
        }
    }

    Context 'Get-ServiceAccountAge Mock Tests' {

        BeforeAll {
            $Now = Get-Date

            $MockAgeAccounts = @(
                # CRITICAL: >3 years old
                [PSCustomObject]@{
                    SAMAccountName       = 'svc-ancient'
                    DisplayName          = 'Ancient Service'
                    DistinguishedName    = 'CN=svc-ancient,OU=ServiceAccounts,DC=contoso,DC=com'
                    Enabled              = $true
                    PasswordLastSet      = $Now.AddDays(-1500)
                    PasswordNeverExpires = $true
                    LastLogonDate        = $Now.AddDays(-1)
                    ServicePrincipalName = @('HTTP/ancient.contoso.com')
                    Description          = 'Very old service'
                    ManagedBy            = $null
                }
                # HIGH: >2 years old
                [PSCustomObject]@{
                    SAMAccountName       = 'svc-aging'
                    DisplayName          = 'Aging Service'
                    DistinguishedName    = 'CN=svc-aging,OU=ServiceAccounts,DC=contoso,DC=com'
                    Enabled              = $true
                    PasswordLastSet      = $Now.AddDays(-900)
                    PasswordNeverExpires = $true
                    LastLogonDate        = $Now.AddDays(-5)
                    ServicePrincipalName = $null
                    Description          = 'Getting old'
                    ManagedBy            = $null
                }
                # MEDIUM: >1 year old
                [PSCustomObject]@{
                    SAMAccountName       = 'svc-medium'
                    DisplayName          = 'Medium Risk Service'
                    DistinguishedName    = 'CN=svc-medium,OU=ServiceAccounts,DC=contoso,DC=com'
                    Enabled              = $true
                    PasswordLastSet      = $Now.AddDays(-500)
                    PasswordNeverExpires = $false
                    LastLogonDate        = $Now.AddDays(-2)
                    ServicePrincipalName = $null
                    Description          = 'Medium risk'
                    ManagedBy            = 'CN=Admin,DC=contoso,DC=com'
                }
                # LOW: <1 year old (should not appear with default threshold)
                [PSCustomObject]@{
                    SAMAccountName       = 'svc-recent'
                    DisplayName          = 'Recent Service'
                    DistinguishedName    = 'CN=svc-recent,OU=ServiceAccounts,DC=contoso,DC=com'
                    Enabled              = $true
                    PasswordLastSet      = $Now.AddDays(-90)
                    PasswordNeverExpires = $false
                    LastLogonDate        = $Now.AddDays(-1)
                    ServicePrincipalName = $null
                    Description          = 'Recent'
                    ManagedBy            = 'CN=Admin,DC=contoso,DC=com'
                }
            )

            Mock Get-ADUser -ModuleName 'ServiceAccount-Audit' -MockWith {
                return $MockAgeAccounts
            }
        }

        It 'Should assign CRITICAL rating for passwords >3 years old' {
            $Results = Get-ServiceAccountAge -DaysOldThreshold 1
            $Critical = $Results | Where-Object { $_.SAMAccountName -eq 'svc-ancient' }
            $Critical.RiskRating | Should -Be 'CRITICAL'
        }

        It 'Should assign HIGH rating for passwords >2 years old' {
            $Results = Get-ServiceAccountAge -DaysOldThreshold 1
            $High = $Results | Where-Object { $_.SAMAccountName -eq 'svc-aging' }
            $High.RiskRating | Should -Be 'HIGH'
        }

        It 'Should assign MEDIUM rating for passwords >1 year old' {
            $Results = Get-ServiceAccountAge -DaysOldThreshold 1
            $Medium = $Results | Where-Object { $_.SAMAccountName -eq 'svc-medium' }
            $Medium.RiskRating | Should -Be 'MEDIUM'
        }

        It 'Should assign LOW rating for passwords <1 year old' {
            $Results = Get-ServiceAccountAge -DaysOldThreshold 1
            $Low = $Results | Where-Object { $_.SAMAccountName -eq 'svc-recent' }
            $Low.RiskRating | Should -Be 'LOW'
        }

        It 'Should filter by threshold and exclude recent accounts' {
            $Results = Get-ServiceAccountAge -DaysOldThreshold 365
            $Results | Where-Object { $_.SAMAccountName -eq 'svc-recent' } | Should -BeNullOrEmpty
        }

        It 'Should sort by password age descending (oldest first)' {
            $Results = Get-ServiceAccountAge -DaysOldThreshold 1
            $Results[0].PasswordAge | Should -BeGreaterThan $Results[-1].PasswordAge
        }

        It 'Should include HasSPN flag in output' {
            $Results = Get-ServiceAccountAge -DaysOldThreshold 1
            $WithSPN = $Results | Where-Object { $_.SAMAccountName -eq 'svc-ancient' }
            $WithSPN.HasSPN | Should -BeTrue
        }
    }

    Context 'Get-SPNReport Mock Tests' {

        BeforeAll {
            $Now = Get-Date

            $MockSPNAccounts = @(
                # Kerberoastable user with old password and weak encryption
                [PSCustomObject]@{
                    SAMAccountName                  = 'svc-sqlkrb'
                    DisplayName                     = 'SQL Kerberoastable'
                    DistinguishedName               = 'CN=svc-sqlkrb,OU=ServiceAccounts,DC=contoso,DC=com'
                    Enabled                         = $true
                    PasswordLastSet                 = $Now.AddDays(-1200)
                    PasswordNeverExpires            = $true
                    ServicePrincipalName            = @('MSSQLSvc/sql01.contoso.com:1433', 'MSSQLSvc/sql01.contoso.com')
                    'msDS-SupportedEncryptionTypes' = 4  # RC4 only
                    LastLogonDate                   = $Now.AddDays(-1)
                    Description                     = 'SQL service'
                    MemberOf                        = @()
                    ObjectClass                     = 'user'
                }
                # Kerberoastable user with recent password and AES
                [PSCustomObject]@{
                    SAMAccountName                  = 'svc-iis'
                    DisplayName                     = 'IIS Service'
                    DistinguishedName               = 'CN=svc-iis,OU=ServiceAccounts,DC=contoso,DC=com'
                    Enabled                         = $true
                    PasswordLastSet                 = $Now.AddDays(-60)
                    PasswordNeverExpires            = $false
                    ServicePrincipalName            = @('HTTP/web01.contoso.com')
                    'msDS-SupportedEncryptionTypes' = 24  # AES128 + AES256
                    LastLogonDate                   = $Now.AddDays(-1)
                    Description                     = 'IIS app pool'
                    MemberOf                        = @()
                    ObjectClass                     = 'user'
                }
            )

            Mock Get-ADUser -ModuleName 'ServiceAccount-Audit' -MockWith {
                return $MockSPNAccounts
            }

            Mock Get-ADComputer -ModuleName 'ServiceAccount-Audit' -MockWith {
                return @()
            }
        }

        It 'Should flag user accounts with SPNs as KERBEROASTABLE' {
            $Results = Get-SPNReport
            $Krb = $Results | Where-Object { $_.SAMAccountName -eq 'svc-sqlkrb' }
            $Krb | Should -Not -BeNullOrEmpty
            $Krb[0].Finding | Should -Match 'KERBEROASTABLE'
        }

        It 'Should flag RC4 encryption as WEAK ENCRYPTION' {
            $Results = Get-SPNReport
            $Weak = $Results | Where-Object { $_.SAMAccountName -eq 'svc-sqlkrb' }
            $Weak[0].Finding | Should -Match 'WEAK ENCRYPTION'
        }

        It 'Should flag OLD PASSWORD + SPN for old passwords on SPN accounts' {
            $Results = Get-SPNReport
            $Old = $Results | Where-Object { $_.SAMAccountName -eq 'svc-sqlkrb' }
            $Old[0].Finding | Should -Match 'OLD PASSWORD \+ SPN'
        }

        It 'Should return one row per SPN (multiple SPNs = multiple rows)' {
            $Results = Get-SPNReport
            $SqlRows = @($Results | Where-Object { $_.SAMAccountName -eq 'svc-sqlkrb' })
            $SqlRows.Count | Should -Be 2
        }

        It 'Should include EncryptionTypes in output' {
            $Results = Get-SPNReport
            $Account = $Results | Where-Object { $_.SAMAccountName -eq 'svc-sqlkrb' } | Select-Object -First 1
            $Account.EncryptionTypes | Should -Match 'RC4'
        }

        It 'Should not flag AES-only accounts as WEAK ENCRYPTION' {
            $Results = Get-SPNReport
            $AES = $Results | Where-Object { $_.SAMAccountName -eq 'svc-iis' }
            $AES[0].Finding | Should -Not -Match 'WEAK ENCRYPTION'
        }

        It 'Should not flag recent passwords as OLD PASSWORD + SPN' {
            $Results = Get-SPNReport
            $Recent = $Results | Where-Object { $_.SAMAccountName -eq 'svc-iis' }
            $Recent[0].Finding | Should -Not -Match 'OLD PASSWORD \+ SPN'
        }
    }

    Context 'Get-ServiceAccountUsage Mock Tests' {

        BeforeAll {
            $MockRemoteServices = @(
                # Domain service account
                [PSCustomObject]@{
                    Name            = 'MSSQLSERVER'
                    DisplayName     = 'SQL Server (MSSQLSERVER)'
                    StartName       = 'CONTOSO\svc-sqlprod'
                    StartMode       = 'Auto'
                    State           = 'Running'
                    PSComputerName  = 'SQL01'
                }
                # Another domain account on different server
                [PSCustomObject]@{
                    Name            = 'MSSQLSERVER'
                    DisplayName     = 'SQL Server (MSSQLSERVER)'
                    StartName       = 'CONTOSO\svc-sqlprod'
                    StartMode       = 'Auto'
                    State           = 'Running'
                    PSComputerName  = 'SQL02'
                }
                # Built-in account (should be filtered)
                [PSCustomObject]@{
                    Name            = 'Spooler'
                    DisplayName     = 'Print Spooler'
                    StartName       = 'NT AUTHORITY\SYSTEM'
                    StartMode       = 'Auto'
                    State           = 'Running'
                    PSComputerName  = 'SQL01'
                }
                # UPN format domain account
                [PSCustomObject]@{
                    Name            = 'AppService'
                    DisplayName     = 'Application Service'
                    StartName       = 'svc-app@contoso.com'
                    StartMode       = 'Auto'
                    State           = 'Running'
                    PSComputerName  = 'APP01'
                }
                # LocalService (should be filtered)
                [PSCustomObject]@{
                    Name            = 'EventLog'
                    DisplayName     = 'Windows Event Log'
                    StartName       = 'NT AUTHORITY\LocalService'
                    StartMode       = 'Auto'
                    State           = 'Running'
                    PSComputerName  = 'APP01'
                }
            )

            Mock Invoke-Command -ModuleName 'ServiceAccount-Audit' -MockWith {
                return $MockRemoteServices
            }
        }

        It 'Should discover domain service accounts on remote servers' {
            $Results = Get-ServiceAccountUsage -ComputerName 'SQL01', 'SQL02', 'APP01'
            $Results | Should -Not -BeNullOrEmpty
        }

        It 'Should find CONTOSO\svc-sqlprod running on multiple servers' {
            $Results = Get-ServiceAccountUsage -ComputerName 'SQL01', 'SQL02'
            $SqlAccount = @($Results | Where-Object { $_.StartName -eq 'CONTOSO\svc-sqlprod' })
            $SqlAccount.Count | Should -BeGreaterOrEqual 2
        }

        It 'Should filter out NT AUTHORITY\LocalService' {
            $Results = Get-ServiceAccountUsage -ComputerName 'APP01'
            $LocalSvc = $Results | Where-Object { $_.StartName -eq 'NT AUTHORITY\LocalService' }
            $LocalSvc | Should -BeNullOrEmpty
        }

        It 'Should detect UPN format service accounts' {
            $Results = Get-ServiceAccountUsage -ComputerName 'APP01'
            $UPN = $Results | Where-Object { $_.StartName -eq 'svc-app@contoso.com' }
            $UPN | Should -Not -BeNullOrEmpty
        }

        It 'Should include ComputerName in results' {
            $Results = Get-ServiceAccountUsage -ComputerName 'SQL01', 'SQL02'
            $Results[0].ComputerName | Should -Not -BeNullOrEmpty
        }

        It 'Should include ServiceName and ServiceDisplayName' {
            $Results = Get-ServiceAccountUsage -ComputerName 'SQL01'
            $Svc = $Results | Where-Object { $_.StartName -eq 'CONTOSO\svc-sqlprod' } | Select-Object -First 1
            $Svc.ServiceName | Should -Be 'MSSQLSERVER'
            $Svc.ServiceDisplayName | Should -Be 'SQL Server (MSSQLSERVER)'
        }

        It 'Should include StartMode and State' {
            $Results = Get-ServiceAccountUsage -ComputerName 'SQL01'
            $Svc = $Results | Select-Object -First 1
            $Svc.StartMode | Should -Not -BeNullOrEmpty
            $Svc.State | Should -Not -BeNullOrEmpty
        }
    }
}
