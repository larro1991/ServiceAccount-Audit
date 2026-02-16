@{
    # Module manifest for ServiceAccount-Audit
    # Audit service accounts across the environment

    RootModule        = 'ServiceAccount-Audit.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'b2c3d4e5-9f80-4b6c-ad7e-3f4a5b6c7d8e'
    Author            = 'Larry Roberts, Independent Consultant'
    CompanyName       = 'Independent Consultant'
    Copyright         = '(c) 2026 Larry Roberts. All rights reserved.'
    Description       = 'Service account security auditing. Discovers service accounts across servers, reports on password age, privileged group membership, SPNs, and identifies accounts with no documented owner. Generates HTML dashboard reports. Requires ActiveDirectory RSAT module.'
    PowerShellVersion = '5.1'

    # Functions to export from this module
    FunctionsToExport = @(
        'Invoke-ServiceAccountAudit'
        'Get-ServiceAccountInventory'
        'Get-ServiceAccountAge'
        'Get-ServiceAccountUsage'
        'Get-SPNReport'
    )

    CmdletsToExport   = @()
    VariablesToExport  = @()
    AliasesToExport    = @()

    PrivateData = @{
        PSData = @{
            Tags         = @('ServiceAccount', 'Security', 'Audit', 'ActiveDirectory', 'Password', 'SPN', 'Compliance')
            LicenseUri   = 'https://github.com/larro1991/ServiceAccount-Audit/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/larro1991/ServiceAccount-Audit'
            ReleaseNotes = @'
## 1.0.0
- Initial release
- Service account discovery via name pattern, PasswordNeverExpires, OU, and SPN detection
- Password age analysis with CRITICAL/HIGH/MEDIUM/LOW risk ratings
- Remote server service scan via WinRM + CimInstance
- SPN / Kerberoasting risk assessment
- HTML dashboard report with dark theme
'@
        }
    }
}
