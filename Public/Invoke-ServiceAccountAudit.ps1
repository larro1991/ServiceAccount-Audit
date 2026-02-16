function Invoke-ServiceAccountAudit {
    <#
    .SYNOPSIS
        Orchestrates a full service account security audit and generates an HTML dashboard.

    .DESCRIPTION
        Runs all ServiceAccount-Audit functions in sequence:
          1. Get-ServiceAccountInventory - Discovers service accounts in AD
          2. Get-ServiceAccountAge - Analyzes password age risk
          3. Get-ServiceAccountUsage - Scans servers for running services (if ComputerName specified)
          4. Get-SPNReport - Audits Kerberoasting risk

        Collects all results and generates a dark-themed HTML dashboard report.

    .PARAMETER SearchBase
        The AD distinguished name to scope the search. Defaults to the current domain root.

    .PARAMETER ComputerName
        One or more server names to scan for running services. If omitted, the usage
        scan is skipped.

    .PARAMETER OutputPath
        Path where the HTML report will be saved. Defaults to
        "ServiceAccountAudit_<timestamp>.html" in the current directory.

    .PARAMETER DaysOldThreshold
        Minimum password age in days for the password age report. Default: 365.

    .PARAMETER IncludeMSA
        Include Managed Service Accounts in the inventory scan.

    .EXAMPLE
        Invoke-ServiceAccountAudit -OutputPath "C:\Reports\svc-audit.html"

    .EXAMPLE
        Invoke-ServiceAccountAudit -ComputerName (Get-Content servers.txt) -DaysOldThreshold 180 -IncludeMSA

    .EXAMPLE
        $servers = Get-ADComputer -Filter "OperatingSystem -like '*Server*'" | Select-Object -ExpandProperty Name
        Invoke-ServiceAccountAudit -ComputerName $servers -SearchBase "DC=contoso,DC=com"
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$SearchBase,

        [Parameter()]
        [string[]]$ComputerName,

        [Parameter()]
        [string]$OutputPath,

        [Parameter()]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$DaysOldThreshold = 365,

        [Parameter()]
        [switch]$IncludeMSA
    )

    begin {
        $StartTime = Get-Date
        Write-Verbose "Starting full service account audit at $StartTime"

        if (-not $OutputPath) {
            $Timestamp = $StartTime.ToString('yyyyMMdd_HHmmss')
            $OutputPath = Join-Path -Path (Get-Location) -ChildPath "ServiceAccountAudit_$Timestamp.html"
        }

        # Ensure output directory exists
        $OutputDir = Split-Path -Path $OutputPath -Parent
        if ($OutputDir -and -not (Test-Path -Path $OutputDir)) {
            New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null
        }
    }

    process {
        # --- Phase 1: Service Account Inventory ---
        Write-Verbose "Phase 1: Service Account Inventory"
        Write-Progress -Activity 'Service Account Audit' -Status 'Discovering service accounts...' -PercentComplete 10

        $InventoryParams = @{}
        if ($SearchBase)  { $InventoryParams['SearchBase']  = $SearchBase }
        if ($IncludeMSA)  { $InventoryParams['IncludeMSA']  = $true }

        try {
            $Inventory = @(Get-ServiceAccountInventory @InventoryParams)
            Write-Verbose "Inventory: $($Inventory.Count) accounts discovered"
        }
        catch {
            Write-Warning "Inventory scan failed: $_"
            $Inventory = @()
        }

        # --- Phase 2: Password Age Analysis ---
        Write-Verbose "Phase 2: Password Age Analysis"
        Write-Progress -Activity 'Service Account Audit' -Status 'Analyzing password age...' -PercentComplete 30

        $AgeParams = @{
            DaysOldThreshold = $DaysOldThreshold
        }
        if ($SearchBase) { $AgeParams['SearchBase'] = $SearchBase }

        try {
            $PasswordAge = @(Get-ServiceAccountAge @AgeParams)
            Write-Verbose "Password Age: $($PasswordAge.Count) accounts above threshold"
        }
        catch {
            Write-Warning "Password age analysis failed: $_"
            $PasswordAge = @()
        }

        # --- Phase 3: Service Usage Scan ---
        $UsageResults = @()
        if ($ComputerName -and $ComputerName.Count -gt 0) {
            Write-Verbose "Phase 3: Service Usage Scan ($($ComputerName.Count) servers)"
            Write-Progress -Activity 'Service Account Audit' -Status "Scanning $($ComputerName.Count) servers..." -PercentComplete 50

            $UsageParams = @{
                ComputerName = $ComputerName
            }
            if ($SearchBase) { $UsageParams['SearchBase'] = $SearchBase }

            try {
                $UsageResults = @(Get-ServiceAccountUsage @UsageParams)
                Write-Verbose "Usage: $($UsageResults.Count) service entries found"
            }
            catch {
                Write-Warning "Usage scan failed: $_"
                $UsageResults = @()
            }
        }
        else {
            Write-Verbose "Phase 3: Skipped (no ComputerName specified)"
        }

        # --- Phase 4: SPN / Kerberoasting Audit ---
        Write-Verbose "Phase 4: SPN / Kerberoasting Audit"
        Write-Progress -Activity 'Service Account Audit' -Status 'Auditing SPNs...' -PercentComplete 70

        $SPNParams = @{}
        if ($SearchBase) { $SPNParams['SearchBase'] = $SearchBase }

        try {
            $SPNResults = @(Get-SPNReport @SPNParams)
            Write-Verbose "SPN: $($SPNResults.Count) SPN entries analyzed"
        }
        catch {
            Write-Warning "SPN audit failed: $_"
            $SPNResults = @()
        }

        # --- Phase 5: Generate HTML Report ---
        Write-Verbose "Phase 5: Generating HTML report"
        Write-Progress -Activity 'Service Account Audit' -Status 'Generating report...' -PercentComplete 90

        $EndTime = Get-Date
        $Duration = $EndTime - $StartTime

        # Build summary statistics
        $TotalAccounts     = $Inventory.Count
        $CriticalFindings  = ($PasswordAge | Where-Object { $_.RiskRating -eq 'CRITICAL' }).Count
        $HighFindings      = ($PasswordAge | Where-Object { $_.RiskRating -eq 'HIGH' }).Count
        $Kerberoastable    = ($SPNResults | Where-Object { $_.Finding -match 'KERBEROASTABLE' }).Count
        $NoOwner           = ($Inventory | Where-Object { $_.Finding -match 'NO OWNER' }).Count
        $PrivilegedAccounts = ($Inventory | Where-Object { $_.Finding -match 'IN PRIVILEGED GROUP' }).Count
        $ServersScanned    = if ($ComputerName) { $ComputerName.Count } else { 0 }
        $ServiceEntries    = $UsageResults.Count

        $DashboardData = @{
            Title              = 'Service Account Security Audit'
            GeneratedAt        = $EndTime.ToString('yyyy-MM-dd HH:mm:ss')
            Duration           = '{0:mm}m {0:ss}s' -f $Duration
            SearchBase         = if ($SearchBase) { $SearchBase } else { '(Domain Root)' }
            DaysOldThreshold   = $DaysOldThreshold
            TotalAccounts      = $TotalAccounts
            CriticalFindings   = $CriticalFindings
            HighFindings       = $HighFindings
            Kerberoastable     = $Kerberoastable
            NoOwner            = $NoOwner
            PrivilegedAccounts = $PrivilegedAccounts
            ServersScanned     = $ServersScanned
            ServiceEntries     = $ServiceEntries
            Inventory          = $Inventory
            PasswordAge        = $PasswordAge
            UsageResults       = $UsageResults
            SPNResults         = $SPNResults
        }

        try {
            New-HtmlDashboard -Data $DashboardData -OutputPath $OutputPath
            Write-Verbose "Report saved to: $OutputPath"
        }
        catch {
            Write-Warning "HTML report generation failed: $_"
        }

        Write-Progress -Activity 'Service Account Audit' -Completed
    }

    end {
        # Return a summary object
        $Summary = [PSCustomObject]@{
            AuditDate          = $EndTime
            Duration           = $Duration
            SearchBase         = if ($SearchBase) { $SearchBase } else { '(Domain Root)' }
            TotalAccounts      = $TotalAccounts
            CriticalPasswords  = $CriticalFindings
            HighPasswords      = $HighFindings
            KerberoastableAccounts = $Kerberoastable
            NoOwnerAccounts    = $NoOwner
            PrivilegedAccounts = $PrivilegedAccounts
            ServersScanned     = $ServersScanned
            ServiceEntries     = $ServiceEntries
            ReportPath         = $OutputPath
        }
        $Summary.PSObject.TypeNames.Insert(0, 'ServiceAccountAudit.Summary')

        Write-Verbose "Audit complete. $TotalAccounts accounts, $CriticalFindings critical, $Kerberoastable kerberoastable."
        $Summary
    }
}
