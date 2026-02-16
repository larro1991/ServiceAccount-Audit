function Get-ServiceAccountAge {
    <#
    .SYNOPSIS
        Analyzes service account password age and assigns risk ratings.

    .DESCRIPTION
        Focused analysis of service account password age across Active Directory.
        Assigns risk ratings based on how long ago the password was last changed:
          CRITICAL - Password older than 3 years (1095 days)
          HIGH     - Password older than 2 years (730 days)
          MEDIUM   - Password older than 1 year (365 days)
          LOW      - Password changed within the last year

    .PARAMETER SearchBase
        The AD distinguished name to scope the search. Defaults to the current domain root.

    .PARAMETER DaysOldThreshold
        The minimum age in days to include in results. Default: 365.

    .PARAMETER NamingPattern
        Comma-separated name patterns to match service accounts.
        Default: "svc*,service*"

    .EXAMPLE
        Get-ServiceAccountAge -DaysOldThreshold 730
        Returns only accounts with passwords older than 2 years.

    .EXAMPLE
        Get-ServiceAccountAge -SearchBase "OU=ServiceAccounts,DC=contoso,DC=com"
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$SearchBase,

        [Parameter()]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$DaysOldThreshold = 365,

        [Parameter()]
        [string]$NamingPattern = 'svc*,service*'
    )

    begin {
        Write-Verbose "Starting password age analysis (threshold: $DaysOldThreshold days)"

        $ADProperties = @(
            'SAMAccountName'
            'DisplayName'
            'DistinguishedName'
            'Enabled'
            'PasswordLastSet'
            'PasswordNeverExpires'
            'LastLogonDate'
            'ServicePrincipalName'
            'Description'
            'ManagedBy'
        )

        $Results = [System.Collections.Generic.List[PSObject]]::new()
        $Now = Get-Date
    }

    process {
        $Patterns = $NamingPattern -split ',' | ForEach-Object { $_.Trim() }
        $AllAccounts = [System.Collections.Generic.Dictionary[string, Microsoft.ActiveDirectory.Management.ADUser]]::new(
            [StringComparer]::OrdinalIgnoreCase
        )

        foreach ($Pattern in $Patterns) {
            Write-Verbose "Querying pattern: $Pattern"
            $Params = @{
                Filter     = "SAMAccountName -like '$Pattern'"
                Properties = $ADProperties
            }
            if ($SearchBase) { $Params['SearchBase'] = $SearchBase }

            try {
                $Found = Get-ADUser @Params -ErrorAction SilentlyContinue
                foreach ($Account in $Found) {
                    if (-not $AllAccounts.ContainsKey($Account.SAMAccountName)) {
                        $AllAccounts[$Account.SAMAccountName] = $Account
                    }
                }
            }
            catch {
                Write-Warning "Search failed for pattern '$Pattern': $_"
            }
        }

        # Also include accounts with PasswordNeverExpires
        $NeverExpiresParams = @{
            Filter     = "PasswordNeverExpires -eq `$true"
            Properties = $ADProperties
        }
        if ($SearchBase) { $NeverExpiresParams['SearchBase'] = $SearchBase }
        try {
            $Found = Get-ADUser @NeverExpiresParams -ErrorAction SilentlyContinue
            foreach ($Account in $Found) {
                if (-not $AllAccounts.ContainsKey($Account.SAMAccountName)) {
                    $AllAccounts[$Account.SAMAccountName] = $Account
                }
            }
        }
        catch {
            Write-Warning "PasswordNeverExpires search failed: $_"
        }

        # Also include accounts with SPNs (service accounts by definition)
        $SPNParams = @{
            Filter     = "ServicePrincipalName -like '*'"
            Properties = $ADProperties
        }
        if ($SearchBase) { $SPNParams['SearchBase'] = $SearchBase }
        try {
            $Found = Get-ADUser @SPNParams -ErrorAction SilentlyContinue
            foreach ($Account in $Found) {
                if (-not $AllAccounts.ContainsKey($Account.SAMAccountName)) {
                    $AllAccounts[$Account.SAMAccountName] = $Account
                }
            }
        }
        catch {
            Write-Warning "SPN search failed: $_"
        }

        Write-Verbose "Evaluating $($AllAccounts.Count) accounts for password age"

        foreach ($Account in $AllAccounts.Values) {
            # Calculate password age
            if ($Account.PasswordLastSet) {
                $PasswordAge = [math]::Round(($Now - $Account.PasswordLastSet).TotalDays)
            }
            else {
                # Password never set or cannot be determined - treat as maximum risk
                $PasswordAge = [int]::MaxValue
            }

            # Apply threshold filter
            if ($PasswordAge -lt $DaysOldThreshold) {
                continue
            }

            # Assign risk rating
            $RiskRating = if ($PasswordAge -ge 1095) {
                'CRITICAL'
            }
            elseif ($PasswordAge -ge 730) {
                'HIGH'
            }
            elseif ($PasswordAge -ge 365) {
                'MEDIUM'
            }
            else {
                'LOW'
            }

            # Build finding description
            $PasswordDisplay = if ($Account.PasswordLastSet) {
                "$PasswordAge days ($($Account.PasswordLastSet.ToString('yyyy-MM-dd')))"
            }
            else {
                'NEVER SET'
            }

            $HasSPN = ($null -ne $Account.ServicePrincipalName -and $Account.ServicePrincipalName.Count -gt 0)

            $Findings = [System.Collections.Generic.List[string]]::new()
            $Findings.Add("$RiskRating - Password age: $PasswordDisplay")

            if ($Account.PasswordNeverExpires) {
                $Findings.Add('NEVER EXPIRES')
            }
            if ($HasSPN) {
                $Findings.Add('HAS SPN (Kerberoastable)')
            }
            if ($Account.Enabled -eq $false) {
                $Findings.Add('ACCOUNT DISABLED')
            }

            $Result = [PSCustomObject]@{
                SAMAccountName       = $Account.SAMAccountName
                DisplayName          = $Account.DisplayName
                DistinguishedName    = $Account.DistinguishedName
                Enabled              = $Account.Enabled
                PasswordLastSet      = $Account.PasswordLastSet
                PasswordAge          = $PasswordAge
                PasswordNeverExpires = $Account.PasswordNeverExpires
                LastLogonDate        = $Account.LastLogonDate
                HasSPN               = $HasSPN
                RiskRating           = $RiskRating
                Description          = $Account.Description
                ManagedBy            = $Account.ManagedBy
                Finding              = ($Findings -join '; ')
            }
            $Result.PSObject.TypeNames.Insert(0, 'ServiceAccountAudit.PasswordAge')
            $Results.Add($Result)
        }
    }

    end {
        Write-Verbose "Password age analysis complete. $($Results.Count) accounts above threshold."

        # Sort by password age descending (oldest first = highest risk)
        $Results | Sort-Object -Property PasswordAge -Descending
    }
}
