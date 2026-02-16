function Get-ServiceAccountInventory {
    <#
    .SYNOPSIS
        Discovers service accounts in Active Directory.

    .DESCRIPTION
        Identifies service accounts using multiple heuristics: name pattern matching,
        PasswordNeverExpires flag, accounts in "Service Accounts" OUs, and accounts
        with Service Principal Names (SPNs) registered. Returns a comprehensive
        inventory with security findings.

    .PARAMETER SearchBase
        The AD distinguished name to scope the search. Defaults to the current domain root.

    .PARAMETER NamingPattern
        Comma-separated name patterns to match service accounts.
        Default: "svc*,service*"

    .PARAMETER IncludeMSA
        Include Managed Service Accounts (msDS-ManagedServiceAccount).

    .PARAMETER IncludeGMSA
        Include Group Managed Service Accounts (msDS-GroupManagedServiceAccount).

    .EXAMPLE
        Get-ServiceAccountInventory -SearchBase "DC=contoso,DC=com"

    .EXAMPLE
        Get-ServiceAccountInventory -NamingPattern "svc*,service*,batch*" -IncludeMSA -IncludeGMSA
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$SearchBase,

        [Parameter()]
        [string]$NamingPattern = 'svc*,service*',

        [Parameter()]
        [switch]$IncludeMSA,

        [Parameter()]
        [switch]$IncludeGMSA
    )

    begin {
        Write-Verbose "Starting service account inventory scan"

        $PrivilegedGroups = @(
            'Domain Admins'
            'Enterprise Admins'
            'Schema Admins'
            'Administrators'
            'Account Operators'
            'Backup Operators'
            'Server Operators'
            'Print Operators'
            'DnsAdmins'
        )

        $ADProperties = @(
            'SAMAccountName'
            'DisplayName'
            'DistinguishedName'
            'Enabled'
            'PasswordLastSet'
            'PasswordNeverExpires'
            'LastLogonDate'
            'MemberOf'
            'ServicePrincipalName'
            'Description'
            'ManagedBy'
            'ObjectClass'
            'msDS-ManagedPasswordInterval'
        )

        $SearchParams = @{
            Properties = $ADProperties
            Filter     = '*'
        }
        if ($SearchBase) {
            $SearchParams['SearchBase'] = $SearchBase
        }

        $AllCandidates = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $Results = [System.Collections.Generic.List[PSObject]]::new()
    }

    process {
        # Strategy 1: Name pattern matching
        $Patterns = $NamingPattern -split ',' | ForEach-Object { $_.Trim() }
        foreach ($Pattern in $Patterns) {
            Write-Verbose "Searching by name pattern: $Pattern"
            $PatternParams = $SearchParams.Clone()
            $PatternParams['Filter'] = "SAMAccountName -like '$Pattern'"
            try {
                $Found = Get-ADUser @PatternParams -ErrorAction SilentlyContinue
                foreach ($Account in $Found) {
                    [void]$AllCandidates.Add($Account.SAMAccountName)
                }
            }
            catch {
                Write-Warning "Pattern search failed for '$Pattern': $_"
            }
        }

        # Strategy 2: PasswordNeverExpires flag
        Write-Verbose "Searching for accounts with PasswordNeverExpires"
        $NeverExpiresParams = $SearchParams.Clone()
        $NeverExpiresParams['Filter'] = "PasswordNeverExpires -eq `$true"
        try {
            $Found = Get-ADUser @NeverExpiresParams -ErrorAction SilentlyContinue
            foreach ($Account in $Found) {
                [void]$AllCandidates.Add($Account.SAMAccountName)
            }
        }
        catch {
            Write-Warning "PasswordNeverExpires search failed: $_"
        }

        # Strategy 3: Accounts in "Service Accounts" OUs
        Write-Verbose "Searching for accounts in Service Account OUs"
        $ServiceOUParams = $SearchParams.Clone()
        $ServiceOUParams['Filter'] = '*'
        try {
            $ServiceOUs = Get-ADOrganizationalUnit -Filter "Name -like '*Service Account*'" -ErrorAction SilentlyContinue
            foreach ($OU in $ServiceOUs) {
                $OUSearchParams = $SearchParams.Clone()
                $OUSearchParams['SearchBase'] = $OU.DistinguishedName
                $Found = Get-ADUser @OUSearchParams -ErrorAction SilentlyContinue
                foreach ($Account in $Found) {
                    [void]$AllCandidates.Add($Account.SAMAccountName)
                }
            }
        }
        catch {
            Write-Warning "Service Account OU search failed: $_"
        }

        # Strategy 4: Accounts with SPNs
        Write-Verbose "Searching for accounts with Service Principal Names"
        $SPNParams = $SearchParams.Clone()
        $SPNParams['Filter'] = "ServicePrincipalName -like '*'"
        try {
            $Found = Get-ADUser @SPNParams -ErrorAction SilentlyContinue
            foreach ($Account in $Found) {
                [void]$AllCandidates.Add($Account.SAMAccountName)
            }
        }
        catch {
            Write-Warning "SPN search failed: $_"
        }

        # Include MSA/GMSA if requested
        if ($IncludeMSA) {
            Write-Verbose "Including Managed Service Accounts"
            try {
                $MSAParams = @{ Filter = '*'; Properties = $ADProperties }
                if ($SearchBase) { $MSAParams['SearchBase'] = $SearchBase }
                $MSAs = Get-ADServiceAccount @MSAParams -ErrorAction SilentlyContinue
                foreach ($Account in $MSAs) {
                    [void]$AllCandidates.Add($Account.SAMAccountName)
                }
            }
            catch {
                Write-Verbose "MSA search not available or returned no results: $_"
            }
        }

        # Now retrieve full details for each candidate
        Write-Verbose "Processing $($AllCandidates.Count) candidate accounts"

        foreach ($AccountName in $AllCandidates) {
            try {
                $Account = Get-ADUser -Identity $AccountName -Properties $ADProperties -ErrorAction Stop
            }
            catch {
                Write-Warning "Could not retrieve details for $AccountName : $_"
                continue
            }

            # Calculate password age
            $PasswordAge = if ($Account.PasswordLastSet) {
                [math]::Round(((Get-Date) - $Account.PasswordLastSet).TotalDays)
            }
            else {
                -1
            }

            # Determine account type
            $AccountType = switch ($Account.ObjectClass) {
                'msDS-ManagedServiceAccount'          { 'MSA' }
                'msDS-GroupManagedServiceAccount'      { 'GMSA' }
                default                                { 'User' }
            }

            # Identify privileged group memberships
            $PrivilegedMemberships = @()
            if ($Account.MemberOf) {
                foreach ($GroupDN in $Account.MemberOf) {
                    $GroupName = ($GroupDN -split ',')[0] -replace '^CN=', ''
                    if ($PrivilegedGroups -contains $GroupName) {
                        $PrivilegedMemberships += $GroupName
                    }
                }
            }

            # Check for SPNs
            $HasSPN = ($null -ne $Account.ServicePrincipalName -and $Account.ServicePrincipalName.Count -gt 0)

            # Generate findings
            $Findings = [System.Collections.Generic.List[string]]::new()

            if ($PasswordAge -gt 365) {
                $Findings.Add('PASSWORD OLD')
            }
            if ($Account.PasswordNeverExpires) {
                $Findings.Add('NEVER EXPIRES')
            }
            if ($PrivilegedMemberships.Count -gt 0) {
                $Findings.Add('IN PRIVILEGED GROUP')
            }
            if (-not $Account.ManagedBy -and [string]::IsNullOrWhiteSpace($Account.ManagedBy)) {
                $Findings.Add('NO OWNER')
            }
            if (-not $Account.Enabled -and $Account.MemberOf.Count -gt 0) {
                $Findings.Add('DISABLED BUT IN GROUPS')
            }
            if ([string]::IsNullOrWhiteSpace($Account.Description)) {
                $Findings.Add('NO DESCRIPTION')
            }

            $Result = [PSCustomObject]@{
                SAMAccountName       = $Account.SAMAccountName
                DisplayName          = $Account.DisplayName
                DistinguishedName    = $Account.DistinguishedName
                Enabled              = $Account.Enabled
                PasswordLastSet      = $Account.PasswordLastSet
                PasswordNeverExpires = $Account.PasswordNeverExpires
                PasswordAge          = $PasswordAge
                LastLogonDate        = $Account.LastLogonDate
                MemberOf             = ($PrivilegedMemberships -join ', ')
                HasSPN               = $HasSPN
                AccountType          = $AccountType
                Description          = $Account.Description
                ManagedBy            = $Account.ManagedBy
                Finding              = ($Findings -join '; ')
            }
            $Result.PSObject.TypeNames.Insert(0, 'ServiceAccountAudit.Inventory')
            $Results.Add($Result)
        }
    }

    end {
        Write-Verbose "Inventory complete. Found $($Results.Count) service accounts."
        $Results | Sort-Object -Property SAMAccountName
    }
}
