function Get-ServiceAccountUsage {
    <#
    .SYNOPSIS
        Scans remote servers to find where service accounts are actually running.

    .DESCRIPTION
        Uses WinRM (Invoke-Command) and CIM (Win32_Service) to enumerate services on
        remote servers, identifying those running under domain accounts. Cross-references
        with Active Directory when SearchBase is provided to flag accounts with
        PasswordNeverExpires or other risk conditions.

    .PARAMETER ComputerName
        One or more server names to scan for running services. Mandatory.

    .PARAMETER SearchBase
        Optional AD search base to cross-reference discovered service accounts with
        their AD properties (password age, expiration policy, etc.).

    .EXAMPLE
        Get-ServiceAccountUsage -ComputerName 'SERVER01', 'SERVER02'

    .EXAMPLE
        Get-ServiceAccountUsage -ComputerName (Get-Content servers.txt) -SearchBase "DC=contoso,DC=com"

    .NOTES
        Requires WinRM enabled on target servers. Run from an account with admin
        rights on the target machines.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$ComputerName,

        [Parameter()]
        [string]$SearchBase
    )

    begin {
        Write-Verbose "Starting service account usage scan"

        $AllComputers = [System.Collections.Generic.List[string]]::new()
        $Results = [System.Collections.Generic.List[PSObject]]::new()

        # Well-known local/built-in accounts that are NOT domain service accounts
        $BuiltInAccounts = @(
            'LocalSystem'
            'NT AUTHORITY\LocalService'
            'NT AUTHORITY\NetworkService'
            'NT AUTHORITY\SYSTEM'
            'NT AUTHORITY\LOCAL SERVICE'
            'NT AUTHORITY\NETWORK SERVICE'
            'NT Service\*'
            'Local System'
            ''
        )

        # If SearchBase provided, build a lookup of AD service accounts
        $ADAccountLookup = @{}
        if ($SearchBase) {
            Write-Verbose "Building AD account lookup from SearchBase: $SearchBase"
            try {
                $ADAccounts = Get-ADUser -SearchBase $SearchBase -Filter * -Properties @(
                    'SAMAccountName'
                    'PasswordNeverExpires'
                    'PasswordLastSet'
                    'Enabled'
                ) -ErrorAction SilentlyContinue

                foreach ($ADAccount in $ADAccounts) {
                    $ADAccountLookup[$ADAccount.SAMAccountName] = $ADAccount
                }
                Write-Verbose "Loaded $($ADAccountLookup.Count) AD accounts for cross-reference"
            }
            catch {
                Write-Warning "Could not load AD accounts for cross-reference: $_"
            }
        }

        # Script block to run on remote machines
        $RemoteScriptBlock = {
            Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue |
                Select-Object -Property Name, DisplayName, StartName, StartMode, State
        }
    }

    process {
        foreach ($Computer in $ComputerName) {
            $AllComputers.Add($Computer)
        }
    }

    end {
        Write-Verbose "Scanning $($AllComputers.Count) servers"

        # Execute remote scan
        $RemoteResults = $null
        try {
            $RemoteResults = Invoke-Command -ComputerName $AllComputers -ScriptBlock $RemoteScriptBlock -ErrorAction SilentlyContinue -ErrorVariable RemoteErrors
        }
        catch {
            Write-Warning "Remote scan failed: $_"
            return
        }

        # Log connection failures
        foreach ($Err in $RemoteErrors) {
            Write-Warning "Connection issue: $($Err.Exception.Message)"
        }

        if (-not $RemoteResults) {
            Write-Warning "No results returned from any server."
            return
        }

        foreach ($Service in $RemoteResults) {
            $StartName = $Service.StartName
            if ([string]::IsNullOrWhiteSpace($StartName)) { continue }

            # Skip built-in local accounts
            $IsBuiltIn = $false
            foreach ($BuiltIn in $BuiltInAccounts) {
                if ($BuiltIn.EndsWith('*')) {
                    $Prefix = $BuiltIn.TrimEnd('*')
                    if ($StartName.StartsWith($Prefix, [StringComparison]::OrdinalIgnoreCase)) {
                        $IsBuiltIn = $true
                        break
                    }
                }
                elseif ($StartName -eq $BuiltIn) {
                    $IsBuiltIn = $true
                    break
                }
            }

            # Build findings
            $Findings = [System.Collections.Generic.List[string]]::new()

            # Flag LocalSystem services that look like they could be domain services
            if ($StartName -eq 'LocalSystem' -or $StartName -eq 'NT AUTHORITY\SYSTEM') {
                # Only flag if the service name looks like a custom/third-party service
                $SystemServices = @(
                    'Spooler', 'MSSQLSERVER', 'SQLAgent*', 'W3SVC', 'WAS',
                    'IISADMIN', 'MSSQLServerOLAPService', 'ReportServer'
                )
                $IsSuspect = $false
                foreach ($Pattern in $SystemServices) {
                    if ($Service.Name -like $Pattern) {
                        $IsSuspect = $true
                        break
                    }
                }
                if ($IsSuspect) {
                    $Findings.Add('RUNS AS LOCALSYSTEM (review if domain account needed)')
                }
                else {
                    continue  # Skip standard system services
                }
            }

            if ($IsBuiltIn -and $Findings.Count -eq 0) { continue }

            # Check if this is a domain account (contains backslash or @)
            $IsDomainAccount = ($StartName -match '\\' -and $StartName -notmatch '^NT ') -or ($StartName -match '@')

            if ($IsDomainAccount) {
                # Extract SAMAccountName for AD lookup
                $SAMName = if ($StartName -match '\\(.+)$') {
                    $Matches[1]
                }
                elseif ($StartName -match '^(.+)@') {
                    $Matches[1]
                }
                else {
                    $StartName
                }

                # Cross-reference with AD if available
                if ($ADAccountLookup.ContainsKey($SAMName)) {
                    $ADInfo = $ADAccountLookup[$SAMName]
                    if ($ADInfo.PasswordNeverExpires) {
                        $Findings.Add('DOMAIN ACCOUNT WITH PASSWORD NEVER EXPIRES')
                    }
                    if ($ADInfo.PasswordLastSet) {
                        $Age = [math]::Round(((Get-Date) - $ADInfo.PasswordLastSet).TotalDays)
                        if ($Age -gt 365) {
                            $Findings.Add("PASSWORD $Age DAYS OLD")
                        }
                    }
                    if (-not $ADInfo.Enabled) {
                        $Findings.Add('AD ACCOUNT DISABLED BUT SERVICE RUNNING')
                    }
                }
                else {
                    $Findings.Add('DOMAIN SERVICE ACCOUNT')
                }
            }

            if ($Findings.Count -eq 0 -and -not $IsDomainAccount) { continue }

            $ComputerDisplayName = if ($Service.PSComputerName) {
                $Service.PSComputerName
            }
            else {
                'Unknown'
            }

            $Result = [PSCustomObject]@{
                ComputerName       = $ComputerDisplayName
                ServiceName        = $Service.Name
                ServiceDisplayName = $Service.DisplayName
                StartName          = $StartName
                StartMode          = $Service.StartMode
                State              = $Service.State
                Finding            = ($Findings -join '; ')
            }
            $Result.PSObject.TypeNames.Insert(0, 'ServiceAccountAudit.Usage')
            $Results.Add($Result)
        }

        Write-Verbose "Usage scan complete. Found $($Results.Count) service account entries across $($AllComputers.Count) servers."
        $Results | Sort-Object -Property StartName, ComputerName
    }
}
