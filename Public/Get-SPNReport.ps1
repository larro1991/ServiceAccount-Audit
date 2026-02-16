function Get-SPNReport {
    <#
    .SYNOPSIS
        Audits Service Principal Names (SPNs) for Kerberoasting risk.

    .DESCRIPTION
        Identifies user accounts with Service Principal Names registered in Active Directory.
        User accounts with SPNs are vulnerable to Kerberoasting attacks - any authenticated
        domain user can request a TGS ticket encrypted with the service account's password
        hash, then crack it offline. This function flags such accounts and evaluates their
        risk based on encryption types and password age.

    .PARAMETER SearchBase
        The AD distinguished name to scope the search. Defaults to the current domain root.

    .PARAMETER IncludeComputers
        Include computer accounts in the report. By default, only user accounts are returned
        since computer accounts change their passwords automatically every 30 days.

    .EXAMPLE
        Get-SPNReport

    .EXAMPLE
        Get-SPNReport -SearchBase "DC=contoso,DC=com" -IncludeComputers

    .NOTES
        Kerberoasting context:
        - Any authenticated user can request a service ticket for any SPN
        - The ticket is encrypted with the service account's NTLM hash
        - Attackers crack these tickets offline (no lockout, no detection)
        - Only user accounts with SPNs are practical targets (computer passwords are random 120+ chars)
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$SearchBase,

        [Parameter()]
        [switch]$IncludeComputers
    )

    begin {
        Write-Verbose "Starting SPN / Kerberoasting audit"

        $ADProperties = @(
            'SAMAccountName'
            'DisplayName'
            'DistinguishedName'
            'Enabled'
            'PasswordLastSet'
            'PasswordNeverExpires'
            'ServicePrincipalName'
            'msDS-SupportedEncryptionTypes'
            'LastLogonDate'
            'Description'
            'MemberOf'
            'ObjectClass'
        )

        $Results = [System.Collections.Generic.List[PSObject]]::new()
        $Now = Get-Date

        # Encryption type flags (from MS-KILE)
        # These map to the msDS-SupportedEncryptionTypes attribute
        $EncTypeMap = @{
            0x1  = 'DES-CBC-CRC'
            0x2  = 'DES-CBC-MD5'
            0x4  = 'RC4-HMAC'
            0x8  = 'AES128-CTS-HMAC-SHA1'
            0x10 = 'AES256-CTS-HMAC-SHA1'
        }

        $WeakEncryption = @('DES-CBC-CRC', 'DES-CBC-MD5', 'RC4-HMAC')
    }

    process {
        # Query for user accounts with SPNs
        Write-Verbose "Searching for user accounts with SPNs"
        $UserParams = @{
            Filter     = "ServicePrincipalName -like '*'"
            Properties = $ADProperties
        }
        if ($SearchBase) { $UserParams['SearchBase'] = $SearchBase }

        try {
            $UserAccounts = @(Get-ADUser @UserParams -ErrorAction SilentlyContinue)
            Write-Verbose "Found $($UserAccounts.Count) user accounts with SPNs"
        }
        catch {
            Write-Warning "User SPN search failed: $_"
            $UserAccounts = @()
        }

        # Query for computer accounts with SPNs (if requested)
        $ComputerAccounts = @()
        if ($IncludeComputers) {
            Write-Verbose "Searching for computer accounts with SPNs"
            $CompParams = @{
                Filter     = "ServicePrincipalName -like '*'"
                Properties = $ADProperties
            }
            if ($SearchBase) { $CompParams['SearchBase'] = $SearchBase }

            try {
                $ComputerAccounts = @(Get-ADComputer @CompParams -ErrorAction SilentlyContinue)
                Write-Verbose "Found $($ComputerAccounts.Count) computer accounts with SPNs"
            }
            catch {
                Write-Warning "Computer SPN search failed: $_"
                $ComputerAccounts = @()
            }
        }

        $AllAccounts = @($UserAccounts) + @($ComputerAccounts)

        foreach ($Account in $AllAccounts) {
            if (-not $Account.ServicePrincipalName -or $Account.ServicePrincipalName.Count -eq 0) {
                continue
            }

            # Calculate password age
            $PasswordAge = if ($Account.PasswordLastSet) {
                [math]::Round(($Now - $Account.PasswordLastSet).TotalDays)
            }
            else {
                -1
            }

            # Decode supported encryption types
            $EncValue = $Account.'msDS-SupportedEncryptionTypes'
            $SupportedEncryption = [System.Collections.Generic.List[string]]::new()

            if ($null -ne $EncValue -and $EncValue -ne 0) {
                foreach ($Flag in $EncTypeMap.Keys) {
                    if ($EncValue -band $Flag) {
                        $SupportedEncryption.Add($EncTypeMap[$Flag])
                    }
                }
            }
            else {
                # No encryption types set - defaults to RC4
                $SupportedEncryption.Add('RC4-HMAC (default)')
            }

            $EncryptionDisplay = $SupportedEncryption -join ', '

            # Check for weak encryption
            $HasWeakEncryption = $false
            foreach ($EncType in $SupportedEncryption) {
                foreach ($Weak in $WeakEncryption) {
                    if ($EncType -like "$Weak*") {
                        $HasWeakEncryption = $true
                        break
                    }
                }
                if ($HasWeakEncryption) { break }
            }

            # Determine if this is a user or computer account
            $IsUserAccount = ($Account.ObjectClass -ne 'computer')

            # Process each SPN on the account
            foreach ($SPN in $Account.ServicePrincipalName) {
                $Findings = [System.Collections.Generic.List[string]]::new()

                if ($IsUserAccount) {
                    $Findings.Add('KERBEROASTABLE')
                }

                if ($HasWeakEncryption) {
                    $Findings.Add('WEAK ENCRYPTION')
                }

                if ($IsUserAccount -and $PasswordAge -gt 365) {
                    $Findings.Add('OLD PASSWORD + SPN')
                }

                if ($Account.PasswordNeverExpires -and $IsUserAccount) {
                    $Findings.Add('PASSWORD NEVER EXPIRES')
                }

                if (-not $Account.Enabled) {
                    $Findings.Add('ACCOUNT DISABLED')
                }

                $Result = [PSCustomObject]@{
                    SAMAccountName  = $Account.SAMAccountName
                    SPN             = $SPN
                    PasswordLastSet = $Account.PasswordLastSet
                    PasswordAge     = $PasswordAge
                    Enabled         = $Account.Enabled
                    EncryptionTypes = $EncryptionDisplay
                    IsUserAccount   = $IsUserAccount
                    Finding         = ($Findings -join '; ')
                }
                $Result.PSObject.TypeNames.Insert(0, 'ServiceAccountAudit.SPN')
                $Results.Add($Result)
            }
        }
    }

    end {
        Write-Verbose "SPN audit complete. $($Results.Count) SPN entries analyzed."
        $Results | Sort-Object -Property @{Expression = 'IsUserAccount'; Descending = $true }, PasswordAge -Descending
    }
}
