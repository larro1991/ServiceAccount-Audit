function New-HtmlDashboard {
    <#
    .SYNOPSIS
        Generates a dark-themed HTML dashboard for service account audit results.

    .DESCRIPTION
        Internal function that produces a self-contained HTML file with dark theme
        and red accent (#f85149) for a security-focused visual style. Includes
        summary cards, data tables for each audit section, and risk highlighting.

    .PARAMETER Data
        Hashtable containing all audit data sections and summary statistics.

    .PARAMETER OutputPath
        File path where the HTML report will be written.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Data,

        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )

    # --- Helper: Convert objects to HTML table rows ---
    function ConvertTo-HtmlTableRows {
        param([array]$Objects, [string[]]$Properties)
        if (-not $Objects -or $Objects.Count -eq 0) {
            return "<tr><td colspan='$($Properties.Count)' class='empty'>No data available</td></tr>"
        }
        $Rows = [System.Text.StringBuilder]::new()
        foreach ($Obj in $Objects) {
            [void]$Rows.Append('<tr>')
            foreach ($Prop in $Properties) {
                $Value = $Obj.$Prop
                $CellClass = ''

                # Highlight findings and risk ratings
                if ($Prop -eq 'Finding' -and $Value) {
                    if ($Value -match 'CRITICAL|KERBEROASTABLE|OLD PASSWORD \+ SPN') {
                        $CellClass = ' class="critical"'
                    }
                    elseif ($Value -match 'HIGH|IN PRIVILEGED GROUP|WEAK ENCRYPTION') {
                        $CellClass = ' class="high"'
                    }
                    elseif ($Value -match 'MEDIUM|PASSWORD OLD|NEVER EXPIRES') {
                        $CellClass = ' class="medium"'
                    }
                }
                if ($Prop -eq 'RiskRating') {
                    $CellClass = switch ($Value) {
                        'CRITICAL' { ' class="critical"' }
                        'HIGH'     { ' class="high"' }
                        'MEDIUM'   { ' class="medium"' }
                        'LOW'      { ' class="low"' }
                        default    { '' }
                    }
                }
                if ($Prop -eq 'Enabled' -and $Value -eq $false) {
                    $CellClass = ' class="disabled"'
                }

                $DisplayValue = if ($null -eq $Value) { '' }
                                elseif ($Value -is [datetime]) { $Value.ToString('yyyy-MM-dd HH:mm') }
                                elseif ($Value -is [bool]) { if ($Value) { 'Yes' } else { 'No' } }
                                else { [System.Web.HttpUtility]::HtmlEncode([string]$Value) }

                [void]$Rows.Append("<td$CellClass>$DisplayValue</td>")
            }
            [void]$Rows.Append('</tr>')
        }
        return $Rows.ToString()
    }

    # --- Build summary cards ---
    $SummaryCards = @"
    <div class="cards">
        <div class="card">
            <div class="card-value">$($Data.TotalAccounts)</div>
            <div class="card-label">Service Accounts</div>
        </div>
        <div class="card card-critical">
            <div class="card-value">$($Data.CriticalFindings)</div>
            <div class="card-label">Critical Passwords</div>
        </div>
        <div class="card card-high">
            <div class="card-value">$($Data.HighFindings)</div>
            <div class="card-label">High Risk Passwords</div>
        </div>
        <div class="card card-critical">
            <div class="card-value">$($Data.Kerberoastable)</div>
            <div class="card-label">Kerberoastable</div>
        </div>
        <div class="card card-high">
            <div class="card-value">$($Data.PrivilegedAccounts)</div>
            <div class="card-label">Privileged Accounts</div>
        </div>
        <div class="card card-medium">
            <div class="card-value">$($Data.NoOwner)</div>
            <div class="card-label">No Owner</div>
        </div>
        <div class="card">
            <div class="card-value">$($Data.ServersScanned)</div>
            <div class="card-label">Servers Scanned</div>
        </div>
        <div class="card">
            <div class="card-value">$($Data.ServiceEntries)</div>
            <div class="card-label">Service Entries</div>
        </div>
    </div>
"@

    # --- Build inventory table ---
    $InventoryProps = @('SAMAccountName','Enabled','PasswordLastSet','PasswordAge','PasswordNeverExpires','LastLogonDate','MemberOf','HasSPN','AccountType','ManagedBy','Finding')
    $InventoryHeaders = ($InventoryProps | ForEach-Object { "<th>$_</th>" }) -join ''
    $InventoryRows = ConvertTo-HtmlTableRows -Objects $Data.Inventory -Properties $InventoryProps

    # --- Build password age table ---
    $AgeProps = @('SAMAccountName','Enabled','PasswordLastSet','PasswordAge','PasswordNeverExpires','RiskRating','HasSPN','ManagedBy','Finding')
    $AgeHeaders = ($AgeProps | ForEach-Object { "<th>$_</th>" }) -join ''
    $AgeRows = ConvertTo-HtmlTableRows -Objects $Data.PasswordAge -Properties $AgeProps

    # --- Build usage table ---
    $UsageSection = ''
    if ($Data.UsageResults -and $Data.UsageResults.Count -gt 0) {
        $UsageProps = @('ComputerName','ServiceName','ServiceDisplayName','StartName','StartMode','State','Finding')
        $UsageHeaders = ($UsageProps | ForEach-Object { "<th>$_</th>" }) -join ''
        $UsageRows = ConvertTo-HtmlTableRows -Objects $Data.UsageResults -Properties $UsageProps
        $UsageSection = @"
    <div class="section">
        <h2>Service Account Usage</h2>
        <p class="section-desc">Domain accounts running services on scanned servers. $($Data.ServersScanned) servers scanned, $($Data.ServiceEntries) entries found.</p>
        <div class="table-wrapper">
            <table>
                <thead><tr>$UsageHeaders</tr></thead>
                <tbody>$UsageRows</tbody>
            </table>
        </div>
    </div>
"@
    }

    # --- Build SPN table ---
    $SPNProps = @('SAMAccountName','SPN','PasswordLastSet','PasswordAge','Enabled','EncryptionTypes','Finding')
    $SPNHeaders = ($SPNProps | ForEach-Object { "<th>$_</th>" }) -join ''
    $SPNRows = ConvertTo-HtmlTableRows -Objects $Data.SPNResults -Properties $SPNProps

    # --- Compose full HTML ---
    $Html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$([System.Web.HttpUtility]::HtmlEncode($Data.Title))</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: #0d1117;
            color: #c9d1d9;
            line-height: 1.5;
            padding: 2rem;
        }
        h1 {
            color: #f85149;
            font-size: 1.8rem;
            margin-bottom: 0.25rem;
            border-bottom: 2px solid #f85149;
            padding-bottom: 0.5rem;
        }
        h2 {
            color: #f0f6fc;
            font-size: 1.3rem;
            margin-bottom: 0.5rem;
            padding-bottom: 0.25rem;
            border-bottom: 1px solid #21262d;
        }
        .meta {
            color: #8b949e;
            font-size: 0.85rem;
            margin-bottom: 1.5rem;
        }
        .meta span { margin-right: 1.5rem; }

        /* Summary Cards */
        .cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }
        .card {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 1.25rem;
            text-align: center;
        }
        .card-value {
            font-size: 2rem;
            font-weight: 700;
            color: #f0f6fc;
        }
        .card-label {
            font-size: 0.8rem;
            color: #8b949e;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-top: 0.25rem;
        }
        .card-critical { border-color: #f85149; }
        .card-critical .card-value { color: #f85149; }
        .card-high { border-color: #d29922; }
        .card-high .card-value { color: #d29922; }
        .card-medium { border-color: #e3b341; }
        .card-medium .card-value { color: #e3b341; }

        /* Sections */
        .section {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
        }
        .section-desc {
            color: #8b949e;
            font-size: 0.85rem;
            margin-bottom: 1rem;
        }

        /* Tables */
        .table-wrapper {
            overflow-x: auto;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.85rem;
        }
        thead {
            background: #21262d;
            position: sticky;
            top: 0;
        }
        th {
            text-align: left;
            padding: 0.6rem 0.75rem;
            color: #f0f6fc;
            font-weight: 600;
            white-space: nowrap;
            border-bottom: 2px solid #30363d;
        }
        td {
            padding: 0.5rem 0.75rem;
            border-bottom: 1px solid #21262d;
            max-width: 300px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        tr:hover { background: #1c2129; }
        td.critical { color: #f85149; font-weight: 600; }
        td.high { color: #d29922; font-weight: 600; }
        td.medium { color: #e3b341; }
        td.low { color: #3fb950; }
        td.disabled { color: #f85149; }
        td.empty {
            text-align: center;
            color: #484f58;
            padding: 2rem;
        }

        /* Footer */
        .footer {
            text-align: center;
            color: #484f58;
            font-size: 0.75rem;
            margin-top: 2rem;
            padding-top: 1rem;
            border-top: 1px solid #21262d;
        }

        @media print {
            body { background: #fff; color: #000; }
            .card { border-color: #ccc; }
            .section { border-color: #ccc; }
            td.critical, td.high { color: #c00; }
        }
    </style>
</head>
<body>
    <h1>$([System.Web.HttpUtility]::HtmlEncode($Data.Title))</h1>
    <div class="meta">
        <span>Generated: $($Data.GeneratedAt)</span>
        <span>Duration: $($Data.Duration)</span>
        <span>Search Base: $([System.Web.HttpUtility]::HtmlEncode($Data.SearchBase))</span>
        <span>Password Threshold: $($Data.DaysOldThreshold) days</span>
    </div>

    $SummaryCards

    <div class="section">
        <h2>Service Account Inventory</h2>
        <p class="section-desc">All discovered service accounts with security findings. $($Data.TotalAccounts) accounts found.</p>
        <div class="table-wrapper">
            <table>
                <thead><tr>$InventoryHeaders</tr></thead>
                <tbody>$InventoryRows</tbody>
            </table>
        </div>
    </div>

    <div class="section">
        <h2>Password Age Analysis</h2>
        <p class="section-desc">Service accounts sorted by password age. Threshold: $($Data.DaysOldThreshold)+ days. CRITICAL (&gt;3yr), HIGH (&gt;2yr), MEDIUM (&gt;1yr), LOW (&lt;1yr).</p>
        <div class="table-wrapper">
            <table>
                <thead><tr>$AgeHeaders</tr></thead>
                <tbody>$AgeRows</tbody>
            </table>
        </div>
    </div>

    $UsageSection

    <div class="section">
        <h2>SPN / Kerberoasting Risk</h2>
        <p class="section-desc">User accounts with Service Principal Names are vulnerable to offline password cracking (Kerberoasting). $($Data.Kerberoastable) kerberoastable accounts found.</p>
        <div class="table-wrapper">
            <table>
                <thead><tr>$SPNHeaders</tr></thead>
                <tbody>$SPNRows</tbody>
            </table>
        </div>
    </div>

    <div class="footer">
        ServiceAccount-Audit v1.0.0 | Generated by Invoke-ServiceAccountAudit | $(Get-Date -Format 'yyyy')
    </div>
</body>
</html>
"@

    # Write to file
    $Html | Out-File -FilePath $OutputPath -Encoding utf8 -Force
    Write-Verbose "HTML dashboard written to: $OutputPath"
}
