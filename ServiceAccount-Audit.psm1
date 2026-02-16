# ServiceAccount-Audit Module Loader
# Dot-source all public and private functions

$PublicPath  = Join-Path -Path $PSScriptRoot -ChildPath 'Public'
$PrivatePath = Join-Path -Path $PSScriptRoot -ChildPath 'Private'

# Import private functions first (used internally by public functions)
if (Test-Path -Path $PrivatePath) {
    $PrivateFiles = Get-ChildItem -Path $PrivatePath -Filter '*.ps1' -ErrorAction SilentlyContinue
    foreach ($File in $PrivateFiles) {
        try {
            . $File.FullName
            Write-Verbose "Imported private function: $($File.BaseName)"
        }
        catch {
            Write-Error "Failed to import private function $($File.BaseName): $_"
        }
    }
}

# Import public functions (exported to the caller)
if (Test-Path -Path $PublicPath) {
    $PublicFiles = Get-ChildItem -Path $PublicPath -Filter '*.ps1' -ErrorAction SilentlyContinue
    foreach ($File in $PublicFiles) {
        try {
            . $File.FullName
            Write-Verbose "Imported public function: $($File.BaseName)"
        }
        catch {
            Write-Error "Failed to import public function $($File.BaseName): $_"
        }
    }
}
