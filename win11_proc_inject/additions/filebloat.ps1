param(
    [ValidateSet('v1','v2','v3')]
    [string]$Mode,

    [int]$MB,

    [string]$Path,

    [int]$LineCount = 10000,

    [switch]$Help
)

function Show-Help {
@"
==== File / Source Bloat Utility ====

Usage Examples:
  .\filebloat.ps1 -Mode v1 -Path file.exe -MB 100
  .\filebloat.ps1 -Mode v2 -Path out.bin -MB 512
  .\filebloat.ps1 -Mode v3 -LineCount 15000 -Path data.c

Modes:
  v1 - Append 0x00s to existing file
       Requires: -Path (existing), -MB

  v2 - Create binary of 0xFF bytes
       Requires: -MB
       Optional: -Path (default: .\file.bin)

  v3 - Generate C array of file-name strings
       Optional: -Path (default: .\bloat_array.c)
                 -LineCount (default: 10000)

Only megabyte input is accepted for -MB.
"@ | Write-Host
exit
}

# Show help if requested or Mode is missing
if ($Help -or -not $Mode) { Show-Help }

# ========== MODE v1 ==========
if ($Mode -eq 'v1') {
    if (-not $Path -or -not (Test-Path $Path)) { throw "v1 requires valid -Path to an existing file." }
    if (-not $MB) { throw "v1 requires -MB" }

    $fs = [IO.File]::Open($Path, 'Open', 'Write')
    try { $fs.SetLength($fs.Length + ($MB * 1MB)) }
    finally { $fs.Close() }

    Write-Host "Appended $MB MB of 0x00 to $Path"
}

# ========== MODE v2 ==========
elseif ($Mode -eq 'v2') {
    if (-not $MB) { throw "v2 requires -MB" }
    if (-not $Path) { $Path = '.\file.bin' }

    $buf = New-Object byte[] (1MB)
    for ($i = 0; $i -lt $buf.Length; $i++) { $buf[$i] = 0xFF }

    $fs = [IO.File]::Create($Path)
    try {
        for ($i = 0; $i -lt $MB; $i++) {
            $fs.Write($buf, 0, $buf.Length)
        }
    } finally { $fs.Close() }

    Write-Host "Created $MB MB file: $Path"
}

# ========== MODE v3 ==========
elseif ($Mode -eq 'v3') {
    if (-not $Path) { $Path = '.\bloat_array.c' }

    $roots = @("$env:USERPROFILE", "$env:SystemRoot", "C:\ProgramData")
    $files = @()

    foreach ($root in $roots) {
        try {
            $files += Get-ChildItem -Path $root -Recurse -File -Depth 3 -ErrorAction Ignore |
                Where-Object { $_.Name.Length -gt 5 -and $_.Name -match '^[\w\.\-]+$' } |
                Select-Object -ExpandProperty Name
        } catch {}
    }

    if ($files.Count -eq 0) { throw "No suitable filenames found for v3" }

    $list = $files | Get-Random -Count ([Math]::Min($LineCount, $files.Count)) | Sort-Object
    "const char* bloatData[] = {" | Set-Content $Path
    $list | ForEach-Object { '    "{0}",' -f $_ } | Add-Content $Path
    "};" | Add-Content $Path

    Write-Host "Wrote $($list.Count) strings to $Path"
}

else {
    Show-Help
}
