<#
.SYNOPSIS
Build the Windows-formatted corpus images: FAT32, exFAT, and NTFS, each
formatted by diskpart's `format`, the same code path as Explorer's Format
dialog.

.DESCRIPTION
Run from an elevated PowerShell (diskpart needs administrator rights) in the
repository root:

    powershell -ExecutionPolicy Bypass -File corpus\recipes\windows.ps1

Each image is a fixed-size VHD (a raw disk with an MBR and one partition, plus
a 512-byte VHD footer at the end that unearth ignores). Set $env:CORPUS_SCENARIOS
to a comma-separated list to build a subset.

This recipe has not yet been run on a real Windows machine; see corpus/README.md.
#>

$ErrorActionPreference = "Stop"

$Repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$Corpus = Join-Path $Repo "corpus"
$Images = if ($env:CORPUS_IMAGES) { $env:CORPUS_IMAGES } else { Join-Path $Corpus "images" }
$Work = if ($env:CORPUS_WORK) { $env:CORPUS_WORK } else { Join-Path $Corpus "work" }
$VolumeMiB = if ($env:CORPUS_VOLUME_SIZE) { [int]($env:CORPUS_VOLUME_SIZE / 1MB) } else { 64 }
$Seed = if ($env:CORPUS_SEED) { $env:CORPUS_SEED } else { "1" }
$Letter = "Q"

New-Item -ItemType Directory -Force -Path $Images, $Work, (Join-Path $Corpus "expected") | Out-Null

Push-Location $Repo
try { cargo build --quiet --example corpus_tool } finally { Pop-Location }
$Tool = Join-Path $Repo "target\debug\examples\corpus_tool.exe"

$Scenarios = if ($env:CORPUS_SCENARIOS) { $env:CORPUS_SCENARIOS -split "," } else { & $Tool scenarios }
$OsVer = (Get-CimInstance Win32_OperatingSystem).Version

function Invoke-Diskpart([string]$Script) {
    $file = Join-Path $Work "diskpart.txt"
    Set-Content -Path $file -Value $Script -Encoding ASCII
    $out = diskpart /s $file
    if ($LASTEXITCODE -ne 0) { throw "diskpart failed:`n$out" }
}

# Create a file's parent folder if needed. New-Item refuses to "create" a
# drive root such as Q:\, so only act when the parent is actually missing.
function Ensure-Parent([string]$Path) {
    $parent = Split-Path -Parent $Path
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Force -Path $parent | Out-Null
    }
}

function Apply-Plan([string]$Mount, [string]$Stage, [string]$Plan) {
    foreach ($line in Get-Content -LiteralPath $Plan -Encoding UTF8) {
        if ($line -eq "" -or $line.StartsWith("#")) { continue }
        $f = $line -split "`t"
        $rel = if ($f.Length -gt 1) { $f[1] -replace "/", "\" } else { "" }
        switch ($f[0]) {
            "copy" {
                # Copy-Item keeps LastWriteTime, which the test checks the
                # recovered file for.
                $dst = Join-Path $Mount $rel
                Ensure-Parent $dst
                Copy-Item -LiteralPath (Join-Path $Stage $rel) -Destination $dst
            }
            "fill" {
                $dst = Join-Path $Mount $rel
                Ensure-Parent $dst
                try { Copy-Item -LiteralPath (Join-Path $Stage $rel) -Destination $dst -ErrorAction Stop }
                catch { Remove-Item -LiteralPath $dst -ErrorAction SilentlyContinue }
            }
            "delete" {
                if ($f[2] -eq "maybe") { Remove-Item -LiteralPath (Join-Path $Mount $rel) -ErrorAction SilentlyContinue }
                else { Remove-Item -LiteralPath (Join-Path $Mount $rel) }
            }
            "rmdir"  { Remove-Item -LiteralPath (Join-Path $Mount $rel) }
            "sync"   { Write-VolumeCache -DriveLetter $Letter }
            default  { throw "bad plan line: $line" }
        }
    }
}

foreach ($fs in @("fat32", "exfat", "ntfs")) {
    foreach ($scenario in $Scenarios) {
        $name = "windows-$fs-$scenario"
        if ($env:CORPUS_ONLY -and -not $name.Contains($env:CORPUS_ONLY)) { continue }
        Write-Host "== $name"
        $dir = Join-Path $Work $name
        if (Test-Path $dir) { Remove-Item -Recurse -Force $dir }
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        $stage = Join-Path $dir "stage"
        $plan = Join-Path $dir "plan.txt"
        & $Tool plan $scenario $stage $plan --volume-size ($VolumeMiB * 1MB) --seed $Seed
        if ($LASTEXITCODE -ne 0) { throw "corpus_tool plan failed" }

        $img = Join-Path $Images "$name.vhd"
        if (Test-Path $img) { Remove-Item -Force $img }
        Invoke-Diskpart @"
create vdisk file="$img" maximum=$VolumeMiB type=fixed
select vdisk file="$img"
attach vdisk
create partition primary
format fs=$fs quick label=CORPUS
assign letter=$Letter
"@
        try {
            Apply-Plan "${Letter}:\" $stage $plan
        } finally {
            Invoke-Diskpart @"
select vdisk file="$img"
detach vdisk
"@
        }

        & $Tool expect --stage $stage --plan $plan --image $img --name $name `
            --filesystem $fs --platform windows `
            --source "Windows $OsVer diskpart format fs=$fs quick (fixed VHD)" `
            --scenario $scenario --out (Join-Path $Corpus "expected\$name.json")
        if ($LASTEXITCODE -ne 0) { throw "corpus_tool expect failed" }
    }
}

& $Tool lock --expected (Join-Path $Corpus "expected") --out (Join-Path $Corpus "corpus.lock")
