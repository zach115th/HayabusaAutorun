<#
.SYNOPSIS
    Hayabusa Autorun: modular PowerShell automation for Hayabusa & Takajo workflows.
    https://github.com/SigmaHQ/sigma
    https://github.com/Yamato-Security/hayabusa
    https://github.com/Yamato-Security/takajo
    https://github.com/google/timesketch
    https://mitre-attack.github.io/attack-navigator/
.DESCRIPTION
    1. Prompts for input (event log path and desired output profile).
    2. Creates timestamped Results folder.
    3. Updates Hayabusa detection rules.
    4. Executes Hayabusa scan (CSV, Timesketch or JSON) against local EVTX files.
    5. Optionally invokes Takajo to parse JSONL for deep artifact extraction.
    6. Informs user of completion and result location.
.PARAMETER None
.VERSION
    20250806r1
#>

param ()

#region Helper Functions

function Show-Header {
    Write-Host "`n`t*****************************************************" -ForegroundColor Blue
    Write-Host "`t*                                                   *" -ForegroundColor Blue
    Write-Host "`t*                       HayabusaAutorun             *" -ForegroundColor Blue
    Write-Host "`t*                                                   *" -ForegroundColor Blue
    Write-Host "`t*****************************************************`n" -ForegroundColor Blue
}

function Get-LogPath {
    $raw = Read-Host "`n`tEnter Event Log Path"
    # Remove wrapping single or double quotes
    $cleaned = $raw -replace '^(["''])|(["''])$',''
    return $cleaned
}

function Get-Profile {
    do {
        $selection = Read-Host "`n`tCSV(C), Timesketch(T), or Takajo parsable(P) output?"
        switch ($selection.ToUpper()) {
            'C' { return 'C' }
            'T' { return 'T' }
            'P' { return 'P' }
            Default { Write-Host "`n`tInvalid selection. Please choose C, T, or P." -ForegroundColor Red }
        }
    } while ($true)
}

function Initialize-Output {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Output
    )
    if (-not (Test-Path -Path $Output)) {
        New-Item -ItemType Directory -Path $Output | Out-Null
    }
}

function Warn-IfHayabusaUpdate {
    param(
        [Parameter(Mandatory = $true)]
        [string]$HayabusaExe
    )

    # Get local version from file name
    $localVersion = [regex]::Match((Split-Path $HayabusaExe -Leaf), 'hayabusa-?v?([0-9]+\.[0-9]+\.[0-9]+)').Groups[1].Value

    # Query GitHub API for latest release tag
    try {
        $latest = Invoke-RestMethod -Uri "https://api.github.com/repos/Yamato-Security/hayabusa/releases/latest" -Headers @{'User-Agent'='Edge'}
        $latestVersion = $latest.tag_name -replace '[^\d\.]',''  # Strip 'v'
    } catch {
        Write-Host "`n`t[Warning] Could not check for Hayabusa updates (GitHub not reachable)." -ForegroundColor Yellow
        return
    }

    # Compare
    if ($localVersion -and $latestVersion -and ($localVersion -ne $latestVersion)) {
        Write-Host "`n`t[UPDATE AVAILABLE]" -ForegroundColor Yellow
        Write-Host "`tLatest Hayabusa version: $($latest.tag_name)" -ForegroundColor Yellow
        Write-Host "`tLocal Hayabusa version: v$localVersion" -ForegroundColor Yellow
        Write-Host "`tDownload: $($latest.html_url)" -ForegroundColor Yellow
	Pause
    } elseif ($localVersion -eq $latestVersion) {
        Write-Host "`n`t[Hayabusa is up to date: v$localVersion]" -ForegroundColor Green
    }
}

function Warn-IfTakajoUpdate {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TakajoExe
    )

    # Get local version from file name (handles takajo-2.0.6-win-x64.exe, takajo-v2.0.6.exe, etc)
    $localVersion = [regex]::Match((Split-Path $TakajoExe -Leaf), 'takajo-?v?([0-9]+\.[0-9]+\.[0-9]+)').Groups[1].Value

    # Query GitHub API for latest release tag
    try {
        $latest = Invoke-RestMethod -Uri "https://api.github.com/repos/Yamato-Security/takajo/releases/latest" -Headers @{'User-Agent'='Edge'}
        $latestVersion = $latest.tag_name -replace '[^\d\.]',''  # Strip non-numeric
    } catch {
        Write-Host "`n`t[Warning] Could not check for Takajo updates (GitHub not reachable)." -ForegroundColor Yellow
        return
    }

    if ($localVersion -and $latestVersion -and ($localVersion -ne $latestVersion)) {
        Write-Host "`n`t[UPDATE AVAILABLE]" -ForegroundColor Yellow
        Write-Host "`tLatest Takajo version: $($latest.tag_name)" -ForegroundColor Yellow
        Write-Host "`tLocal Takajo version: $localVersion" -ForegroundColor Yellow
        Write-Host "`tDownload: $($latest.html_url)" -ForegroundColor Yellow
        Pause
    } elseif ($localVersion -eq $latestVersion) {
        Write-Host "`n`t[Takajo is up to date: $localVersion]" -ForegroundColor Green
    } elseif (-not $localVersion) {
        Write-Host "`n`t[Could not detect Takajo version from filename.]" -ForegroundColor Yellow
    }
}

function Update-HayabusaRules {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Executable
    )
    Write-Host "`n`tUpdating rules...`n" -ForegroundColor Green
    Start-Process -FilePath $Executable -ArgumentList 'update-rules -q' -NoNewWindow -PassThru -Wait
    Write-Host "`n`tRules update complete.`n" -ForegroundColor Green
}

function Invoke-HayabusaScan {
    param (
        [Parameter(Mandatory=$true)][string]$Executable,
        [Parameter(Mandatory=$true)][string]$Logs,
        [Parameter(Mandatory=$true)][string]$Profile,
        [Parameter(Mandatory=$true)][string]$Output,
        [Parameter(Mandatory=$true)][string]$Date
    )
    # Always quote paths in argument list
    $quotedLogs = '"' + $Logs + '"'
    switch ($Profile.ToUpper()) {
        'C' {
            $csvOut = '"' + "$Output\csv_results_${Date}.csv" + '"'
            Write-Host "`n`tStarting CSV timeline scan...`n" -ForegroundColor Green
            Start-Process -FilePath $Executable -ArgumentList `
                "csv-timeline --directory $quotedLogs --scan-all-evtx-files --no-wizard --enable-all-rules --multiline --output $csvOut --profile super-verbose --UTC -N -q" `
                -NoNewWindow `
                -PassThru `
                -Wait
        }
        'T' {
            $tsOut = '"' + "$Output\ts_results_${Date}.csv" + '"'
            Write-Host "`n`tStarting Timesketch timeline scan...`n" -ForegroundColor Green
            Start-Process -FilePath $Executable -ArgumentList `
                "csv-timeline --directory $quotedLogs --scan-all-evtx-files --no-wizard --enable-all-rules --output $tsOut --profile timesketch-verbose --UTC -N -q" `
                -NoNewWindow `
                -PassThru `
                -Wait
        }
        'P' {
            $jsonlOut = '"' + "$Output\takajo_results_${Date}.jsonl" + '"'
            Write-Host "`n`tStarting JSON timeline scan...`n" -ForegroundColor Green
            Start-Process -FilePath $Executable -ArgumentList `
                "json-timeline --directory $quotedLogs --scan-all-evtx-files --no-wizard --enable-all-rules --JSONL-output -o $jsonlOut --profile super-verbose --UTC -N -q" `
                -NoNewWindow `
                -PassThru `
                -Wait
        }
        Default {
            Write-Host "`n`tUnexpected profile in scan. Skipping." -ForegroundColor Yellow
            return
        }
    }
}

function Invoke-TakajoParser {
    param (
        [Parameter(Mandatory=$true)][string]$TakajoExe,
        [Parameter(Mandatory=$true)][string]$Output,
        [Parameter(Mandatory=$true)][string]$Date
    )
    $jsonlIn = '"' + "$Output\takajo_results_${Date}.jsonl" + '"'
    $takajoOut = '"' + "$Output\Takajo_${Date}" + '"'
    Write-Host "`n`tStarting Takajo parsing...`n" -ForegroundColor Green
    Start-Process -FilePath $TakajoExe -ArgumentList `
        "automagic -t $jsonlIn -o $takajoOut -q" `
        -NoNewWindow `
        -PassThru `
        -Wait
}

function Show-Completion {
    param (
        [Parameter(Mandatory=$true)][string]$Output
    )
    Write-Host "`n`tFinished scanning. Results located at: $Output`n" -ForegroundColor Green
    Write-Host "`n`tVisualize TTPs via MITRE Navigator: https://mitre-attack.github.io/attack-navigator/`n" -ForegroundColor Green
    Pause
    Exit 0
}
#endregion

function Main {
    Show-Header
    $Logs    = Get-LogPath
    $Profile = Get-Profile
    $Date    = Get-Date -Format 'yyyyMMddHHmm'
    $Output  = Join-Path -Path '.\Results' -ChildPath $Date
    Initialize-Output -Output $Output

    $HayabusaExe = Get-ChildItem -Path ".\hayabusa-*.exe" | Select-Object -First 1
    if (-not $HayabusaExe) { 
	Write-Error "`n`tHayabusa executable not found!"
	Write-Host "`tDownload latest version: https://github.com/Yamato-Security/hayabusa/releases`n" 
	exit 1 
	}

    $TakajoExe = Get-ChildItem -Path ".\takajo-*.exe" | Select-Object -First 1
    if ($Profile -eq 'P') {
        if (-not $TakajoExe) { 
	   Write-Error "`n`tTakajo executable not found!"
	   Write-Host "`tDownload latest version: https://github.com/Yamato-Security/takajo/releases`n"
	   exit 1 
	}
    }

    Warn-IfHayabusaUpdate -HayabusaExe $HayabusaExe.FullName
    Warn-IfTakajoUpdate -TakajoExe $TakajoExe.FullName
    Update-HayabusaRules -Executable $HayabusaExe.FullName

    Invoke-HayabusaScan -Executable $HayabusaExe.FullName -Logs $Logs -Profile $Profile -Output $Output -Date $Date
    if ($Profile -eq 'P') {
        Invoke-TakajoParser -TakajoExe $TakajoExe.FullName -Output $Output -Date $Date
    }
    Show-Completion -Output $Output
}

# Kick off the process
Main
