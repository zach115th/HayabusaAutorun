<#
.SYNOPSIS
    Convert Hayabusa export to DFIR-friendly timeline format.

.PARAMETER InputFile
    Path to the csv file that contains the columns:
    Timestamp, RuleTitle, Level, Computer, Channel, EventID, RuleAuthor,
    RuleModifiedDate, Status, RecordID, Details, ExtraFieldInfo, …
    
.PARAMETER OutputFile
    Path where the formatted timeline will be written.

.EXAMPLE
    .\Format-timeline.ps1 -InputFile .\csv_results_*.csv `
                               -OutputFile .\timeline.csv
#>

param(
    [Parameter(Mandatory)][string]$InputFile,
    [Parameter(Mandatory)][string]$OutputFile
)

# 1. Load the raw data (tabs between columns)
$raw = Import-Csv -Path $InputFile

# 2. Transform every row
$uid = 1
$timeline = foreach ($row in $raw) {

    $dtUtc = if ($row.Timestamp -match '(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})') {
            $Matches[1]                # keep “YYYY-MM-DD HH:MM:SS”
         } else {
            $row.Timestamp              # fallback (already fine)
         }

    # Artifact ── “Windows EID: 1116 (ID1116-…evtx) [Defender threat detected]”
    $artifact = "Windows EID: {0} RID: {1} `n({2}) `n[{3}]" -f $row.EventID, $row.RecordID, (Split-Path $row.EvtxFile -Leaf), $row.Provider

    # Event Description / What Happened ── RuleTitle + Details + ExtraFieldInfo
    $description = "[{0}] `n{1} `n{2}" -f $row.RuleTitle, $row.Details, $row.ExtraFieldInfo

    $notes = "{0} `n{1} `n{2}" -f $row.MitreTactics, $row.MitreTags, $row.OtherTags

    # Build output object
    [pscustomobject]@{
        'UID'                             = $uid++
        'Date / Time (UTC)'               = $dtUtc
        'Artifact'                        = $artifact
        'Event Description/What Happened' = $description.Trim()
        'Event System / Source'           = $row.Computer
        'Examiner'                        = 'Hayabusa'
        'Notes'                           = $notes.Trim()
    }
}

# Ensure the ImportExcel module is available, install if missing, then import it
if (-not (Get-Module -ListAvailable -Name ImportExcel)) {
    try {
        # Make sure PSGallery exists (and is reachable)
        if (-not (Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue)) {
            Register-PSRepository -Default -ErrorAction Stop
        }

        # Install for current user (no admin needed)
        Install-Module -Name ImportExcel -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
    }
    catch {
        throw "ImportExcel not found and automatic install failed: $($_.Exception.Message)"
    }
}

# Load the module (whether it was already there or just installed)
Import-Module ImportExcel -ErrorAction Stop

# 3. Write the timeline
$timeline | Export-Excel '.\timeline.xlsx' -WorksheetName 'Timeline'
