# Shared by the persona scripts (dot-sourced).

# Polite scripted browsing (lab/src/wlab/browse.py) with an installed or
# Playwright browser; a failure is a warning, never the end of a session.
function Invoke-Browse {
    param(
        [Parameter(Mandatory)][string]$LabRoot,
        [Parameter(Mandatory)][string]$Browser,
        [Parameter(Mandatory)][string]$List,
        [Parameter(Mandatory)][double]$Minutes,
        [Parameter(Mandatory)][int]$Seed
    )
    $sites = Join-Path $LabRoot 'capture\sites.json'
    & uv run --project $LabRoot python -m wlab.browse --browser $Browser --sites $sites `
        --list $List --minutes $Minutes --seed $Seed | Out-Host
    if ($LASTEXITCODE -ne 0) { Write-Warning "browsing with $Browser ended with exit code $LASTEXITCODE" }
}
