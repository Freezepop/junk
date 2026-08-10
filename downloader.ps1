$Owner = "Freezepop"
$Repo = "junk"
$Branch = "main"
$RepoPath = "vault_1.13.13_linux_amd64"
$OutputDirectory = "C:\Vault\vault_1.13.13_linux_amd64"

New-Item `
    -ItemType Directory `
    -Force `
    -Path $OutputDirectory |
    Out-Null

$Headers = @{
    "Accept"     = "application/vnd.github+json"
    "User-Agent" = "PowerShell-GitHub-Downloader"
}

$ApiUrl = "https://api.github.com/repos/$Owner/$Repo/contents/${RepoPath}?ref=${Branch}"

$Files = Invoke-RestMethod `
    -Uri $ApiUrl `
    -Headers $Headers

foreach ($File in $Files) {
    if ($File.type -ne "file") {
        continue
    }

    $Destination = Join-Path $OutputDirectory $File.name

    Write-Host "Downloading $($File.name)"

    Invoke-WebRequest `
        -Uri $File.download_url `
        -OutFile $Destination
}

Write-Host "Download completed: $OutputDirectory"