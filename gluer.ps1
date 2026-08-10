$PartsDirectory = "C:\Vault\Parts"
$OutputFile = "C:\Vault\Joined\vault_2.0.4_linux_amd64.zip"

New-Item `
    -ItemType Directory `
    -Force `
    -Path (Split-Path $OutputFile) |
    Out-Null

$Parts = Get-ChildItem `
    "$PartsDirectory\vault_2.0.4_linux_amd64.zip.part.*" |
    Sort-Object Name

if ($Parts.Count -eq 0) {
    throw "Части файла не найдены"
}

$OutputStream = [System.IO.File]::Create($OutputFile)

try {
    foreach ($Part in $Parts) {
        Write-Host "Adding: $($Part.Name)"

        $PartStream = [System.IO.File]::OpenRead($Part.FullName)

        try {
            $PartStream.CopyTo($OutputStream)
        }
        finally {
            $PartStream.Dispose()
        }
    }
}
finally {
    $OutputStream.Dispose()
}

Write-Host "Created: $OutputFile"