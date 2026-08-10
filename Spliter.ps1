$InputFile = "C:\Users\Cyber\Desktop\Hashi\vault_1.13.13_linux_amd64.zip"
$ChunkSize = 9500000

$InputStream = [System.IO.File]::OpenRead($InputFile)

try {
    $Buffer = New-Object byte[] $ChunkSize
    $PartNumber = 0

    while (($BytesRead = $InputStream.Read(
        $Buffer,
        0,
        $Buffer.Length
    )) -gt 0) {
        $PartFile = "{0}.part.{1:D3}" -f $InputFile, $PartNumber
        $OutputStream = [System.IO.File]::Create($PartFile)

        try {
            $OutputStream.Write($Buffer, 0, $BytesRead)
        }
        finally {
            $OutputStream.Dispose()
        }

        Write-Host "Created: $PartFile ($BytesRead bytes)"
        $PartNumber++
    }
}
finally {
    $InputStream.Dispose()
}