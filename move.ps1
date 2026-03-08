# Config
$NexusUrl   = "http://localhost:8081"
$SourceRepo = "npmjs"
$TargetRepo = "asterius.npm"
$User       = "dev"
$Pass       = "dev"
$TmpDir     = "$env:TEMP\nexus-migration"

# Load System.Net.Http explicitly (required for PS5)
Add-Type -AssemblyName System.Net.Http

# Basic auth header
$Bytes   = [System.Text.Encoding]::UTF8.GetBytes("${User}:${Pass}")
$Base64  = [Convert]::ToBase64String($Bytes)
$Headers = @{ Authorization = "Basic $Base64" }

# Create temp dir
New-Item -ItemType Directory -Force -Path $TmpDir | Out-Null

$ContinuationToken = $null

do {
    # Build URL with optional pagination token
    $Url = "$NexusUrl/service/rest/v1/components?repository=$SourceRepo"
    if ($ContinuationToken) {
        $Url += "&continuationToken=$ContinuationToken"
    }

    Write-Host "Fetching components from: $Url"

    $Response          = Invoke-RestMethod -Uri $Url -Headers $Headers -Method Get
    $ContinuationToken = $Response.continuationToken

    foreach ($Component in $Response.items) {
        $Name        = $Component.name
        $Version     = $Component.version
        $DownloadUrl = $Component.assets[0].downloadUrl

        Write-Host "Moving $Name@$Version ..."

        # Download .tgz (no npm hooks triggered)
        $SafeName = $Name -replace "[/\\]", "_"
        $TmpFile  = "$TmpDir\$SafeName-$Version.tgz"
        Invoke-WebRequest -Uri $DownloadUrl -Headers $Headers -OutFile $TmpFile

        # Upload using multipart via System.Net.Http
        $UploadUrl = "$NexusUrl/service/rest/v1/components?repository=$TargetRepo"

        $HttpClient    = New-Object System.Net.Http.HttpClient
        $HttpClient.DefaultRequestHeaders.Authorization = `
            New-Object System.Net.Http.Headers.AuthenticationHeaderValue("Basic", $Base64)

        $Multipart   = New-Object System.Net.Http.MultipartFormDataContent
        $FileBytes   = [System.IO.File]::ReadAllBytes($TmpFile)
        $ByteContent = New-Object System.Net.Http.ByteArrayContent(,$FileBytes)
        $ByteContent.Headers.ContentType = `
            [System.Net.Http.Headers.MediaTypeHeaderValue]::Parse("application/octet-stream")

        $Multipart.Add($ByteContent, "npm.asset", [System.IO.Path]::GetFileName($TmpFile))

        $Result = $HttpClient.PostAsync($UploadUrl, $Multipart).Result
        $HttpClient.Dispose()

        if ($Result.IsSuccessStatusCode) {
            Write-Host "  Done: $Name@$Version"
        } else {
            Write-Host "  FAILED: $Name@$Version - HTTP $($Result.StatusCode)" -ForegroundColor Red
        }

        Remove-Item $TmpFile -Force
    }

} while ($ContinuationToken)

Write-Host "`nMigration complete!"
