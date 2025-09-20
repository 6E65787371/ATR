@echo off

set /p APP_KEY=Enter App Key: 
set /p APP_SECRET=Enter App Secret: 
set /p REDIRECT_URI=Enter Redirect URI: 
set STATE=12345

echo "https://www.dropbox.com/oauth2/authorize?client_id=%APP_KEY%&response_type=code&token_access_type=offline&redirect_uri=%REDIRECT_URI%&state=%STATE%"

set /p AUTHORIZATION_CODE=Enter Authorization Code: 

curl -X POST https://api.dropboxapi.com/oauth2/token ^
    -d code=%AUTHORIZATION_CODE% ^
    -d grant_type=authorization_code ^
    -d client_id=%APP_KEY% ^
    -d client_secret=%APP_SECRET% ^
    -d redirect_uri=%REDIRECT_URI%

pause