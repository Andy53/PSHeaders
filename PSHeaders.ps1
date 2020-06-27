param($File, $Url, $Cookie, $CookieValue, $CookieName, $Csv, [Switch]$Help, $OutputFile, $Proxy, $Cert, $Verb, [Switch]$Verbose)

$LinuxOS = $False
$WindowsOS= $False
$CsvArrayList = [System.Collections.ArrayList]@()
$OutputString = New-Object System.Collections.Generic.List[string]
$WriteToFile  = $false
$WriteToCSV   = $false
$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession

function Set-Cookie([string]$urlString){
    if($Cookie[$Cookie.length - 1] -eq ";"){
        $Cookie = $Cookie.Substring(0,$Cookie.Length-1)
    }
    $thisCookie = New-Object System.Net.Cookie 
    $cookies = $Cookie.Split(";")
    foreach($element in $cookies){
        $currentCookie = $element.Split("=")
        $thisCookie.Name = $currentCookie[0]
        $thisCookie.Value = $currentCookie[1]
        $thisCookie.Domain = $urlString
        $session.Cookies.Add($thisCookie);
    }
    return $session
}

function Set-Cookie-Params{
    param([string]$urlString)
    $cookie = New-Object System.Net.Cookie 
    $cookie.Name = $cookieName
    $cookie.Value = $cookieValue
    $cookie.Domain = $urlString
    $session.Cookies.Add($cookie);
    return $session
}

function Show-Help{
    param([string] $message = "")

    Write-Host "    ____  _____ __  __               __              "
    Write-Host "   / __ \/ ___// / / /__  ____ _____/ /__  __________"
    Write-Host "  / /_/ /\__ \/ /_/ / _ \/ __ `/ __  / _ \/ ___/ ___/"
    Write-Host " / ____/___/ / __  /  __/ /_/ / /_/ /  __/ /  (__  ) "
    Write-Host "/_/    /____/_/ /_/\___/\__,_/\__,_/\___/_/  /____/  "
    Write-Host "-----------------------------------------------------"
    Write-Host "Author : Andy Bowden"
    Write-Host "Email  : Andy.Bowden@coalfire.com"
    Write-Host "Version: PSHeaders-0.3"
    if($message -ne ""){
        Write-Host -ForegroundColor Red  "Error = $message"
    }
    Write-Host "-----------------------------------------------------"
    Write-Host "Usage:"
    Write-Host "    -Help        - Display this message."
    Write-Host "    -Url         - Specifies the URL to use"
    Write-Host "    -File        - Specifies a file contianing URL's to be used."
    Write-Host "    -Proxy       - Proxy server to use. E.g. http://127.0.0.1:8000"
    Write-Host "    -OutputFile  - The location where output will be written to disk."
    Write-Host "    -Csv         - The location where output will be written to disk"
    Write-Host "                   in CSV format."   
    Write-Host "    -Cert        - Specifices a PFX file to use as the client certificate"
    Write-Host "    -Verb        - Specifies the HTTP Verb to use e.g. GET, PUT, POST etc."
    Write-Host "                   Currently Powershell versions prior to 6.0 can only use"
    Write-Host "                   Standard verbs."
    Write-Host "    -Verbose     - Provides verbose output."
    Write-Host "    -Cookie      - This parameter can be used to pass cookies directly out"
    Write-Host "                   of HTTP requests for automatic parsing however cannot be"
    Write-Host "                   used if the cookie contains a = character in the value."
    Write-Host "                   If you need to pass an = use the -CookieName and "
    Write-Host "                   -CookieValue parameters.     "         
    Write-Host "    -CookieName  - Used when supplying a cookie with a web reqest. "
    Write-Host "                   Name of the cookie to be supplied. Must be used in"
    Write-Host "                   conjunction with -CookieValue"
    Write-Host "    -CookieValue - Used when supplying a cookie with a web reqest. "
    Write-Host "                   Value of the cookie to be supplied. Must be used "
    Write-Host "                   in conjunction with -CookieName" 
    exit
}

#if ($IsWindows -or $ENV:OS) {
if($IsWindows -or $ENV:OS){
add-type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(
        ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) {
            return true;
        }
 }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
Invoke-WebRequest https://expired.badssl.com/ -UseBasicParsing | Out-Null
    $WindowsOS = $true
}
else {
    $LinuxOS = $true
}

if($Help){
    Show-Help
    exit
}

if(!$File -and !$Url){
    Write-Output "A file containing URL's must be provided to -File or a URL provided to -Url"
    exit
}

if($OutputFile){
    if(Split-Path -Path $OutputFile){  
        if(Test-Path (Split-Path -Path $OutputFile) -PathType Any){
            $WriteToFile = $true
        }
        else{
            Write-Host -ForegroundColor Red "[•] ERROR - " -NoNewline
            Write-Host "You have not entered a valid file name for the output file. Output will not be written to disk."
        }
    }
    else{
        Write-Host -ForegroundColor Red "[•] ERROR - " -NoNewline
        Write-Host "You have not entered a valid file name for the output file. Output will not be written to disk."
    }
}

if($Csv){
    if(Split-Path -Path $Csv){  
        if(Test-Path (Split-Path -Path $Csv) -PathType Any){
            $WriteToCSVe = $true
        }
        else{
            Write-Host -ForegroundColor Red "[•] ERROR - " -NoNewline
            Write-Host "You have not entered a valid file name for the CSV file. Output will not be written in CSV format."
        }
    }
    else{
        Write-Host -ForegroundColor Red "[•] ERROR - " -NoNewline
        Write-Host "You have not entered a valid file name for the CSV file. Output will not be written in CSV format."
    }
}

if($Verb){
    $displayWarning = $true
    if($Verb.ToUpper() -eq "GET"){
        $displayWarning = $false
    }
    if($Verb.ToUpper() -eq "HEAD"){
        $displayWarning = $false
    }
    if($Verb.ToUpper() -eq "POST"){
        $displayWarning = $false
    }
    if($Verb.ToUpper() -eq "PUT"){
        $displayWarning = $false
    }
    if($Verb.ToUpper() -eq "DELETE"){
        $displayWarning = $false
    }
    if($Verb.ToUpper() -eq "CONNECT"){
        $displayWarning = $false
    }
    if($Verb.ToUpper() -eq "OPTIONS"){
        $displayWarning = $false
    }
    if($Verb.ToUpper() -eq "TRACE"){
        $displayWarning = $false
    }
    if($Verb.ToUpper() -eq "TRACK"){
        $displayWarning = $false
    }
    if($Verb.ToUpper() -eq "PATCH"){
        $displayWarning = $false
    }
    if($displayWarning -eq $true){
        Write-Host -ForegroundColor Yellow "[•]" -NoNewline
        Write-Host "Warning: Non standard HTTP verb used: $Verb"
    }
}
else{
    $verb = "Head"
}

if($File){
    foreach($line in Get-Content $File) {
        try { 
            try {
                Write-Output "`nChecking Http headers for $line"
                Write-Output "-----------------------------------------------------"
                if($LinuxOS -eq $true){
                    if($CookieName -and $CookieValue){
                        $Session = Set-Cookie-Params($line)
                        if($Cert){
                            $Exists = Test-Path $Cert
                            if($Exists -eq $True){
                                $Cert = Get-PfxCertificate -FilePath $Cert
                                $response = iwr $line -UseBasicParsing -WebSession $Session -CustomMethod $Verb -Proxy $Proxy -SkipCertificateCheck -Certificate $Cert
                            }
                            else{
                                $response = iwr $line -UseBasicParsing -CustomMethod $Verb -Proxy $Proxy
                            }
                        }
                        else{
                            $response = iwr $line -UseBasicParsing -WebSession $Session -CustomMethod $Verb -Proxy $Proxy -SkipCertificateCheck
                        }
                    }
                    elseif($CookieName -xor $CookieValue){
                        Write-Output "If a cookie is to be sent with the web request both CookieName and CookieValue must be provided."
                        exit
                    }
                    else{
                        if($Cert){
                            $Exists = Test-Path $Cert
                            if($Exists -eq $True){
                                $Cert = Get-PfxCertificate -FilePath $Cert
                                $response = iwr $line -UseBasicParsing -CustomMethod $Verb -Proxy $Proxy -SkipCertificateCheck -Certificate $Cert
                            }
                            else{
                                $response = iwr $line -UseBasicParsing -CustomMethod $Verb -Proxy $Proxy
                            }
                        }
                        else{
                            $response = iwr $line -UseBasicParsing -CustomMethod $Verb -Proxy $Proxy -SkipCertificateCheck
                        }
                    }
                    if($Cookie){
                        $Session = Set-Cookie($Url)
                        if($Cert){
                            $Exists = Test-Path $Cert
                            if($Exists -eq $True){
                                $Cert = Get-PfxCertificate -FilePath $Cert
                                $response = iwr $line -UseBasicParsing -WebSession $Session -CustomMethod $Verb -Proxy $Proxy -SkipCertificateCheck -Certificate $Cert
                            }
                            else{
                                $response = iwr $line -UseBasicParsing -CustomMethod $Verb -Proxy $Proxy
                            }
                        }
                        else{
                            $response = iwr $line -UseBasicParsing -WebSession $Session -CustomMethod $Verb -Proxy $Proxy -SkipCertificateCheck
                        }
                    }
                }
                else{
                    if($CookieName -and $CookieValue){
                        $Session = Set-Cookie-Params($line)
                        if($Cert){
                            $Exists = Test-Path $Cert
                            if($Exists -eq $True){
                                $Cert = Get-PfxCertificate -FilePath $Cert
                                $response = iwr $line -UseBasicParsing -WebSession $Session -Method $Verb -Proxy $Proxy -Certificate $Cert
                            }
                            else{
                                $response = iwr $line -UseBasicParsing -Method $Verb -Proxy $Proxy
                            }
                        }
                        else{
                            $response = iwr $line -UseBasicParsing -WebSession $Session -Method $Verb -Proxy $Proxy
                        }
                    }
                    elseif($CookieName -xor $CookieValue){
                        Write-Output "If a cookie is to be sent with the web request both CookieName and CookieValue must be provided."
                        exit
                    }
                    else{
                        if($Cert){
                            $Exists = Test-Path $Cert
                            if($Exists -eq $True){
                                $Cert = Get-PfxCertificate -FilePath $Cert
                                $response = iwr $line -UseBasicParsing -Method $Verb -Proxy $Proxy -Certificate $Cert
                            }
                            else{
                                $response = iwr $line -UseBasicParsing -Method $Verb -Proxy $Proxy
                            }
                        }
                        else{
                            $response = iwr $line -UseBasicParsing -Method $Verb -Proxy $Proxy
                        }
                    }
                    if($Cookie){
                        $Session = Set-Cookie($Url)
                        if($Cert){
                            $Exists = Test-Path $Cert
                            if($Exists -eq $True){
                                $Cert = Get-PfxCertificate -FilePath $Cert
                                $response = iwr $line -UseBasicParsing -WebSession $Session -Method $Verb -Proxy $Proxy -Certificate $Cert
                            }
                            else{
                                $response = iwr $line -UseBasicParsing -Method $Verb -Proxy $Proxy
                            }
                        }
                        else{
                            $response = iwr $line -UseBasicParsing -WebSession $Session -Method $Verb -Proxy $Proxy
                        }
                    }
                }
            }
            catch [System.Net.WebException] {
                Write-Host -ForegroundColor Red "[•] Exception: " -NoNewline
                Write-Host $_ 
                $response = $_.Exception.Response
            }
            catch [Microsoft.PowerShell.Commands.HttpResponseException] {
                Write-Host -ForegroundColor Red "[•] Exception: " -NoNewline
                Write-Host $_ 
                $response = [Microsoft.PowerShell.Commands.BasicHtmlWebResponseObject]$_.Exception.Response
            }
            if($Verbose){
                if($IsLinux){
                    Write-Host $response.BaseResponse
                }
                else{
                    Write-Host ""
                    $output = [Microsoft.PowerShell.Commands.BasicHtmlWebResponseObject]$response
                    Write-Host $output.RawContent -NoNewline
                }
	        Write-Output "-----------------------------------------------------"
            }
            #------------------Cache-Control--------------------------------------------------
            if ($response.Headers["Cache-Control"]) {
                $output = $response.Headers["Cache-Control"]
                if($output -match "no-cache" -and $output -match "no-store"){
                    Write-Host -ForegroundColor Green "[•]" -NoNewline
                    Write-Output "$line Cache-Control Found = $output"
                    $OutputString.Add("$line Cache-Control Found = $output")
                    $element = $line, "Cache-Control", $output
                }
                else{
                    Write-Host -ForegroundColor Yellow "[•]" -NoNewline
                    Write-Host "$line Cache-Control Found = $output | " -NoNewline
                    Write-Host -ForegroundColor Yellow "Should contain 'no-cache, no-store'"
                    $OutputString.Add("$line Cache-Control Found = $output | Should contain 'no-cache, no-store'")
                    $element = $line, "Cache-Control", "$output | Should contain 'no-cache, no-store'"
                    [void]$CsvArrayList.Add($element)
                }
            } else {
                Write-Host -ForegroundColor Red "[•]" -NoNewline
                Write-Output "$line Cache-Control Not found"
                $OutputString.Add("$line Cache-Control Not found")
                $element = $line, "Cache-Control", "Not Found"
                [void]$CsvArrayList.Add($element)
            }
            #-----------------X-Content-Type-Options---------------------------------------
            if ($response.Headers["X-Content-Type-Options"]) {
                $output = $response.Headers["X-Content-Type-Options"]
                if($output -eq "nosniff"){
                    Write-Host -ForegroundColor Green "[•]" -NoNewline
                    Write-Output "$line X-Content-Type-Options Found = $output"
                    $OutputString.Add("$line X-Content-Type-Options Found = $output")
                    $element = $line, "X-Content-Type-Options", $output
                }
                else{
                    Write-Host -ForegroundColor Yellow "[•]" -NoNewline
                    Write-Host "$line X-Content-Type-Options Found = $output | " -NoNewline
                    Write-Host -ForegroundColor Yellow "Should be 'nosniff'"
                    $OutputString.Add("$line X-Content-Type-Options Found = $output | Should be 'nosniff'")
                    $element = $line, "X-Content-Type-Options", "$output | Should be 'nosniff'"
                    [void]$CsvArrayList.Add($element)
                }
            } else {
                Write-Host -ForegroundColor Red "[•]" -NoNewline
                Write-Output "$line X-Content-Type-Options Not found"
                $OutputString.Add("$line X-Content-Type-Options Not found")
                $element = $line, "X-Content-Type-Options", "Not Found"
                [void]$CsvArrayList.Add($element)
            }
            #-------------------Strict-Transport-Security------------------------------------
            if ($response.Headers["Strict-Transport-Security"]) {
                $output = $response.Headers["Strict-Transport-Security"]
                if($output -match "includeSubDomains"){
                    Write-Host -ForegroundColor Green "[•]" -NoNewline
                    Write-Output "$line Strict-Transport-Security Found = $output"
                    $OutputString.Add("$line Strict-Transport-Security Found = $output")
                    $element = $line, "Strict-Transport-Security", $output
                    [void]$CsvArrayList.Add($element)
                }
                else{
                    Write-Host -ForegroundColor Yellow "[•]" -NoNewline
                    Write-Host "$line Strict-Transport-Security Found = $output | " -NoNewline
                    Write-Host -ForegroundColor Yellow "Missing 'includeSubDomains' flag" 
                    $OutputString.Add("$line Strict-Transport-Security Found = $output | Missing 'includeSubDomains' flag")
                    $element = $line, "Strict-Transport-Security", "$output | Missing 'includeSubDomains' flag"
                    [void]$CsvArrayList.Add($element)
                }
                
            } else {
                Write-Host -ForegroundColor Red "[•]" -NoNewline
                Write-Output "$line Strict-Transport-Security Not found"
                $OutputString.Add("$line Strict-Transport-Security Not found")
                $element = $line, "Strict-Transport-Security", "Not Found"
                [void]$CsvArrayList.Add($element)
            }
            #-------------------Referrer-Polic----------------------------------------------
            if ($response.Headers["Referrer-Policy"]) {
                $output = $response.Headers["Referrer-Policy"]
                Write-Host -ForegroundColor Green "[•]" -NoNewline
                Write-Output "$line Referrer-Policy Found = $output"
                $OutputString.Add("$line Referrer-Policy Found = $output")
                $element = $line, "Referrer-Policy", $output
                [void]$CsvArrayList.Add($element)
            } else {
                Write-Host -ForegroundColor Red "[•]" -NoNewline
                Write-Output "$line Referrer-Policy Not found"
                $OutputString.Add("$line Referrer-Policy Not found")
                $element = $line, "Referrer-Policy", "Not Found"
                [void]$CsvArrayList.Add($element)
            }
            #-------------------------------X-Xss-Protection------------------------------
            if ($response.Headers["X-Xss-Protection"]) {
                $output = $response.Headers["X-Xss-Protection"]
                if($output -eq "1; mode=block"){
                    Write-Host -ForegroundColor Green "[•]" -NoNewline
                    Write-Output "$line X-Xss-Protection Found = $output"
                    $OutputString.Add("$line X-Xss-Protection Found = $output")
                    $element = $line, "X-Xss-Protection", $output
                    [void]$CsvArrayList.Add($element)
                }
                else{
                    Write-Host -ForegroundColor Yellow "[•]" -NoNewline
                    Write-Host "$line X-Xss-Protection Found = $output | " -NoNewline
                    Write-Host -ForegroundColor Yellow "Should be '1; mode=block' flag" 
                    $OutputString.Add("$line X-Xss-Protection Found = $output | Should be '1; mode=block'")
                    $element = $line, "X-Xss-Protection", "$output | Should be '1; mode=block'"
                    [void]$CsvArrayList.Add($element)
                }
            } else {
                Write-Host -ForegroundColor Red "[•]" -NoNewline
                Write-Output "$line X-Xss-Protection Not found"
                $OutputString.Add("$line X-Xss-Protection Not found")
                $element = $line, "X-Xss-Protection", "Not Found"
                [void]$CsvArrayList.Add($element)
            }
            #-----------------------Content-Security-Policy------------------------------------------
            if ($response.Headers["Content-Security-Policy"]) {
                $output = $response.Headers["Content-Security-Policy"]
                Write-Host -ForegroundColor Green "[•]" -NoNewline
                Write-Output "$line Content-Security-Policy Found = $output"
                $OutputString.Add("$line Content-Security-Policy Found = $output")
                $element = $line, "Content-Security-Policy", $output
                [void]$CsvArrayList.Add($element)
            } else {
                Write-Host -ForegroundColor Red "[•]" -NoNewline
                Write-Output "$line Content-Security-Policy Not found"
                $OutputString.Add("$line Content-Security-Policy Not found")
                $element = $line, "Content-Security-Policy", "Not Found"
                [void]$CsvArrayList.Add($element)
            }
            #-----------------------Feature-Policy------------------------------------------
            if ($response.Headers["Feature-Policy"]) {
                $output = $response.Headers["Feature-Policy"]
                Write-Host -ForegroundColor Green "[•]" -NoNewline
                Write-Output "$line Feature-Policy Found = $output"
                $OutputString.Add("$line Feature-Policy Found = $output")
                $element = $line, "Feature-Policy", $output
                [void]$CsvArrayList.Add($element)
            } else {
                Write-Host -ForegroundColor Red "[•]" -NoNewline
                Write-Output "$line Feature-Policy Not found"
                $OutputString.Add("$line Feature-Policy Not found")
                $element = $line, "Feature-Policy", "Not Found"
                [void]$CsvArrayList.Add($element)
            }
            #-----------------------X-Frame-Options------------------------------------------
            if ($response.Headers["X-Frame-Options"]) {
                $output = $response.Headers["X-Frame-Options"]
                if($output -eq "deny" -or $output -eq "sameorigin"){
                    Write-Host -ForegroundColor Green "[•]" -NoNewline
                    Write-Output "$line X-Frame-Options Found = $output"
                    $OutputString.Add("$line X-Frame-Options Found = $output")
                    $element = $line, "X-Frame-Options", $output
                    [void]$CsvArrayList.Add($element)
                }
                else{
                    Write-Host -ForegroundColor Yellow "[•]" -NoNewline
                    Write-Host "$line X-Frame-Options Found = $output | " -NoNewline
                    Write-Host -ForegroundColor Yellow "Should be '1; mode=block' or 'sameorigin'" 
                    $OutputString.Add("$line X-Frame-Options = $output | Should be '1; mode=block' or 'sameorigin'")
                    $element = $line, "X-Frame-Options", "$output | Should be 'deny' or 'sameorigin'"
                    [void]$CsvArrayList.Add($element)
                }
            } else {
                Write-Host -ForegroundColor Red "[•]" -NoNewline
                Write-Output "$line X-Frame-Options Not found"
                $OutputString.Add("$line X-Frame-Options Not found")
                $element = $line, "X-Frame-Options", "Not Found"
                [void]$CsvArrayList.Add($element)
            }
            if ($response.Headers["Server"]) {
                $output = $response.Headers["Server"]
                Write-Host -ForegroundColor Red "[•]" -NoNewline
                Write-Host "$line Server = $output | " -NoNewline
                Write-Host -ForegroundColor Red "This header should be surpressed if possible."
                $OutputString.Add("$line Server found")
                $element = $line, "Server", "Not Found"
                [void]$CsvArrayList.Add($element)
            }
            $respone = ''
        }
        catch {
            Write-Host "An error occurred performing the request to $line" 
            Write-Host $_
        }
        Write-Output "-----------------------------------------------------"
    }
}

if($Url){
    try {
        try { 
            Write-Output "`nChecking Http headers for $Url"
            Write-Output "-----------------------------------------------------"
            if($LinuxOS -eq $true){
                if($CookieName -and $CookieValue){
                    $Session = Set-Cookie-Params($Url)
                    if($Cert){
                        $Exists = Test-Path $Cert
                        if($Exists -eq $True){
                            $Cert = Get-PfxCertificate -FilePath $Cert
                            $response = iwr $Url -UseBasicParsing -WebSession $Session -CustomMethod $Verb -Proxy $Proxy -SkipCertificateCheck -Certificate $Cert
                        }
                        else{
                            $response = iwr $Url -UseBasicParsing -CustomMethod $Verb -Proxy $Proxy
                        }
                    }
                    else{
                        $response = iwr $Url -UseBasicParsing -WebSession $Session -CustomMethod $Verb -Proxy $Proxy -SkipCertificateCheck
                    }
                }
                elseif($CookieName -xor $CookieValue){
                    Write-Output "If a cookie is to be sent with the web request both CookieName and CookieValue must be provided."
                    exit
                }
                else{
                    if($Cert){
                        $Exists = Test-Path $Cert
                        if($Exists -eq $True){
                            $Cert = Get-PfxCertificate -FilePath $Cert
                            $response = iwr $Url -UseBasicParsing -CustomMethod $Verb -Proxy $Proxy -SkipCertificateCheck -Certificate $Cert
                        }
                        else{
                            $response = iwr $Url -UseBasicParsing -CustomMethod $Verb -Proxy $Proxy
                        }
                    }
                    else{
                        $response = iwr $Url -UseBasicParsing -CustomMethod $Verb -Proxy $Proxy -SkipCertificateCheck
                    }
                }
                if($Cookie){
                    $Session = Set-Cookie($Url)
                    if($Cert){
                        $Exists = Test-Path $Cert
                        if($Exists -eq $True){
                            $Cert = Get-PfxCertificate -FilePath $Cert
                            $response = iwr $Url -UseBasicParsing -WebSession $Session -CustomMethod $Verb -Proxy $Proxy -SkipCertificateCheck -Certificate $Cert
                        }
                        else{
                            $response = iwr $Url -UseBasicParsing -CustomMethod $Verb -Proxy $Proxy
                        }
                    }
                    else{
                        $response = iwr $Url -UseBasicParsing -WebSession $Session -CustomMethod $Verb -Proxy $Proxy -SkipCertificateCheck
                    }
                }
            }
            else{
                if($CookieName -and $CookieValue){
                    $Session = Set-Cookie-Params($Url)
                    if($Cert){
                        $Exists = Test-Path $Cert
                        if($Exists -eq $True){
                            $Cert = Get-PfxCertificate -FilePath $Cert
                            $response = iwr $Url -UseBasicParsing -WebSession $Session -Method $Verb -Proxy $Proxy -Certificate $Cert
                        }
                        else{
                            $response = iwr $Url -UseBasicParsing -Method $Verb -Proxy $Proxy
                        }
                    }
                    else{
                        $response = iwr $Url -UseBasicParsing -WebSession $Session -Method $Verb -Proxy $Proxy
                    }
                }
                elseif($CookieName -xor $CookieValue){
                    Write-Output "If a cookie is to be sent with the web request both CookieName and CookieValue must be provided."
                    exit
                }
                else{
                    if($Cert){
                        $Exists = Test-Path $Cert
                        if($Exists -eq $True){
                            $Cert = Get-PfxCertificate -FilePath $Cert
                            $response = iwr $Url -UseBasicParsing -Method $Verb -Proxy $Proxy -Certificate $Cert
                        }
                        else{
                            $response = iwr $Url -UseBasicParsing -Method $Verb -Proxy $Proxy
                        }
                    }
                    else{
                        $response = iwr $Url -UseBasicParsing -Method $Verb -Proxy $Proxy
                    }
                }
                if($Cookie){
                    $Session = Set-Cookie($Url)
                    if($Cert){
                        $Exists = Test-Path $Cert
                        if($Exists -eq $True){
                            $Cert = Get-PfxCertificate -FilePath $Cert
                            $response = iwr $Url -UseBasicParsing -WebSession $Session -Method $Verb -Proxy $Proxy -Certificate $Cert
                        }
                        else{
                            $response = iwr $Url -UseBasicParsing -Method $Verb -Proxy $Proxy
                        }
                    }
                    else{
                        $response = iwr $Url -UseBasicParsing -WebSession $Session -Method $Verb -Proxy $Proxy
                    }
                }
            }
            } 
            catch [System.Net.WebException] {
                Write-Host -ForegroundColor Red "[•] Exception: " -NoNewline
                Write-Host $_ 
                $response = $_.Exception.Response
            }
	        catch {
                if($IsLinux){
                    Write-Host -ForegroundColor Red "[•] Exception: " -NoNewline
                    Write-Host $_ 
                    $response = [Microsoft.PowerShell.Commands.BasicHtmlWebResponseObject]$_.Exception.Response
                }
            }
            if($Verbose){
                if($IsLinux){
                    Write-Host $response.BaseResponse
                }
                else{
                    Write-Host ""
                    $output = [Microsoft.PowerShell.Commands.BasicHtmlWebResponseObject]$response
                    Write-Host $output.RawContent -NoNewline
                }
	            Write-Output "-----------------------------------------------------"
            }
            #------------------Cache-Control--------------------------------------------------  
            if ($response.Headers["Cache-Control"]) {
                $output = $response.Headers["Cache-Control"]
                if($output -match "no-cache" -and $output -match "no-store"){
                    Write-Host -ForegroundColor Green "[•]" -NoNewline
                    Write-Output "$Url Cache-Control Found = $output"
                    $OutputString.Add("$Url Cache-Control Found = $output")
                    $element = $Url, "Cache-Control", $output
                }
                else{
                    Write-Host -ForegroundColor Yellow "[•]" -NoNewline
                    Write-Host "$Url Cache-Control Found = $output | " -NoNewline
                    Write-Host -ForegroundColor Yellow "Should contain 'no-cache, no-store'"
                    $OutputString.Add("$Url Cache-Control Found = $output | Should contain 'no-cache, no-store'")
                    $element = $Url, "Cache-Control", "$output | Should contain 'no-cache, no-store'"
                    [void]$CsvArrayList.Add($element)
                }
            } else {
                Write-Host -ForegroundColor Red "[•]" -NoNewline
                Write-Output "$Url Cache-Control Not found"
                $OutputString.Add("$Url Cache-Control Not found")
                $element = $Url, "Cache-Control", "Not Found"
                [void]$CsvArrayList.Add($element)
            }
            #-----------------X-Content-Type-Options---------------------------------------
            if ($response.Headers["X-Content-Type-Options"]) {
                $output = $response.Headers["X-Content-Type-Options"]
                if($output -eq "nosniff"){
                    Write-Host -ForegroundColor Green "[•]" -NoNewline
                    Write-Output "$Url X-Content-Type-Options Found = $output"
                    $OutputString.Add("$Url X-Content-Type-Options Found = $output")
                    $element = $Url, "X-Content-Type-Options", $output
                }
                else{
                    Write-Host -ForegroundColor Yellow "[•]" -NoNewline
                    Write-Host "$Url X-Content-Type-Options Found = $output | " -NoNewline
                    Write-Host -ForegroundColor Yellow "Should be 'nosniff'"
                    $OutputString.Add("$Url X-Content-Type-Options Found = $output | Should be 'nosniff'")
                    $element = $Url, "X-Content-Type-Options", "$output | Should be 'nosniff'"
                    [void]$CsvArrayList.Add($element)
                }
            } else {
                Write-Host -ForegroundColor Red "[•]" -NoNewline
                Write-Output "$Url X-Content-Type-Options Not found"
                $OutputString.Add("$Url X-Content-Type-Options Not found")
                $element = $Url, "X-Content-Type-Options", "Not Found"
                [void]$CsvArrayList.Add($element)
            }
            #-------------------Strict-Transport-Security------------------------------------
            if ($response.Headers["Strict-Transport-Security"]) {
                $output = $response.Headers["Strict-Transport-Security"]
                if($output -match "includeSubDomains"){
                    Write-Host -ForegroundColor Green "[•]" -NoNewline
                    Write-Output "$Url Strict-Transport-Security Found = $output"
                    $OutputString.Add("$Url Strict-Transport-Security Found = $output")
                    $element = $Url, "Strict-Transport-Security", $output
                    [void]$CsvArrayList.Add($element)
                }
                else{
                    Write-Host -ForegroundColor Yellow "[•]" -NoNewline
                    Write-Host "$Url Strict-Transport-Security Found = $output | " -NoNewline
                    Write-Host -ForegroundColor Yellow "Missing 'includeSubDomains' flag" 
                    $OutputString.Add("$Url Strict-Transport-Security Found = $output | Missing 'includeSubDomains' flag")
                    $element = $Url, "Strict-Transport-Security", "$output | Missing 'includeSubDomains' flag"
                    [void]$CsvArrayList.Add($element)
                }
                
            } else {
                Write-Host -ForegroundColor Red "[•]" -NoNewline
                Write-Output "$Url Strict-Transport-Security Not found"
                $OutputString.Add("$Url Strict-Transport-Security Not found")
                $element = $Url, "Strict-Transport-Security", "Not Found"
                [void]$CsvArrayList.Add($element)
            }
            #-------------------Referrer-Polic----------------------------------------------
            if ($response.Headers["Referrer-Policy"]) {
                $output = $response.Headers["Referrer-Policy"]
                Write-Host -ForegroundColor Green "[•]" -NoNewline
                Write-Output "$Url Referrer-Policy Found = $output"
                $OutputString.Add("$Url Referrer-Policy Found = $output")
                $element = $Url, "Referrer-Policy", $output
                [void]$CsvArrayList.Add($element)
            } else {
                Write-Host -ForegroundColor Red "[•]" -NoNewline
                Write-Output "$Url Referrer-Policy Not found"
                $OutputString.Add("$Url Referrer-Policy Not found")
                $element = $Url, "Referrer-Policy", "Not Found"
                [void]$CsvArrayList.Add($element)
            }
            #-------------------------------X-Xss-Protection------------------------------
            if ($response.Headers["X-Xss-Protection"]) {
                $output = $response.Headers["X-Xss-Protection"]
                if($output -eq "1; mode=block"){
                    Write-Host -ForegroundColor Green "[•]" -NoNewline
                    Write-Output "$Url X-Xss-Protection Found = $output"
                    $OutputString.Add("$Url X-Xss-Protection Found = $output")
                    $element = $Url, "X-Xss-Protection", $output
                    [void]$CsvArrayList.Add($element)
                }
                else{
                    Write-Host -ForegroundColor Yellow "[•]" -NoNewline
                    Write-Host "$Url X-Xss-Protection Found = $output | " -NoNewline
                    Write-Host -ForegroundColor Yellow "Should be '1; mode=block' flag" 
                    $OutputString.Add("$Url X-Xss-Protection Found = $output | Should be '1; mode=block'")
                    $element = $Url, "X-Xss-Protection", "$output | Should be '1; mode=block'"
                    [void]$CsvArrayList.Add($element)
                }
            } else {
                Write-Host -ForegroundColor Red "[•]" -NoNewline
                Write-Output "$Url X-Xss-Protection Not found"
                $OutputString.Add("$Url X-Xss-Protection Not found")
                $element = $Url, "X-Xss-Protection", "Not Found"
                [void]$CsvArrayList.Add($element)
            }
            #-----------------------Content-Security-Policy------------------------------------------
            if ($response.Headers["Content-Security-Policy"]) {
                $output = $response.Headers["Content-Security-Policy"]
                Write-Host -ForegroundColor Green "[•]" -NoNewline
                Write-Output "$Url Content-Security-Policy Found = $output"
                $OutputString.Add("$Url Content-Security-Policy Found = $output")
                $element = $Url, "Content-Security-Policy", $output
                [void]$CsvArrayList.Add($element)
            } else {
                Write-Host -ForegroundColor Red "[•]" -NoNewline
                Write-Output "$Url Content-Security-Policy Not found"
                $OutputString.Add("$Url Content-Security-Policy Not found")
                $element = $Url, "Content-Security-Policy", "Not Found"
                [void]$CsvArrayList.Add($element)
            }
            #-----------------------Feature-Policy------------------------------------------
            if ($response.Headers["Feature-Policy"]) {
                $output = $response.Headers["Feature-Policy"]
                Write-Host -ForegroundColor Green "[•]" -NoNewline
                Write-Output "$Url Feature-Policy Found = $output"
                $OutputString.Add("$Url Feature-Policy Found = $output")
                $element = $Url, "Feature-Policy", $output
                [void]$CsvArrayList.Add($element)
            } else {
                Write-Host -ForegroundColor Red "[•]" -NoNewline
                Write-Output "$Url Feature-Policy Not found"
                $OutputString.Add("$Url Feature-Policy Not found")
                $element = $Url, "Feature-Policy", "Not Found"
                [void]$CsvArrayList.Add($element)
            }
            #-----------------------X-Frame-Options------------------------------------------
            if ($response.Headers["X-Frame-Options"]) {
                $output = $response.Headers["X-Frame-Options"]
                if($output -eq "deny" -or $output -eq "sameorigin"){
                    Write-Host -ForegroundColor Green "[•]" -NoNewline
                    Write-Output "$Url X-Frame-Options Found = $output"
                    $OutputString.Add("$Url X-Frame-Options Found = $output")
                    $element = $Url, "X-Frame-Options", $output
                    [void]$CsvArrayList.Add($element)
                }
                else{
                    Write-Host -ForegroundColor Yellow "[•]" -NoNewline
                    Write-Host "$Url X-Frame-Options Found = $output | " -NoNewline
                    Write-Host -ForegroundColor Yellow "Should be '1; mode=block' or 'sameorigin'" 
                    $OutputString.Add("$Url X-Frame-Options = $output | Should be '1; mode=block' or 'sameorigin'")
                    $element = $Url, "X-Frame-Options", "$output | Should be 'deny' or 'sameorigin'"
                    [void]$CsvArrayList.Add($element)
                }
            } else {
                Write-Host -ForegroundColor Red "[•]" -NoNewline
                Write-Output "$Url X-Frame-Options Not found"
                $OutputString.Add("$Url X-Frame-Options Not found")
                $element = $Url, "X-Frame-Options", "Not Found"
                [void]$CsvArrayList.Add($element)
            }
            if ($response.Headers["Server"]) {
                $output = $response.Headers["Server"]
                Write-Host -ForegroundColor Red "[•]" -NoNewline
                Write-Host "$Url Server = $output | " -NoNewline
                Write-Host -ForegroundColor Red "This header should be surpressed if possible."
                $OutputString.Add("$Url Server found")
                $element = $Url, "Server", "Not Found"
                [void]$CsvArrayList.Add($element)
            }
            $respone = ''
    }
    catch {
        Write-Host "An error occurred performing the request to $Url"
        Write-Host $_
        if($Verbose){
	    Write-Host $response
	    Write-Output "-----------------------------------------------------"
        }
    }
    Write-Output "-----------------------------------------------------"

    

    if($Csv){
        Set-Content $Csv -Value $null
      
        foreach($arr in $CsvArrayList){
            $arr -join ',' | Add-Content $Csv
        }
    } 

    if($WriteToFile -eq $true){
        $OutputString | Out-File $OutputFile
    }
}
