# PSHeaders
A Poweshell script for testing HTTP headers from a server for best security practices.

## Setup
The script can simply be downloaded on Windows and run from a Powershell terminal.

If on OSX or Linux first install Powershell full instructions can be found [here](https://docs.microsoft.com/en-us/powershell/scripting/install/installing-powershell-core-on-linux?view=powershell-7) however it is included in most good pacakge managers.       

Then use `pwsh PSHeaders.ps1 -Help` to see the help menu below along with a nice bit of ASCII art.

## Usage                                            
    -Help        - Display this message.                
    -Url         - Specifies the URL to use                         
    -File        - Specifies a file contianing URL's to be used.               
    -Proxy       - Proxy server to use. E.g. http://127.0.0.1:8000              
    -OutputFile  - The location where output will be written to disk.          
    -Csv         - The location where output will be written to disk            
                   in CSV format.       
    -Cert        - Specifices a PFX file to use as the client certificate    
    -Verb        - Specifies the HTTP Verb to use e.g. GET, PUT, POST etc.    
                   Currently Powershell versions prior to 6.0 can only use    
                   Standard verbs.                                             
    -CookieName  - Used when supplying a cookie with a web reqest.                      
                   Name of the cookie to be supplied. Must be used in               
                   conjunction with -CookieValue                               
    -CookieValue - Used when supplying a cookie with a web reqest.                  
                   Value of the cookie to be supplied. Must be used                 
                   in conjunction with -CookieName                           
