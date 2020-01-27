# PSHeaders
A Poweshell script for testing HTTP Headers

## Setup
The script can simply be downloaded on Windows and run from a Powershell terminal.

If on OSX or Linux first install Powershell full instructions can be found [here](https://docs.microsoft.com/en-us/powershell/scripting/install/installing-powershell-core-on-linux?view=powershell-7) however it is included in most good pacakge managers.       

Usage:                                            
    -Help        - Display this message.                
    -Url         - Specifies the URL to use                         
    -File        - Specifies a file contianing URL's to be used.               
    -Proxy       - Proxy server to use. E.g. http://127.0.0.1:8000              
    -OutputFile  - The location where output will be written to disk.          
    -Csv         - The location where output will be written to disk            
                   in CSV format.                                               
    -CookieName  - Used when supplying a cookie with a web reqest.                      
                   Name of the cookie to be supplied. Must be used in               
                   conjunction with -CookieString                               
    -CookieValue - Used when supplying a cookie with a web reqest.                  
                   Value of the cookie to be supplied. Must be used                 
                   in conjunction with -CookieName                           
