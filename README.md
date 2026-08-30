# PSHeaders
A Poweshell script for auditing HTTP headers from a server for best security practices.

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
    -Cookie      - This parameter can be used to pass cookies directly out
                   of HTTP requests for automatic parsing however cannot be
                   used if the cookie contains a "=" character in the value.
                   If you need to pass an "=" use the -CookieName and 
                   -CookieValue parameters.                                             
    -CookieName  - Used when supplying a cookie with a web reqest.                      
                   Name of the cookie to be supplied. Must be used in               
                   conjunction with -CookieValue                               
    -CookieValue - Used when supplying a cookie with a web reqest.                  
                   Value of the cookie to be supplied. Must be used                 
                   in conjunction with -CookieName      

## Examples   
Perform a request to Google:     
`./PSHeaders -u google.com`    

Perform a request to all URLs/IP addresses in a file:    
`./PSHeaders -f file.txt`   

Perform a request to Google and output to a CSV file:     
`./PSHeaders -u google.com -Csv csv.xls`     

Perform a GET request to Google as oppose to a HEAD request:     
`./PSHeaders -u google.com -Verb GET`     
    
Perform a request to Google using the cookies 1=2;3=4;5=6; and send the request via a proxy at 127.0.0.1:8080:    
`./PSHeaders -u http://google.com -Cookie "1=2;3=4;" -CookieName 5 -CookieValue 6 -Proxy http://127.0.0.1:8080`    
