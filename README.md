# PSHeaders
A Poweshell script for testing HTTP Headers

    ____  _____ __  __               __                  
   / __ \/ ___// / / /__  ____ _____/ /__  __________    
  / /_/ /\__ \/ /_/ / _ \/ __ / __  / _ \/ ___/ ___/    
 / ____/___/ / __  /  __/ /_/ / /_/ /  __/ /  (__  )      
/_/    /____/_/ /_/\___/\__,_/\__,_/\___/_/  /____/          
-----------------------------------------------------      
Author : Andy Bowden                        
Email  : Andy.Bowden@coalfire.com                 
Version: PSHeaders-0.1                                       
-----------------------------------------------------              
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
