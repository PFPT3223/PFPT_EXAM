function Transfer-File-Over-PSRemoting{

<#
.SYNOPSIS
Simple Script used to transfer files over PSRemoting.

.DESCRIPTION
Use PSSession to transfer file over PSRemmoting.

.PARAMETER Local_File
The local path of the file to be transferred.

.PARAMETER Remote_Destination
The Remote Destination of the transferred file.

.PARAMETER computer_name
computer name to connect to.
    
.PARAMETER domain
domain name.
    
.PARAMETER username
username to be authenticated as.
    
.EXAMPLE
PS C:\>  Transfer-File-Over-PSRemoting -Local_File "C:\Users\userX\Desktop\file.txt" -Remote_Destination "C:\" -computer_name pc1 -domain companyX -username john

.LINK
https://pfpt3223.wordpress.com/2018/12/28/assignment-6/

.NOTES
This script was created for completing the requirements of the SecurityTube PowerShell for Penetration Testers (PFPT)
Student ID: PSP-3223

#>


param(
    [parameter(Mandatory = $true)][string]$Local_File,
    [parameter(Mandatory = $true)][string]$Remote_Destination
    [parameter(Mandatory = $true)][string]$computer_name
    [parameter(Mandatory = $true)][string]$domain
    [parameter(Mandatory = $true)][string]$username
)
$ErrorActionPreference = 'SilentlyContinue'

#create new ps session 
$session = New-PSSession –ComputerName $computer_name -Credential $domain\$username

#start transfer file from local to remote machine using pssession
Copy-Item -Path $Local_File -Destination $Remote_Destination -ToSession $session


}