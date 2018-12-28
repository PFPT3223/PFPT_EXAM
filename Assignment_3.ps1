function Enumerate-Directories{
<#
.SYNOPSIS
Enumerate a directory and find writeable directories for non admin user.

.DESCRIPTION
this scritpt enumerate a givin user (Non-admin) to find which writeable directories.


.PARAMETER path_
The path of the directory to be checked.

.PARAMETER USERNAME_
the user name to check its permissions.

.EXAMPLE
PS C:\>  Enumerate-Directories -USERNAME_ pc1 -path_ C:\windows\system32


.LINK
https://pfpt3223.wordpress.com/2018/12/28/assignment-3/

.NOTES
This script was created for completing the requirements of the SecurityTube PowerShell for Penetration Testers (PFPT)
Student ID: PSP-3223

#>  


    param(
    [parameter(Mandatory = $false)][string]$path_ = "C:\windows\system32",
    [parameter(Mandatory = $true)][string]$USERNAME_ 
)


#take username input from user
#$USERNAME_= Read-Host "Enter non-admin username"

#save all directories name inside "C:\windows\system32" in $all_dir as full path
$all_dir = Get-ChildItem $path_ -Directory
$dir_names = foreach ($directories in $all_dir){$directories.Name}
$full_directory_path = foreach ($D in $dir_names){"$path_\$D"}

#test every directory to check if it is writeable
$ErrorActionPreference = 'SilentlyContinue'
try{
    foreach ($s in $full_directory_path)
    {
        $x = icacls $s
        if ( ($x) -match $USERNAME_){
            #$x
            "*************************************"
            " "
            "Directory  "
            write-host ( $s + " >>  is writeable for user (( " +  $USERNAME_ + " )) ") -ForegroundColor Green
             " "
            }
        
    }


}

catch {
   write-host "Error !!"  -ForegroundColor Red 
}

}
