function Enumerate-Shares{

<#
.SYNOPSIS
Simple Script used to Enumerate shares on a network.

.DESCRIPTION
This script will enumerate open shares in a network from a givin text file of PC names.

.EXAMPLE
PS C:\> Enumerate-Shares

.LINK
Github LINK
https://pfpt3223.wordpress.com/2018/12/28/assignment-2/

.NOTES
This script was created for completing the requirements of the SecurityTube PowerShell for Penetration Testers (PFPT)
Student ID: PSP-3223

Credits for https://github.com/ahhh/PSSE/blob/master/Scan-Share-Permissions.ps1
#>

	[CmdletBinding()] Param([Parameter(Mandatory = $true)][String]$PC_names)
	
	function Explore-Shares-Security($TargetHost)	
	{

		try
		{
			# Gets the shares list
			$shares = Get-WmiObject -Class win32_share -ComputerName $TargetHost | select -ExpandProperty Name  
		}
		catch
		{
			Write-Host "Unable to connect to any shares on $TargetHost"    
			$shares = $null
		}
	



		foreach ($share in $shares) 
		{  
			#print shares
			$ACL = $null  
			Write-Host $share  
			 
			
			# Get the Security Settings of the share
			$objShareSec = Get-WMIObject -Class Win32_LogicalShareSecuritySetting -Filter "name='$Share'"  -ComputerName $TargetHost 
		
			try 
			{  
				# Parse the Security Settings
				$SD = $objShareSec.GetSecurityDescriptor().Descriptor    
				foreach($ace in $SD.DACL)
				{				
					$UserName = $ace.Trustee.Name      
					If ($ace.Trustee.Domain -ne $Null) {$UserName = "$($ace.Trustee.Domain)\$UserName"}    
					If ($ace.Trustee.Name -eq $Null) {$UserName = $ace.Trustee.SIDString } 
					# Special check to see if share has extreamly insecure security permissions
					if ($ace.Trustee.Name -eq "EveryOne" -and $ace.AccessMask -eq "2032127" -and $ace.AceType -eq 0) {$UserName = "**EVERYONE** with Insecure Perms"}

					# Build our final array of permissions
					[Array]$ACL += New-Object Security.AccessControl.FileSystemAccessRule($UserName, $ace.AccessMask, $ace.AceType)  
				}            
			}  
			catch  
			{ 
				Write-Host "Unable to obtain permissions for $share" 
			}  
			$ACL  
			Write-Host $('=' * 50)  
			Write-Host $('') 
		} # Loop foreach share 
	}				






# Main code
	
	if ($PC_names)
	{
		$PCs = Get-Content $PC_names
		foreach ($pc in $PCs)
		{
			Write-Host "`n**** $pc Shares **** `n" -ForegroundColor Yellow  
			Explore-Shares-Security ($pc)
		}
	}
	
}