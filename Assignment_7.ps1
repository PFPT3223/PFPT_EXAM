function Start-WebServer{
    
<#
.SYNOPSIS
Simple Web Server Script written in PowerShell.

.DESCRIPTION
This script start a simple web server and you can list, delete, download, upload files over HTTP.

.PARAMETER WebRoot
Webroot of server, the local directory to be shared for listing, reading, writing, and deleting files.

.PARAMETER URL
The url to run the webserver on. -u for short

.EXAMPLE
PS C:\> Start-WebServer

.LINK
https://pfpt3223.wordpress.com/2018/12/28/assignment-7/

.NOTES
This script was created for completing the requirements of the SecurityTube PowerShell for Penetration Testers Certification Exam:
http://www.securitytube-training.com/online-courses/powershell-for-pentesters/

Student ID: PSP-3223
#>           
[CmdletBinding()] Param( 

    [Parameter(Mandatory = $false)][String]$WebRoot = ".",
    [Parameter(Mandatory = $false)][String]$url = 'http://localhost:8000/'

)

    # Our responses to the various API endpoints
    $routes = @{
      # Simple Tes
      "/test" = { return "Test" } 

      # Lists all files in the WebRoot
      "/list" = { return dir $WebRoot }

      # Download web root specified in the query string EX: http://localhost:8000/download?name=Q7.ps1
      "/download" = { return (Get-Content (Join-Path $WebRoot ($context.Request.QueryString[0]))) }

      # Delete the file from the WebRoot specificed in the query string
      "/delete" = { (rm (Join-Path $WebRoot ($context.Request.QueryString[0])))
                     return "Succesfully deleted" }

      # Creates a file based on the contents of an uploaded file via a get request
      "/upload" = { (Set-Content -Path (Join-Path $WebRoot ($context.Request.QueryString[0])) -Value ($context.Request.QueryString[1]))
                     return "Succesfully uploaded" }
                     
      # Shuts down the webserver remotly
      "/exit" = { exit }
    }
     




    # credits for Wagnerandrade's SimpleWebServer 
    $listener = New-Object System.Net.HttpListener
    $listener.Prefixes.Add($url)
    $listener.Start()
    
    Write-Host "[-]Listening at $url..." -ForegroundColor Yellow
     
    try{
      while ($listener.IsListening)
      {
        $context = $listener.GetContext()
        $requestUrl = $context.Request.Url
        $response = $context.Response
       
        Write-Host ''
        Write-Host "> $requestUrl"
       
        $localPath = $requestUrl.LocalPath
        $route = $routes.Get_Item($requestUrl.LocalPath)
       
        if ($route -eq $null) # If a route dosn't exist, we 404
        {
          $response.StatusCode = 404
        }
        else # Else, follow the route and it's returned content
        {
          $content = & $route
          $buffer = [System.Text.Encoding]::UTF8.GetBytes($content)
          $response.ContentLength64 = $buffer.Length
          $response.OutputStream.Write($buffer, 0, $buffer.Length)
        }
        
        $response.Close()
        $responseStatus = $response.StatusCode
        Write-Host "< $responseStatus"
      }
    }catch{ }
  }
