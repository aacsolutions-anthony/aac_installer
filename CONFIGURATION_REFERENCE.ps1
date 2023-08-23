# CONFIGURATION POWERSHELL SRC
# THIS IS SRC FOR THE POWERSHELL USED IN THE GO INSTALLER FOR THE SERVER SETUP 

# Copy folders

# need to merge pulse live to create up to date version with everything in it. 
# 
Copy-Item -Path .\Server\* -Destination 'C:\program files\pulselive' -Recurse -Force
Copy-Item -Path .\Max\* -Destination 'C:\program files\pulselive\max' -Recurse -Force
Expand-Archive -Path .\Client.zip -DestinationPath 'c:\inetpub\wwwroot\pulselive' -Force

# Import the WebAdministration module for IIS management
Import-Module WebAdministration

# Set application pool recycling times
Set-ItemProperty -Path 'IIS:\AppPools\DefaultAppPool' -Name Recycling.periodicRestart.schedule -Value @{value='06:00:00','09:00:00'}

# Convert PulseLive to an application
New-WebApplication -Name "PulseLive" -Site "Default Web Site" -PhysicalPath 'c:\inetpub\wwwroot\pulselive' -ApplicationPool "DefaultAppPool"

# Create registry keys and values
New-Item -Path 'HKLM:\Software\AAC\L' -Force
New-ItemProperty -Path 'HKLM:\Software\AAC\L' -Name 'K' -Value 'Your7DigitKey' -PropertyType 'String' -Force

# Copy the license file
Copy-Item -Path .\pulselive.lic -Destination 'c:\program files\pulselive' -Force

# Set power configuration to never sleep
powercfg /change -standby-timeout-ac 0

# Set folder permissions
$acl = Get-Acl 'c:\inetpub\wwwroot\pulselive\CreatedReports'
$permission = 'IIS_IUSRS','FullControl','Allow'
$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
$acl.SetAccessRule($accessRule)
$acl | Set-Acl 'c:\inetpub\wwwroot\pulselive\CreatedReports'

$acl = Get-Acl 'c:\inetpub\wwwroot\pulselive\Logs'
$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
$acl.SetAccessRule($accessRule)
$acl | Set-Acl 'c:\inetpub\wwwroot\pulselive\Logs'
