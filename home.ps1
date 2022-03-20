# Create home directory and grant permissions with PowerShell
# Permission Home-Base: https://docs.microsoft.com/en-us/troubleshoot/windows-server/user-profiles-and-logon/create-security-enhanced-redirected-folder
<# Use the following settings for NTFS Permissions:
CREATOR OWNER - Full Control (Apply onto: Subfolders and Files Only)
System - Full Control (Apply onto: This Folder, Subfolders, and Files)
Domain Admins - Full Control (Apply onto: This Folder, Subfolders, and Files)
Everyone - Create Folder/Append Data (Apply onto: This Folder Only)
Everyone - List Folder/Read Data (Apply onto: This Folder Only)
Everyone - Read Attributes (Apply onto: This Folder Only)
Everyone - Traverse Folder/Execute File (Apply onto: This Folder Only)
#>
# Filter: https://docs.microsoft.com/en-us/powershell/module/activedirectory/get-aduser?view=windowsserver2019-ps
# Get-SmbShare home$ | Set-SmbShare -FolderEnumerationMode AccessBased -Force
Clear-Host | Out-Null
Start-Transcript -Path .\ADMakeHomeDirectory.txt
If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
 {  
 Cls  
  Write-warning "This script needs to be run As Admin go back and Run as admin"
Start-Sleep -Seconds 5
Exit
 }

$global:ou = "OU=campus"
$domain = "dc=test,dc=lab"
$driveLetter = "Z:"
$DomainsAdminsDn = (Get-ADGroup 'Domänen-Admins').DistinguishedName
# Get all user-accounts exklusive Domain Admins
$Users = Get-ADUser -Filter '(enabled -eq $true) -AND (-not(memberof -eq $DomainsAdminsDn))' -Property sAMAccountName,HomeDirectory,HomeDrive -SearchBase "$ou,$domain" | sort sAMAccountName

foreach ($User in $Users)
    { 
        Write-Host "[Gefunden:]" $User -ForegroundColor Yellow
        $sam=$user.samaccountname
        $fullPath = "\\vsrv01.test.lab\Home$\{0}" -f $sam

        Set-ADUser $User -HomeDrive $driveLetter -HomeDirectory $fullPath 
        if (!(Test-Path $fullPath)) {
          $homeShare = New-Item -path $fullPath -ItemType Directory -force -ea SilentlyContinue

          $acl = Get-Acl $homeShare
  
          $FileSystemRights = [System.Security.AccessControl.FileSystemRights]"Modify"
          $AccessControlType = [System.Security.AccessControl.AccessControlType]::Allow
          $InheritanceFlags = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit, ObjectInherit"
          # $PropagationFlags = [System.Security.AccessControl.PropagationFlags]"InheritOnly"
          $PropagationFlags = [System.Security.AccessControl.PropagationFlags]"none"
  
          $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule ($User.SID, $FileSystemRights, $InheritanceFlags, $PropagationFlags, $AccessControlType)
          $acl.AddAccessRule($AccessRule)
  
          Set-Acl -Path $homeShare -AclObject $acl -ea Stop
  
          Write-Host ("HomeDirectory created at {0}" -f $fullPath) -ForegroundColor Green
        }
        else {
          Write-Host ("HomeDirectory already exist at {0}" -f $fullPath) -ForegroundColor Red
             }
    } 

Stop-Transcript