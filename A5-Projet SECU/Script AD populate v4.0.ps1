<# Notes

#>

#param([parameter(Mandatory=$true)] [String]$OU_CSV,[parameter(Mandatory=$true)] [String]$GROUPS_CSV)

Import-Module ActiveDirectory
Import-Module Microsoft.Powershell.security

$OU_CSV = "C:\Users\Administrateur\Desktop\OUList.csv"
$GROUPS_CSV = "C:\Users\Administrateur\Desktop\GroupList.csv"
$USERS_CSV = "C:\Users\Administrateur\Desktop\UserList.csv"

$DC1 = "alphapar"
$DC2 = "fr"
$FileServer = "192.168.100.4"
$RootShare = "Root"
$UsersShare = "Users"

$listOU = Import-Csv $OU_CSV -Delimiter "|"
$listGROUPS = Import-Csv $GROUPS_CSV -Delimiter "|"
$listUSERS = Import-Csv $USERS_CSV -Delimiter "|"


function CreateOU
{
    foreach($OU in $listOU)
    {
        try
        {
            $OU.Path = $OU.Path.Replace(" ",",")
            Write-Host -ForegroundColor Yellow $OU.Name $OU.Path
            New-ADOrganizationalUnit -Name $OU.Name -Path $OU.Path -ProtectedFromAccidentalDeletion $False
            Write-Host -ForegroundColor Green "OU" $OU.Name "created"

        }
        catch{Write-Host $error[0].Exception.Message}
    }
}

function CreateRootShare
{
    $session = New-CimSession -ComputerName "SRV-FILESERVER1"
    $RootDir = New-Item -path "E:\$($RootShare)" -ItemType Directory -Force -ea Stop
    $UsersDir = New-Item -path "E:\$($RootShare)\$($UsersShare)" -ItemType Directory -Force -ea Stop
    $acl1 = Get-Acl $RootDir
    $acl2 = Get-Acl $UsersDir
    $acl1.SetAccessRuleProtection($True,$False)
    $acl2.SetAccessRuleProtection($True,$False)
    New-SmbShare -Name $RootShare -Path "E:\$($RootShare)" -ChangeAccess "$($DC1)\Utilisateurs du domaine" -FolderEnumerationMode AccessBased -CimSession $session
    Grant-SmbShareAccess -Name $RootShare -AccountName "$($DC1)\administrateur" -AccessRight Full -CimSession $session
    Remove-CimSession -CimSession $session
}

function CreateGroups
{
    foreach($GROUP in $listGROUPS)
    {
        try
        {
            $GROUP.Path = $GROUP.Path.Replace(" ",",")
            Write-Host -ForegroundColor Yellow $GROUP.Name
            New-ADGroup -Name $GROUP.Name -GroupScope $GROUP.Scope -GroupCategory $GROUP.Category -Path $GROUP.Path
            Write-Host -ForegroundColor Green "Group" $GROUP.Name "created"

            if(-not (Test-Path "\\$($FileServer)\Root\$($GROUP.ShareName)"))
            {
                $dir = New-Item -path "\\$($FileServer)\Root\$($GROUP.ShareName)" -ItemType Directory -Force -ea Stop
                $acl = Get-Acl $dir
                $acl.SetAccessRuleProtection($True,$False)
                $rule1 = New-Object System.Security.AccessControl.FileSystemAccessRule("$($DC1)\Administrateur","FullControl","Allow")
                $acl.SetAccessRule($rule1)
                Set-Acl -Path $dir -AclObject $acl
            }
            if($GROUP.Scope -eq "DomainLocal")
            {
               $acl = Get-Acl "\\$($FileServer)\Root\$($GROUP.ShareName)"
               if(($GROUP.Name).Substring(($GROUP.Name).Length -2) -eq "RO")
               {
                    $rule1 = New-Object System.Security.AccessControl.FileSystemAccessRule("$($DC1)\$($GROUP.Name)","Read","Allow")
                    $acl.SetAccessRule($rule1)
                    Set-Acl -Path "\\$($FileServer)\Root\$($GROUP.ShareName)" -AclObject $acl
               }
               elseif(($GROUP.Name).Substring(($GROUP.Name).Length -2) -eq "RW")
               {
                    $rule1 = New-Object System.Security.AccessControl.FileSystemAccessRule("$($DC1)\$($GROUP.Name)","Modify","Allow")
                    $acl.SetAccessRule($rule1)
                    Set-Acl -Path "\\$($FileServer)\Root\$($GROUP.ShareName)" -AclObject $acl
               }        
            }
        }
        catch{Write-Host $error[0].Exception.Message}
    }
}

function CreateUsersAndShares
{
    foreach($USER in $listUSERS)
    {
        try
        {
            Write-Host -ForegroundColor Yellow $USER.FirstName $USER.LastName "in group" $USER.Dpt

            $FullName = $USER.FirstName + " " + $USER.LastName
            $Login = $USER.Firstname + "." + $USER.LastName
            $Pwd = ConvertTo-SecureString "Default99" -AsPlainText -Force
            $OU = "OU="+$USER.Dpt+","+"OU=Users,OU=HQ,OU=Root,DC="+$DC1+",DC="+$DC2 

            New-ADUser -Name $FullName -SamAccountName $Login -DisplayName $FullName -GivenName $USER.FirstName -Surname $USER.LastName -AccountPassword $Pwd -Path $OU -Department $USER.Dpt -Enabled $true
            $GroupAdd = "G_"+$USER.Dpt
            Add-ADGroupMember -Identity $GroupAdd -Members $Login

            Write-Host -ForegroundColor Green "User" $USER.FirstName $USER.LastName "created and added to" $USER.Dpt

            $dir1 = New-Item -path "\\$($FileServer)\Root\Users" -ItemType Directory -Force -ea Stop
            $acl1 = Get-Acl $dir1
            $acl1.SetAccessRuleProtection($True,$False)
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule("$($DC1)\Utilisateurs du domaine","ReadAndExecute","Allow")
            $rule2 = New-Object System.Security.AccessControl.FileSystemAccessRule("$($DC1)\Administrateur","FullControl","Allow")
            $acl1.SetAccessRule($rule)
            $acl1.SetAccessRule($rule2)
            Set-Acl -Path $dir1 -AclObject $acl1

            Set-ADUser $Login -HomeDrive "Z:" -HomeDirectory "\\$($FileServer)\Root\Users\$($Login)" -ea Stop
            $dir2 = New-Item -path "\\$($FileServer)\Root\Users\$($Login)" -ItemType Directory -Force -ea Stop
            $acl2 = Get-Acl $dir2
            $acl2.SetAccessRuleProtection($True,$False)
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($Login,"Modify","Allow")
            $rule2 = New-Object System.Security.AccessControl.FileSystemAccessRule("$($DC1)\Administrateur","FullControl","Allow")
            $acl2.SetAccessRule($rule)
            $acl2.SetAccessRule($rule2)
            Set-Acl -Path $dir2 -AclObject $acl2

            #$session = New-CimSession -ComputerName "SRV-FILESERVER1"
            #New-SmbShare -Name "$($Login)$" -Path "E:\Root\Users\$($Login)" -ChangeAccess $Login -FolderEnumerationMode AccessBased -CimSession $session
            #Remove-CimSession -CimSession $session

        }
        catch{Write-Host $error[0].Exception.Message}
    }
}


CreateOU
#CreateRootShare
CreateGroups
CreateUsersAndShares

