<# Notes
    
#> 

$dc1 = "isec-telecom"
$dc2 = "local"


Import-Module ActiveDirectory
Import-Module 'Microsoft.Powershell.Security'


$myOUs = @("Direction", "AdminFinance", "Technique", "Commercial", "RH")
$myGroups = @("Employes", "Direction", "AdminFinance", "Technique", "Commercial", "RH")

$scriptPath = $MyInvocation.MyCommand.Path
$dir = Split-Path $scriptPath

$users = Import-Csv -Delimiter ";" -Path "C:\usersTelecom.csv"

#********************Création des OU********************************

New-ADOrganizationalUnit -Name "Employes" -Path "dc=$dc1,dc=$dc2" -ProtectedFromAccidentalDeletion:$false
New-ADOrganizationalUnit -Name "Ordinateurs" -Path "dc=$dc1,dc=$dc2" -ProtectedFromAccidentalDeletion:$false
New-ADOrganizationalUnit -Name "ACL" -Path "dc=$dc1,dc=$dc2" -ProtectedFromAccidentalDeletion:$false

foreach($OU in $myOUs)
{
    New-ADOrganizationalUnit -Name $OU -Path "ou=Employes,dc=$dc1,dc=$dc2" -ProtectedFromAccidentalDeletion:$false
    New-ADOrganizationalUnit -Name $OU -Path "ou=Ordinateurs,dc=$dc1,dc=$dc2" -ProtectedFromAccidentalDeletion:$false
}


#********************Création des Groupes********************************

    New-ADGroup -Name Employes -GroupScope Global -GroupCategory Security -Path "ou=Employes,dc=$dc1,dc=$dc2"
    New-ADGroup -Name Ordinateurs -GroupScope Global -GroupCategory Security -Path "ou=Ordinateurs,dc=$dc1,dc=$dc2"
    New-ADGroup -Name Direction -GroupScope Global -GroupCategory Security -Path "ou=Direction,ou=Employes,dc=$dc1,dc=$dc2"
    New-ADGroup -Name AdminFinance -GroupScope Global -GroupCategory Security -Path "ou=AdminFinance,ou=Employes,dc=$dc1,dc=$dc2"
    New-ADGroup -Name Technique -GroupScope Global -GroupCategory Security -Path "ou=Technique,ou=Employes,dc=$dc1,dc=$dc2"
    New-ADGroup -Name Commercial -GroupScope Global -GroupCategory Security -Path "ou=Commercial,ou=Employes,dc=$dc1,dc=$dc2"
    New-ADGroup -Name RH -GroupScope Global -GroupCategory Security -Path "ou=RH,ou=Employes,dc=$dc1,dc=$dc2"

    foreach ($group in $myGroups)
    {
        New-ADGroup -Name "ACL_$($group)_CT" -GroupScope DomainLocal -GroupCategory Security -Path "ou=ACL,dc=$dc1,dc=$dc2"
        New-ADGroup -Name "ACL_$($group)_RO" -GroupScope DomainLocal -GroupCategory Security -Path "ou=ACL,dc=$dc1,dc=$dc2"
        New-ADGroup -Name "ACL_$($group)_RW" -GroupScope DomainLocal -GroupCategory Security -Path "ou=ACL,dc=$dc1,dc=$dc2"
    }

#********************Ajout des Groupes aux groupes********************************

    Add-ADGroupMember -Identity ACL_Direction_RW -Members Direction
    Add-ADGroupMember -Identity ACL_AdminFinance_RW -Members AdminFinance
    Add-ADGroupMember -Identity ACL_Technique_RW -Members Technique
    Add-ADGroupMember -Identity ACL_Commercial_RW -Members Commercial
    Add-ADGroupMember -Identity ACL_RH_RW -Members RH
    Add-ADGroupMember -Identity ACL_Employes_RW -Members Employes

    Add-ADGroupMember -Identity Employes -Members Direction, AdminFinance, Technique, Commercial, RH


#********************Création des Users********************************

foreach ($user in $users)
{   
    $name = $user.firstName + " " + $user.lastName
    $fname = $user.firstName
    $lname = $user.lastName
    $login = $user.firstName + "." + $user.lastName
    $Upassword = "Root365it"
    $dept = $user.dpt

    $RootOU = "ou=$dept,ou=Employes,dc=$dc1,dc=$dc2"

    New-ADUser -Name $name -SamAccountName $login -UserPrincipalName $login -DisplayName $name -GivenName $fname -Surname $lname -AccountPassword (ConvertTo-SecureString $Upassword -AsPlainText -Force) -Path $RootOU -Department $dept -Enabled $true
    Add-ADGroupMember -Identity $dept -Members $login
    echo "Utilisateur ajouté : $name"

}

#********************Creation des dossiers********************************

$myDir = @("SHARE", "USERS_DIR", "SHARE\Direction", "SHARE\AdminFinance", "SHARE\Technique", "SHARE\Commercial", "SHARE\RH", "SHARE\Employes")

foreach($dir in $myDir)
{
    if( -not (Test-Path -Path "C:\$($dir)"))
    {
        New-Item -ItemType directory -Path "C:\$($dir)"
        Get-Item "C:\$($dir)" | Disable-NTFSAccessInheritance
        Get-Item "C:\$($dir)" | Remove-NTFSAccess -Account "Utilisateurs" -AccessRights FullControl
    }
}

foreach($user in $users)
{
    $login = $user.firstName + "." + $user.lastName

    if( -not (Test-Path -Path "C:\USERS_DIR\$($login)"))
    {
        New-Item -ItemType directory -Path "C:\USERS_DIR\$($login)"
        Get-Item "C:\USERS_DIR\$($login)" | Disable-NTFSAccessInheritance
        Get-Item "C:\USERS_DIR\$($login)" | Remove-NTFSAccess -Account "Utilisateurs" -AccessRights FullControl
        Get-Item "C:\USERS_DIR\$($login)" | Add-NTFSAccess -Account "$dc1\$login" -AccessRights FullControl
    }
}

#********************Creation des partages********************************

$myShares = @("Direction", "AdminFinance", "Technique", "Commercial", "RH", "Employes")

foreach($share in $myShares)
{
    if(!(Get-SmbShare -Name $share -ea 0))
    {
        New-SmbShare -Name $share -Path "C:\SHARE\$($share)" -ChangeAccess $share -FolderEnumerationMode AccessBased
    }
}

foreach($user in $users)
{
    $login = $user.firstName + "." + $user.lastName

    if(!(Get-SmbShare -Name $login -ea 0))
    {
        New-SmbShare -Name $login -Path "C:\USERS_DIR\$($login)" -ChangeAccess $login -FolderEnumerationMode AccessBased
    }
}

#********************Droits service Direction********************************

if(!(Get-SmbShare -Name SHARE -ea 0))
{
    New-SmbShare -Name SHARE -Path "C:\SHARE" -ChangeAccess Direction -FolderEnumerationMode AccessBased
}

$direction = @("SHARE", "SHARE\AdminFinance", "SHARE\Metiers", "SHARE\Commercial", "SHARE\RH")
foreach($right in $direction)
{
    Get-Item "C:\$right" | Add-NTFSAccess -Account ACL_Direction_CT -AccessRights FullControl
    Get-Item "C:\$right" | Add-NTFSAccess -Account ACL_Direction_RO -AccessRights Read
    Get-Item "C:\$right" | Add-NTFSAccess -Account ACL_Direction_RW -AccessRights Modify   
}

#********************Droits Supplémentaires********************************

Get-Item "C:\SHARE\Employes" | Add-NTFSAccess -Account ACL_Employes_CT -AccessRights FullControl
Get-Item "C:\SHARE\Employes" | Add-NTFSAccess -Account ACL_Employes_RO -AccessRights Read
Get-Item "C:\SHARE\Employes" | Add-NTFSAccess -Account ACL_Employes_RW -AccessRights Modify

foreach($OU in $myOUs)
{
    Get-Item "C:\SHARE\$($OU)" | Add-NTFSAccess -Account "ACL_$($OU)_CT" -AccessRights FullControl
    Get-Item "C:\SHARE\$($OU)" | Add-NTFSAccess -Account "ACL_$($OU)_RO" -AccessRights Read
    Get-Item "C:\SHARE\$($OU)" | Add-NTFSAccess -Account "ACL_$($OU)_RW" -AccessRights Modify
}



Pause


