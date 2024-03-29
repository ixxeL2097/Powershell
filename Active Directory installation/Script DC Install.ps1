
$domain = "contoso.local"
$netbios ="CONTOSO"
$mdp = "Root365it"
$key = ConvertTo-SecureString $mdp -AsPlainText -Force

$answer = Read-Host "Do you want to install Domain Controller on this computer ? [y/n]"

    if($answer -eq "y")
    {
        $status = Get-WindowsFeature AD-Domain-Services
        if($status.InstallState -eq "Available")
        {
            Install-windowsfeature -name AD-Domain-Services –IncludeManagementTools

            Import-Module ADDSDeployment
            Install-ADDSForest `
             -DomainName $domain `
             -DomainNetbiosName $netbios `
             -CreateDnsDelegation:$false `
             -ForestMode Win2008R2 `
             -DomainMode Win2008R2 `
             -InstallDns:$true `
             -NoRebootOnCompletion:$true `
             -SysvolPath "C:\Windows\SYSVOL" `
             -DatabasePath "C:\Windows\NTDS" `
             -LogPath "C:\Windows\NTDS" `
             -Force:$true        
        }
        else
        {
            echo "can't install AD-DS role, state is $($status.InstallState)"
        }
    }
    else
    {
        echo "Cancelling AD-DS installation..."
    }











Install-windowsfeature -name AD-Domain-Services –IncludeManagementTools
Import-Module ADDSDeployment
Install-ADDSForest `
 -DomainName $domain `
 -DomainNetbiosName $netbios `
 -CreateDnsDelegation:$false `
 -ForestMode Win2008R2 `
 -DomainMode Win2008R2 `
 -InstallDns:$true `
 -NoRebootOnCompletion:$true `
 -SysvolPath "C:\Windows\SYSVOL" `
 -DatabasePath "C:\Windows\NTDS" `
 -LogPath "C:\Windows\NTDS" `
 -Force:$true

