function SetIpConfiguration
{
    Write-Host -fore Cyan "Do you want to configure TCP/IP settings ? [y/n]"
    $answer = Read-Host 

    if($answer -eq "y")
    {
        #---------------------------------USER QUESTIONS------------------------------------------

        Write-Host -fore Cyan "Select interface's IP address :"
        $IP = Read-Host

        Write-Host -fore Cyan "Select a gateway address :"
        $GATEWAY = Read-Host

        Write-Host -fore Cyan "Select CIDR subnet mask (ex : 24) :"
        $MASK = Read-Host 

        Write-Host -fore Cyan "Select DNS 1 server (ex : 8.8.8.8) :"
        $DNS1 = Read-Host 

        Write-Host -fore Cyan "Select DNS 2 server (ex : 8.8.4.4) :"
        $DNS2 = Read-Host 

        #-------------------------------------CHECKING--------------------------------------------
        $adapter = Get-NetAdapter         # on obtient un tableau de la liste des interfaces
        
        
        if($adapter.Name -is [system.array])  # on verifie si il y a plusieurs noms d'interfaces et donc plusieurs cartes réseau
        {
            $i=1
            Write-Host -fore Yellow "Il y a plusieurs interfaces :"
            foreach ($int in $adapter.name)
            {  
                Write-Host -fore Yellow "$i : $int"
                $i++
            }
            $i--
            Write-Host -fore Yellow "Laquelle voulez-vous configurer ? [1-$i]"
            $choice = Read-Host      
            $index = $adapter.ifIndex[$choice-1]    
        }
        else
        {
            $choice=0
            Write-Host -fore Green "Il y a 1 seule interface : $($adapter.Name)"
            $index = $adapter.ifIndex
        }
        #$eth = $adapter.Name[$choice-1]    

        #------------------------------RESET CONFIGURATION----------------------------------------

        $interface = Get-NetIPInterface -InterfaceIndex "$index" -AddressFamily IPv4
        # Remove the static default gateway
        $interface | Remove-NetRoute -AddressFamily IPv4 -Confirm:$false
        # Set interface to "Obtain an IP address automatically"
        $interface | Set-NetIPInterface -Dhcp Enabled
        # Set interface to "Obtain DNS server address automatically"
        $interface | Set-DnsClientServerAddress -ResetServerAddresses

        #------------------------------SETTING NEW CONFIG-----------------------------------------

        #Remove-NetIPAddress -InterfaceIndex $index
        New-NetIPAddress –interfaceIndex $index -IPAddress $IP -DefaultGateway $GATEWAY -AddressFamily IPv4 -PrefixLength $MASK
        Set-DNSClientServerAddress –interfaceIndex $index –ServerAddresses ($DNS1,$DNS2)

        $inf = Get-NetIPAddress -InterfaceIndex $index

        Write-Host -fore Magenta "----------CONFIGURATION FEEDBACK----------"
        Write-Host -fore Green "IP address set to $($inf.IPv4address) and subnet mask to /$($inf.PrefixLength) on interface $($inf.InterfaceAlias)"
        Write-Host -fore Magenta "------------------------------------------"
    }
    else
    {
        Write-Host -fore Red "Skipping TCP/IP configuration..."
    }
}

function SetComputerConfiguration
{
    Write-Host -fore Cyan "Do you want to configure Hostname and Domain ? [y/n]"
    $answer = Read-Host 

    if($answer -eq "y")
    {
        Write-Host -fore Yellow "Please enter hostname for this computer : "
        $hostname = Read-Host 
        $computer = Get-WmiObject Win32_ComputerSystem
        $computer.Rename($hostname)    

        Write-Host -fore Red "Do you want to restart computer now ? [y/n]" 
        $answer = Read-Host 
        if($answer -eq "y")
        {
            $hostname = hostname
            Restart-Computer -ComputerName $hostname -Force 
        }
    }
    else
    {
        Write-Host -fore Red "Skipping Hostname and Domain configuration..."
    }   
}
function InstallNewForest
{
    $domain = "contoso.local"
    $netbios ="CONTOSO"
    $mdp = "Root365it"
    $key = ConvertTo-SecureString $mdp -AsPlainText -Force

    Write-Host -fore Cyan "Do you want to install Domain Controller on this computer ? [y/n]"
    $answer = Read-Host 

    if($answer -eq "y")
    {
        $status = Get-WindowsFeature AD-Domain-Services   # ici on verifie si le DC est déja installé ou non sur le serveur
        if($status.InstallState -eq "Available")
        {
            Install-windowsfeature -name AD-Domain-Services –IncludeManagementTools       
        }
        else
        {
            write-host -fore red "can't install AD-DS role, state is $($status.InstallState)"
        }

        $forest = (gwmi win32_computersystem)
        if ($forest.partofdomain -eq $true)      # ici on verifie si l'ordinateur fait parti d'un domaine ou non
        {
            write-host -fore green "This computer is already domain joined : $($forest.Domain)"
        } 
        else 
        {
            write-host -fore Yellow "WORKGROUP detected, starting Forest installation..."

            Import-Module ADDSDeployment
            Install-ADDSForest `            # ici on installe une nouvelle forêt car il s'agit de la premiere installation. Si une foret existe deja, il faut utiliser la commande : Install-ADDSDomainController
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
              -SafeModeAdministratorPassword $key `
              -Force:$true 
        }
    }
    else
    {
        Write-Host -fore Red "Skipping AD-DS installation..."
    }    
}

function SetDNSConfiguration
{
    Write-Host -fore Cyan "Do you want to configure your DNS server ? [y/n]"
    $answer = Read-Host 

    if($answer -eq "y")
    {
        $netID="10.255.255.0/24"      
        Add-DnsServerPrimaryZone `
            -NetworkId $netID `
            -DynamicUpdate Secure `
            -ReplicationScope Forest 
    }
    else
    {
        Write-Host -fore Red "Skipping DNS configuration..."
    }    
}

SetIpConfiguration
SetComputerConfiguration
InstallNewForest
SetDNSConfiguration

