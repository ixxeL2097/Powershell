#----------------VARIABLES GLOBALES-------------------------------

$IP = ""
$GATEWAY = ""
$MASK = ""
$DNS1 = ""
$DNS2 = ""
$DOMAIN = ""
$NETBIOS = ""
$NETID = ""
$REVERSEZONE = ""
$ALLDNSZONE = ""
$MDP = ""
$KEY = ""

#----------------------------------------------------------------

function restartSystem
{
	Write-Host -fore Yellow "Do you want to restart computer now (Recommanded) ? [y/n]" 
    $answer = Read-Host 
    if($answer -eq "y")
    {
        $hostname = hostname
        Restart-Computer -ComputerName $hostname -Force 
    }
}

function findIPAddress
{
	if([string]::IsNullOrEmpty($Global:IP))
	{
	    $index = findNetInterface
		$inf = Get-NetIPAddress -InterfaceIndex $index
		$Global:IP = $inf.IPv4address	
	}
}

function findSelfReverseDNSzone
{
	findNetworkID
	$temp = $Global:NETID.Split('.')
	$Global:REVERSEZONE = $temp[2]+'.'+$temp[1]+'.'+$temp[0]+'.in-addr.arpa'
}

function findDomain
{
	$forest = (gwmi win32_computersystem)
	$Global:DOMAIN = $forest.Domain
}

function findNetworkID
{
	findIPAddress
	$temp = $Global:IP[1].Split('.')
	$Global:NETID = $temp[0]+'.'+$temp[1]+'.'+$temp[2]+'.'+'0/24'
}

function findNetInterface
{
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
	return $index
}

function SetIpConfiguration
{
    Write-Host -fore Cyan "Do you want to configure TCP/IP settings ? [y/n]"
    $answer = Read-Host 

    if($answer -eq "y")
    {
        #---------------------------------USER QUESTIONS------------------------------------------

        Write-Host -fore Cyan "Select interface's IP address :"
        $Global:IP = Read-Host

        Write-Host -fore Cyan "Select a gateway address :"
        $Global:GATEWAY = Read-Host

        Write-Host -fore Cyan "Select CIDR subnet mask (ex : 24) :"
        $Global:MASK = Read-Host 

        Write-Host -fore Cyan "Select DNS 1 server (ex : 8.8.8.8) :"
        $Global:DNS1 = Read-Host 

        Write-Host -fore Cyan "Select DNS 2 server (ex : 8.8.4.4) :"
        $Global:DNS2 = Read-Host 

        #-------------------------------------CHECKING--------------------------------------------
        
		$index = findNetInterface
        #$eth = $adapter.Name[$choice-1]    

        #------------------------------RESET CONFIGURATION----------------------------------------

        $interface = Get-NetIPInterface -InterfaceIndex $index -AddressFamily IPv4
        # Remove the static default gateway
        $interface | Remove-NetRoute -AddressFamily IPv4 -Confirm:$false
        # Set interface to "Obtain an IP address automatically"
        $interface | Set-NetIPInterface -Dhcp Enabled
        # Set interface to "Obtain DNS server address automatically"
        $interface | Set-DnsClientServerAddress -ResetServerAddresses

        #------------------------------SETTING NEW CONFIG-----------------------------------------

        #Remove-NetIPAddress -InterfaceIndex $index
        New-NetIPAddress –interfaceIndex $index -IPAddress $Global:IP -DefaultGateway $Global:GATEWAY -AddressFamily IPv4 -PrefixLength $Global:MASK
        Set-DNSClientServerAddress –interfaceIndex $index –ServerAddresses ($Global:DNS1, $Global:DNS2)

        $inf = Get-NetIPAddress -InterfaceIndex $index

        Write-Host -fore Magenta "-------------------------------------CONFIGURATION FEEDBACK-----------------------------------------------------"
        Write-Host -fore Green "IP address set to $($inf.IPv4address) and subnet mask to /$($inf.PrefixLength) on interface $($inf.InterfaceAlias)"
        Write-Host -fore Magenta "----------------------------------------------------------------------------------------------------------------"
    }
    else
    {
        Write-Host -fore Red "Skipping TCP/IP configuration..."
    }
}

function SetComputerConfiguration
{
    Write-Host -fore Cyan "Do you want to configure Hostname ? [y/n]"
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

function InstallDomainController
{
    $status = Get-WindowsFeature AD-Domain-Services   # ici on verifie si le DC est déja installé ou non sur le serveur
    if($status.InstallState -eq "Available")
    {
		write-host -fore green "starting Domain Controller installation..."
        Install-windowsfeature -name AD-Domain-Services –IncludeManagementTools

        Import-Module ADDSDeployment
        Install-ADDSDomainController `
            -DomainName $Global:DOMAIN `
            -DomainNetbiosName $Global:NETBIOS `
            -CreateDnsDelegation:$false `
            -DomainMode Win2008R2 `
            -InstallDns:$true `
            -NoRebootOnCompletion:$true `
            -SysvolPath "C:\Windows\SYSVOL" `
            -DatabasePath "C:\Windows\NTDS" `
            -LogPath "C:\Windows\NTDS" `
            -SafeModeAdministratorPassword $Global:KEY `
            -Force:$true 
			
		restartSystem
        # ici on installe une nouvelle forêt car il s'agit de la premiere installation. Si une foret existe deja, il faut utiliser la commande : Install-ADDSDomainController
     }
     else
     {
        write-host -fore red "can't install AD-DS role, state is $($status.InstallState)"
     }
}


function InstallForest
{
    $forest = (gwmi win32_computersystem)
    if ($forest.partofdomain -eq $true)      # ici on verifie si l'ordinateur fait parti d'un domaine ou non
    {
        write-host -fore Red "Sorry, but this computer is already domain joined : $($forest.Domain)"
        write-host -fore Red "New Forest installation canceled"
    } 
    else 
    {
        $status = Get-WindowsFeature AD-Domain-Services   # ici on verifie si le DC est déja installé ou non sur le serveur
        if($status.InstallState -eq "Available")
        {
			write-host -fore green "WORKGROUP detected, starting Forest installation..."
            Install-windowsfeature -name AD-Domain-Services –IncludeManagementTools

            Import-Module ADDSDeployment
            Install-ADDSForest `
                -DomainName $Global:DOMAIN `
                -DomainNetbiosName $Global:NETBIOS `
                -CreateDnsDelegation:$false `
                -ForestMode Win2008R2 `
                -DomainMode Win2008R2 `
                -InstallDns:$true `
                -NoRebootOnCompletion:$true `
                -SysvolPath "C:\Windows\SYSVOL" `
                -DatabasePath "C:\Windows\NTDS" `
                -LogPath "C:\Windows\NTDS" `
                -SafeModeAdministratorPassword $Global:KEY `
                -Force:$true 
				
			restartSystem
             # ici on installe une nouvelle forêt car il s'agit de la premiere installation. Si une foret existe deja, il faut utiliser la commande : Install-ADDSDomainController
        }
        else
        {
            write-host -fore red "can't install AD-DS role, state is $($status.InstallState)"
        }
    }
}


function InstallDCorForest
{
    Write-Host -fore Cyan "Do you want to install new Forest/DomainController ? [y/n]"
    $GO = Read-Host

    if($GO -eq "y")
    {
		$Global:MDP = "Root365it"
		$Global:KEY = ConvertTo-SecureString $Global:MDP -AsPlainText -Force

        Write-Host -fore Cyan "Please, give a domain name in order to join or create one. (ex: contoso.local ) : "
        $Global:DOMAIN = Read-Host
        $temp = $Global:DOMAIN.Split('.', 2)
        $Global:NETBIOS = $temp[0]
         
        Write-Host -fore Cyan "is it a new Forest (will install Primary DC) ? [y/n]"
        $answer = Read-Host 

        if($answer -eq "y")
        {
            InstallForest
        }
        else
        {
            Write-Host -fore Cyan "Do you want to install Secondary/ReadOnly Domain Controller on this computer ? [y/n]"
            $answer = Read-Host 

            if($answer -eq "y")
            {   
                InstallDomainController 
            }
        }
    }   
    else
    {
        Write-Host -fore Red "Skipping AD-DS installation..."
    }   
}

function checkZone($zone)
{
	$Global:ALLDNSZONE = Get-DnsServerZone
	foreach ($zones in $Global:ALLDNSZONE.ZoneName)
    {  
		if($zones -eq $zone)
		{
			Write-Host -fore Red "This zone $($zones) already exists"
			$cancel = "true"
		}
    }
	
}

function SetDNSConfiguration
{
    Write-Host -fore Cyan "Do you want to configure your DNS server ? [y/n]"
    $answer = Read-Host 

    if($answer -eq "y")
    {
		if([string]::IsNullOrEmpty($Global:DOMAIN))
		{
			findDomain
		}
		$cancel = checkZone $Global:DOMAIN
		if([string]::IsNullOrEmpty($cancel))
		{
			write-host -fore green "Installing primary direct zone..."
			Add-DnsServerPrimaryZone `
				-Name $Global:DOMAIN `
				-DynamicUpdate Secure `
				-ReplicationScope Forest
		}
		else
		{
			Write-Host -fore Red "Primary direct zone already exists for this domain : $($Global:DOMAIN)"
		}

        Write-Host -fore Cyan "Reverse lookup zone ? [y/n]"
        $answer = Read-Host

        if($answer -eq "y")
        {
			findSelfReverseDNSzone
			$cancelreverse = checkZone $Global:REVERSEZONE
			if([string]::IsNullOrEmpty($cancelreverse))
			{
				write-host -fore green "Installing reverse lookup zone..."   
				Add-DnsServerPrimaryZone `
					-NetworkId $Global:NETID `
					-DynamicUpdate Secure `
					-ReplicationScope Forest
			}
			else
			{
				Write-Host -fore Red "Reverse lookup zone already exists for this domain : $($Global:REVERSEZONE)"
			}
        }
    }      
    else
    {
        Write-Host -fore Red "Skipping DNS configuration..."
    }    
}


SetIpConfiguration
SetComputerConfiguration
InstallDCorForest
SetDNSConfiguration
Pause

