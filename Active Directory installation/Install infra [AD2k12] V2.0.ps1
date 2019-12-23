#-----------------------------------------------------------------
#--------------------------GLOBAL VARS----------------------------
#-----------------------------------------------------------------
$IP = ""
$GATEWAY = ""
$MASK = ""
$CIDR = "24"
$INDEXINF = ""
$DNS1 = ""
$DNS2 = ""
$DOMAIN = ""
$NETBIOS = ""
$NETID = ""
$REVERSEZONE = ""
$ALLDNSZONE = ""
$MDP = ""
$KEY = ""
$HOSTNAME = ""
#-----------------------------------------------------------------
#----------------------------ANSWERS------------------------------
#-----------------------------------------------------------------
$setTCPIP = ""
$setHOST = ""
$setFOREST = ""
$setDC = ""
$setDNS = ""
$setDHCP = ""


#-----------------------------------------------------------------
#---------------------------QUESTIONS-----------------------------
#-----------------------------------------------------------------

function startProcedure
{
	Write-Host -fore Cyan "CONFIGURE TCP/IP SETTINGS ? [y/n]"
	$Global:setTCPIP = Read-Host
	if($Global:setTCPIP -eq "y")
	{
		askIPconf
	}
	else { Write-Host -fore Red "TCP/IP CONFIGURATION SKIPPED" }
	
	Write-Host -fore Cyan "CONFIGURE HOSTNAME ? [y/n]"
    $Global:setHOST = Read-Host
	if($Global:setHOST -eq "y")
	{
		askHostname
	}
	else { Write-Host -fore Red "HOSTNAME CONFIGURATION SKIPPED" }
	
	Write-Host -fore Cyan "INSTALL NEW FOREST ? [y/n]"
    $Global:setFOREST = Read-Host
	if($Global:setFOREST -eq "y")
	{
		askDomain
	}
	else { Write-Host -fore Red "FOREST INSTALLATION SKIPPED" }
	
	Write-Host -fore Cyan "INSTALL NEW DOMAIN CONTROLLER (SECONDARY) ? [y/n]"
    $Global:setDC = Read-Host
	if($Global:setDC -eq "y")
	{
		askDomain
	}
	else { Write-Host -fore Red "DOMAIN CONTROLLER INSTALLATION SKIPPED" }
	
	Write-Host -fore Cyan "CONFIGURE DNS SETTINGS (PRIMARY+REVERSE) ? [y/n]"
    $Global:setDNS = Read-Host
	if($Global:setDNS -ne "y")
	{
		Write-Host -fore Red "DNS CONFIGURATION SKIPPED"
	}
	
	Write-Host -fore Cyan "INSTALL DHCP ? [y/n]"
    $Global:setDHCP = Read-Host
	if($Global:setDHCP -eq "y")
	{
		askDHCP
	}
	else { Write-Host -fore Red "DHCP INSTALLATION SKIPPED" }
	
	perform
}

function perform
{
	if($Global:setTCPIP -eq "y")
	{
		setIpConfiguration
	}
	if($Global:setHOST -eq "y")
	{
		setHostname
	}
	if($Global:setFOREST -eq "y")
	{
		InstallForest
	}
	if($Global:setDC -eq "y")
	{
		InstallDomainController
	}
	if($Global:setDNS -eq "y")
	{
		setDNSConfiguration
	}
	if($Global:setDHCP -eq "y")
	{
		
	}
}

function askIPconf
{
	Write-Host -fore Cyan "SELECT IP ADDRESS (ex : 192.168.1.1) :"
	$Global:IP = Read-Host
	Write-Host -fore Cyan "SELECT GATEWAY ADDRESS :"
	$Global:GATEWAY = Read-Host
	Write-Host -fore Cyan "SELECT CIDR SUBNET MASK (ex : 24) :"
	$Global:CIDR = Read-Host 
	Write-Host -fore Cyan "SELECT PRIMARY DNS SERVER (ex : 8.8.8.8) :"
	$Global:DNS1 = Read-Host 
	Write-Host -fore Cyan "SELECT SECONDARY DNS SERVER (ex : 8.8.4.4) :"
	$Global:DNS2 = Read-Host 
}

function askHostname
{
    Write-Host -fore Cyan "SELECT HOSTNAME FOR THIS COMPUTER : "
    $Global:HOSTNAME = Read-Host
}

function askDomain
{
	Write-Host -fore Cyan "PLEASE, SELECT A DOMAIN NAME IN ORDER TO JOIN OR CREATE ONE (ex: contoso.local ) : "
    $Global:DOMAIN = Read-Host
    $temp = $Global:DOMAIN.Split('.', 2)
    $Global:NETBIOS = $temp[0]
}

function askDHCP
{
	
}

#-----------------------------------------------------------------
#---------------------------FUNCTIONS-----------------------------
#-----------------------------------------------------------------
##################################################################
############################--TOOLS--#############################
##################################################################

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

function checkZone($zone)
{
	$Global:ALLDNSZONE = Get-DnsServerZone
	foreach ($zones in $Global:ALLDNSZONE.ZoneName)
    {  
		if($zones -eq $zone)
		{
			Write-Host -fore Red "This zone $($zones) already exists"
			$exists = "true"
			return $exists
		}
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

function findNetworkID
{
	findIPAddress
	$temp = $Global:IP[1].Split('.')
	$Global:NETID = $temp[0]+'.'+$temp[1]+'.'+$temp[2]+'.'+'0/'+$Global:CIDR
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

function findNetInterface
{
	$adapter = Get-NetAdapter       # on obtient un tableau de la liste des interfaces
            
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
        $Global:INDEXINF = $adapter.ifIndex[$choice-1]  
		
    }
    else
    {
        Write-Host -fore Green "Il y a 1 seule interface : $($adapter.Name)"
        $Global:INDEXINF = $adapter.ifIndex
    }
}



##################################################################
############################--MAIN--##############################
##################################################################

function setHostname
{
	$computer = Get-WmiObject Win32_ComputerSystem
    $computer.Rename($Global:HOSTNAME)    
	restartSystem
}

function setIpConfiguration
{
	$index = findNetInterface
	$interface = Get-NetIPInterface -InterfaceIndex $index -AddressFamily IPv4
	# Remove the static default gateway
	$interface | Remove-NetRoute -AddressFamily IPv4 -Confirm:$false
	# Set interface to "Obtain an IP address automatically"
	$interface | Set-NetIPInterface -Dhcp Enabled
	# Set interface to "Obtain DNS server address automatically"
	$interface | Set-DnsClientServerAddress -ResetServerAddresses

	New-NetIPAddress –interfaceIndex $index -IPAddress $Global:IP -DefaultGateway $Global:GATEWAY -AddressFamily IPv4 -PrefixLength $Global:CIDR
	Set-DNSClientServerAddress –interfaceIndex $index –ServerAddresses ($Global:DNS1, $Global:DNS2)

	$inf = Get-NetIPAddress -InterfaceIndex $index

	Write-Host -fore Magenta "-------------------------------------CONFIGURATION FEEDBACK-----------------------------------------------------"
	Write-Host -fore Green "IP address set to $($inf.IPv4address) and subnet mask to /$($inf.PrefixLength) on interface $($inf.InterfaceAlias)"
	Write-Host -fore Magenta "----------------------------------------------------------------------------------------------------------------"
}

function InstallDomainController
{
    $status = Get-WindowsFeature AD-Domain-Services   # ici on verifie si le DC est déja installé ou non sur le serveur
    if($status.InstallState -eq "Available")
    {
		write-host -fore green "STARTING DOMAIN CONTROLLER INSTALLATION [$($Global:DOMAIN)]..."
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
        write-host -fore red "CAN'T INSTALL AD-DS ROLE, STATE IS $($status.InstallState)"
     }
}

function InstallForest
{
    $forest = (Get-WmiObject win32_computersystem)
    if ($forest.partofdomain -eq $true)      # ici on verifie si l'ordinateur fait parti d'un domaine ou non
    {
        write-host -fore Red "SORRY, BUT THIS COMPUTER IS ALREADY DOMAIN JOINED : $($forest.Domain)"
        write-host -fore Red "NEW FOREST INSTALLATION CANCELED"
    } 
    else 
    {
        $status = Get-WindowsFeature AD-Domain-Services   # ici on verifie si le DC est déja installé ou non sur le serveur
        if($status.InstallState -eq "Available")
        {
			write-host -fore green "WORKGROUP DETECTED, STARTING FOREST INSTALLATION [$($Global:DOMAIN)]..."
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
            write-host -fore red "CAN'T INSTALL AD-DS ROLE, STATE IS $($status.InstallState)"
        }
    }
}

function setDNSConfiguration
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

function setDHCP
{
	$dhcp = Get-WindowsFeature -Name 'DHCP'
	if($dhcp.InstallState -eq "Available")
	{
		findIPAddress
		Install-WindowsFeature -Name DHCP –IncludeManagementTools
		Add-DhcpServerSecurityGroup
		Restart-Service dhcpserver
		Add-DhcpServerInDC -DnsName hostname -IPAddress $Global:IP
	}
}

#-----------------------------------------------------------------
#----------------------------PROGRAM------------------------------
#-----------------------------------------------------------------
##################################################################
#########################--EXECUTION--############################
##################################################################

startProcedure
Pause






















