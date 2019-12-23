<# Notes
    Pour activer le contrôle PowerShell à distance voici les commandes utiles :
    - Get-Item WSMan:\localhost\Client\TrustedHosts                                                         ==> liste les ordinateurs de confiance
    - Set-Item WSMan:\localhost\Client\TrustedHosts -Value 'machineA,machineB'                              ==> permet d'ajouter des machines à la liste de confiance
    - Set-Item WSMan:\localhost\Client\TrustedHosts -Value '*'                                              ==> Ajoute toutes les connexion sur la liste de confiance
    - Set-Item WSMan:\localhost\Client\TrustedHosts -Value 'machineC' -Concatenate                          ==> Append à la liste de confiance
    - Get-NetConnectionProfile -Name "Androidfred" | Set-NetConnectionProfile -NetworkCategory Private      ==> Set le réseau en réseau privé
#> 

##################################################################
########################## GLOBAL VARS ###########################
##################################################################
$REMOTEPCNAME       = $null
$IP                 = $null
$GATEWAY            = $null
$MASK               = $null
$CIDR               = $null
$INDEXINF           = $null
$DNS1               = $null
$DNS2               = $null
$DOMAIN             = $null
$NETBIOS            = $null
$NETID              = $null
$REVERSEZONE        = $null
$ALLDNSZONE         = $null
$MDP                = $null
$LOGIN              = $null
$CREDENTIALS        = $null
$KEY                = $null
$HOSTNAME           = $null
$SESSION            = $null
$ADAPTER            = $null
##################################################################
########################## ANSWER VARS ###########################
##################################################################
$setTCPIP           = $null
$setHOST            = $null
$setFOREST          = $null
$setDC              = $null
$setDNS             = $null
$setDHCP            = $null

function initVariables
{
    $Global:MDP                 = "Root365it"
    $Global:LOGIN               = "Administrateur"
    $Global:REMOTEPCNAME        = "SRV-DC1"
    $Global:CIDR                = "24"
}

##################################################################
########################### QUESTIONS ############################
##################################################################

function startProcedure
{
    Write-Host -fore Cyan "CONFIGURE HOSTNAME ? [y/n]"
    $Global:setHOST = Read-Host
	if($Global:setHOST -eq "y")
	{
		askHostname
	}
    else { Write-Host -fore Red "HOSTNAME CONFIGURATION SKIPPED" }
    
	Write-Host -fore Cyan "CONFIGURE TCP/IP SETTINGS ? [y/n]"
	$Global:setTCPIP = Read-Host
	if($Global:setTCPIP -eq "y")
	{
		askIPconf
	}
	else { Write-Host -fore Red "TCP/IP CONFIGURATION SKIPPED" }
	
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
    
    Exec
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

function Exec
{
    initCredentials
    
    if($Global:setHOST -eq "y")
	{
		$Global:SESSION = initSession $Global:REMOTEPCNAME $Global:CREDENTIALS
        setHostname
        closeSession $Global:SESSION
	}    
    if($Global:setTCPIP -eq "y")
	{
        $Global:SESSION = initSession $Global:REMOTEPCNAME $Global:CREDENTIALS
        setIpConfiguration
        closeSession $Global:SESSION
	}
	if($Global:setFOREST -eq "y")
	{
        $Global:SESSION = initSession $Global:REMOTEPCNAME $Global:CREDENTIALS

        closeSession $Global:SESSION
	}
	if($Global:setDC -eq "y")
	{
		
	}
	if($Global:setDNS -eq "y")
	{
		
	}
	if($Global:setDHCP -eq "y")
	{
		
	}
}

##################################################################
############################# TOOLS ##############################
##################################################################

function initCredentials
{
    $password                = ConvertTo-SecureString -String $Global:MDP -AsPlainText -Force
    $Global:CREDENTIALS      = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $Global:LOGIN, $password
}

function initSession($remotePC, $credential)
{
    while (!$session)
    {
        Start-Sleep -Seconds 2
        $session = New-PSSession -ComputerName $remotePC -Credential $credential -ea SilentlyContinue  
    }
    Write-Host -fore green "Session initialized"
    return $session
}

function closeSession($session)
{
    Remove-PSSession -Session $session
    $session = $null
    Write-Host -fore green "Session closed"
}

function restartSystem
{
    Write-Host -fore Yellow "RESTARTING NOW..."
    Start-Sleep -Seconds 3
    $hostname = hostname
    Restart-Computer -ComputerName $hostname -Force
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
    if($Global:ADAPTER.Name -is [system.array])  # on verifie si il y a plusieurs noms d'interfaces et donc plusieurs cartes réseau
    {
        $i=1
        Write-Host -fore Yellow "Il y a plusieurs interfaces :"
        foreach ($int in $Global:ADAPTER.name)
        {  
            Write-Host -fore Yellow "$i : $int"
            $i++
        }
        $i--
        Write-Host -fore Yellow "Laquelle voulez-vous configurer ? [1-$i]"
        $choice = Read-Host  
        $Global:INDEXINF = $Global:ADAPTER.ifIndex[$choice-1]  
    }
    else
    {
        Write-Host -fore Green "Il y a 1 seule interface : $($Global:ADAPTER.Name)"
        $Global:INDEXINF = $Global:ADAPTER.ifIndex
    }
}

##################################################################
####################### MAIN FONCTIONS ###########################
##################################################################

function setHostname
{
    Invoke-Command -Session $Global:SESSION -ScriptBlock {
        param($Global:HOSTNAME)
        try 
        {
            $computer = Get-WmiObject Win32_ComputerSystem
            $computer.Rename($Global:HOSTNAME)
        }
        catch
        {
            $Error.Exception.Message
            Break
        }
    } -ArgumentList $Global:HOSTNAME
    Invoke-Command -Session $Global:SESSION -ScriptBlock ${function:restartSystem} 
    $Global:REMOTEPCNAME = $Global:HOSTNAME
}

function setIpConfiguration 
{
    $Global:ADAPTER = Invoke-Command -Session $Global:SESSION -ScriptBlock {
        try 
        {
            Get-NetAdapter
        }
        catch
        {
            $Error.Exception.Message
            Break
        }
    } 

    findNetInterface

    Invoke-Command -Session $Global:SESSION -ScriptBlock {
        param
        (
            $Global:INDEXINF, $Global:IP, $Global:GATEWAY, $Global:CIDR, $Global:DNS1, $Global:DNS2
        )
        try 
        {
            $interface = Get-NetIPInterface -InterfaceIndex $Global:INDEXINF -AddressFamily IPv4
            $interface | Remove-NetRoute -AddressFamily IPv4 -Confirm:$false
            $interface | Set-NetIPInterface -Dhcp Enabled
            $interface | Set-DnsClientServerAddress -ResetServerAddresses
            New-NetIPAddress -interfaceIndex $Global:INDEXINF -IPAddress $Global:IP -DefaultGateway $Global:GATEWAY -AddressFamily IPv4 -PrefixLength $Global:CIDR
            Set-DNSClientServerAddress -interfaceIndex $Global:INDEXINF -ServerAddresses ($Global:DNS1, $Global:DNS2)
            $inf = Get-NetIPAddress -InterfaceIndex $Global:INDEXINF
            Write-Host -fore Magenta "-------------------------------------CONFIGURATION FEEDBACK-----------------------------------------------------"
            Write-Host -fore Green "IP address set to $($inf.IPv4address) and subnet mask to /$($inf.PrefixLength) on interface $($inf.InterfaceAlias)"
            Write-Host -fore Magenta "----------------------------------------------------------------------------------------------------------------"
        }
        catch
        {
            $Error.Exception.Message
            Break
        }
    } -ArgumentList $Global:INDEXINF, $Global:IP, $Global:GATEWAY, $Global:CIDR, $Global:DNS1, $Global:DNS2
}


##################################################################
########################### EXECUTION ############################
##################################################################

initVariables
startProcedure
Pause