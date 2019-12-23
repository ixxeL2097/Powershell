<# Notes
    Pour activer le contrôle PowerShell à distance voici les commandes utiles :
    - get-service winrm
    - Enable-PSRemoting –force
    - winrm s winrm/config/client '@{TrustedHosts="RemoteComputer"}'
    - winrm quickconfig
    - Get-Item WSMan:\localhost\Client\TrustedHosts                                                         ==> liste les ordinateurs de confiance
    - Set-Item WSMan:\localhost\Client\TrustedHosts -Value 'machineA,machineB'                              ==> permet d'ajouter des machines à la liste de confiance
    - Set-Item WSMan:\localhost\Client\TrustedHosts -Value '*'                                              ==> Ajoute toutes les connexion sur la liste de confiance
    - Set-Item WSMan:\localhost\Client\TrustedHosts -Value 'machineC' -Concatenate                          ==> Append à la liste de confiance
    - Get-NetConnectionProfile -Name "Androidfred" | Set-NetConnectionProfile -NetworkCategory Private      ==> Set le réseau en réseau privé
#> 

##################################################################
########################## GLOBAL VARS ###########################
##################################################################

#Connexion PC distant
$REMOTEPCNAME       = $null         #Hostname du PC distant
$MDP                = $null         #password du compte admin distant pour la connexion
$LOGIN              = $null         #login du compte admin distant pour la connexion
$CREDENTIALS        = $null         #Combinaison des variables login+mdp
$SESSION            = $null         #session de connexion avec le PC distant

#Config IP PC distant
$HOSTNAME           = $null         #Var pour assignation d'un nouveau hostname
$IP                 = $null         #IP du PC distant
$GATEWAY            = $null         #Gateway pour le PC distant
$MASK               = $null         #Masque de sous réseau du PC distant
$CIDR               = $null         #CIDR du PC distant
$INDEXINF           = $null         #Index de l'interface réseau du PC distant
$DNS1               = $null         #DNS 1 du PC distant
$DNS2               = $null         #DNS 2 du PC distant
$ADAPTER            = $null

#VARS pour install DC
$DOMAIN             = $null         #nom de domain pour l'installation du DC
$NETBIOS            = $null
$DSRM                = $null         #password de l'installation du DC
$INSTALLDNS         = $null         #Variable pour installer ou non le DNS pendant l'installation du DC
$DCINSTALLMODE      = $null         #type d'installation du DC (new Forest/new Domain DC/second DC/ReadOnly DC)
$ROOTCredentials    = $null 
$ROOTmdp            = $null
$ROOTlogin          = $null

#VARS pour install DNS
$NETID              = $null         #Identifiant réseau correspondant à l'IP
$REVERSEZONE        = $null         #nom de la zone de résolution inversée
$ALLDNSZONE         = $null         #Array contenant la liste des zones DNS du serveur DNS distant
 
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
    $Global:MDP                 = ConvertTo-SecureString -String "Root365it" -AsPlainText -Force                                          #password du compte admin distant pour la connexion
    $Global:LOGIN               = "Administrateur"                                                                                        #login du compte admin distant pour la connexion
    $Global:ROOTlogin           = "Administrateur"
    $Global:ROOTmdp             = ConvertTo-SecureString -String "Root365it" -AsPlainText -Force 
    $Global:REMOTEPCNAME        = "DC1"                                                                                               #hostname du PC distant pour la connexion
    $Global:CIDR                = "24"
    $Global:DSRM                 = ConvertTo-SecureString -String "Root365it" -AsPlainText -Force                                          #password DSRM de l'installation du DC
    $Global:DOMAIN              = "contoso.local"                                                                                         #nom de domain pour l'installation du DC
    $Global:NETBIOS             = "CONTOSO" 
    $Global:INSTALLDNS          = $true

    $Global:CREDENTIALS         = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $Global:LOGIN, $Global:MDP
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
	
	Write-Host -fore Cyan "INSTALL NEW FOREST / NEW DOMAIN DC / SECOND DC / READ-ONLY DC ? [y/n]"
    $Global:setFOREST = Read-Host
	if($Global:setFOREST -eq "y")
	{
		askDomainAndType
	}
	else { Write-Host -fore Red "FOREST INSTALLATION SKIPPED" }
	
	<#Write-Host -fore Cyan "INSTALL NEW DOMAIN CONTROLLER (SECONDARY) ? [y/n]"
    $Global:setDC = Read-Host
	if($Global:setDC -eq "y")
	{
		askDomain
	}
	else { Write-Host -fore Red "DOMAIN CONTROLLER INSTALLATION SKIPPED" }#>
	
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
	Write-Host -fore Yellow "SELECT IP ADDRESS (ex : 192.168.1.1) :"
	$Global:IP = Read-Host
	Write-Host -fore Yellow "SELECT GATEWAY ADDRESS :"
	$Global:GATEWAY = Read-Host
	Write-Host -fore Yellow "SELECT CIDR SUBNET MASK (ex : 24) :"
	$Global:CIDR = Read-Host 
	Write-Host -fore Yellow "SELECT PRIMARY DNS SERVER (ex : 8.8.8.8) :"
	$Global:DNS1 = Read-Host 
	Write-Host -fore Yellow "SELECT SECONDARY DNS SERVER (ex : 8.8.4.4) :"
	$Global:DNS2 = Read-Host 
}

function askHostname
{
    Write-Host -fore Yellow "SELECT HOSTNAME FOR THIS COMPUTER : "
    $Global:HOSTNAME = Read-Host
}

function askDomainAndType
{
    Write-Host -fore Yellow "-------INSTALLATION TYPES------- "
    Write-Host -fore Yellow "------ 1 - NEW FOREST------------"
    Write-Host -fore Yellow "------ 2 - NEW DOMAIN DC---------"
    Write-Host -fore Yellow "------ 3 - SECOND DC-------------"
    Write-Host -fore Yellow "------ 4 - READ-ONLY DC----------"
    Write-Host -fore Yellow "-------------------------------- "
    Write-Host -fore Yellow "Please, select option [1-4] : "
    $Global:DCINSTALLMODE = Read-Host
	Write-Host -fore Yellow "PLEASE, SELECT A DOMAIN NAME IN ORDER TO JOIN OR CREATE ONE (ex: contoso.local ) : "
    $Global:DOMAIN = Read-Host
    $temp = $Global:DOMAIN.Split('.', 2)
    $Global:NETBIOS = $temp[0]
}

function askDHCP
{
	
}

function Exec
{
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
        switch($Global:DCINSTALLMODE)
        {
            1 { InstallForest }
            2 { Write-Host -Red "Function not implemented yet !" }
            3 { InstallDomainController }
            4 { Write-Host -Red "Function not implemented yet !" }
            default { Write-Host -Red "no information received!" }
        }
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

function getRootCredentials
{
    $Global:ROOTlogin = $Global:NETBIOS+"\"+$Global:ROOTlogin
    $Global:ROOTCredentials     = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $Global:ROOTlogin, $Global:ROOTmdp
}

function initSession($remotePC, $credential)
{
    while (!$session)
    {
        Start-Sleep -Seconds 2
        Write-Host -fore Yellow "Testing connection..."
        $session = New-PSSession -ComputerName $remotePC -Credential $credential -ea SilentlyContinue  
    }
    Write-Host -fore green "Session initialized"
    return $session
}

function closeSession($session)
{
    Write-Host -fore Yellow "Closing connection..."
    Remove-PSSession -Session $session
    $session = $null
    Write-Host -fore green "Session closed"
}

function restartSystem
{
    Write-Host -fore Red "RESTARTING NOW..."
    Start-Sleep -Seconds 3
    $hostname = hostname
    Restart-Computer -ComputerName $hostname -Force -Verbose
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
	$forest = (Get-WmiObject win32_computersystem)
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
    $Global:ADAPTER = Invoke-Command -Session $Global:SESSION -ScriptBlock { try { Get-NetAdapter }catch { $Error.Exception.Message; Break; } } 

    findNetInterface

    Invoke-Command -Session $Global:SESSION -ScriptBlock {
        param($Global:INDEXINF, $Global:IP, $Global:GATEWAY, $Global:CIDR, $Global:DNS1, $Global:DNS2)
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

function InstallForest
{
    Invoke-Command -Session $Global:SESSION -ScriptBlock {
        param($Global:DOMAIN, $Global:NETBIOS, $Global:DSRM, $Global:INSTALLDNS)
        try 
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
                    Install-windowsfeature -name AD-Domain-Services -IncludeManagementTools -Verbose
                    Import-Module ADDSDeployment
                    Install-ADDSForest `
                        -DomainName $Global:DOMAIN `
                        -DomainNetbiosName $Global:NETBIOS `
                        -CreateDnsDelegation:$false `
                        -ForestMode Win2008R2 `
                        -DomainMode Win2008R2 `
                        -InstallDns:$Global:INSTALLDNS `
                        -NoRebootOnCompletion:$false `
                        -SysvolPath "C:\Windows\SYSVOL" `
                        -DatabasePath "C:\Windows\NTDS" `
                        -LogPath "C:\Windows\NTDS" `
                        -SafeModeAdministratorPassword $Global:DSRM `
                        -Force:$true `
                        -Verbose
                     # ici on installe une nouvelle forêt car il s'agit de la premiere installation. Si une foret existe deja, il faut utiliser la commande : Install-ADDSDomainController
                }
                else
                {
                    write-host -fore red "CAN'T INSTALL AD-DS ROLE, STATE IS $($status.InstallState)"
                }
            }     
        }
        catch 
        {
            $Error.Exception.Message
            Break
        }
    } -ArgumentList $Global:DOMAIN, $Global:NETBIOS, $Global:DSRM, $Global:INSTALLDNS
}

function InstallDomainController
{
    getRootCredentials
    Invoke-Command -Session $Global:SESSION -ScriptBlock {
        param($Global:DOMAIN, $Global:NETBIOS, $Global:DSRM, $Global:INSTALLDNS, $Global:ROOTCredentials)
        try 
        {
            $status = Get-WindowsFeature AD-Domain-Services   # ici on verifie si le DC est déja installé ou non sur le serveur
            if($status.InstallState -eq "Available")
            {
                write-host -fore green "STARTING DOMAIN CONTROLLER INSTALLATION..."
                Install-windowsfeature -name AD-Domain-Services -IncludeManagementTools -Verbose
                Import-Module ADDSDeployment
                Install-ADDSDomainController `
                    -DomainName $Global:DOMAIN `
                    -CreateDnsDelegation:$false `
                    -InstallDns:$Global:INSTALLDNS `
                    -NoRebootOnCompletion:$false `
                    -SysvolPath "C:\Windows\SYSVOL" `
                    -DatabasePath "C:\Windows\NTDS" `
                    -LogPath "C:\Windows\NTDS" `
                    -SafeModeAdministratorPassword $Global:DSRM `
                    -Force:$true `
                    -Credential:$Global:ROOTCredentials `
                    -Verbose
                     # ici on installe une nouvelle forêt car il s'agit de la premiere installation. Si une foret existe deja, il faut utiliser la commande : Install-ADDSDomainController
            }
            else
            {
                write-host -fore red "CAN'T INSTALL AD-DS ROLE, STATE IS $($status.InstallState)"
            }   
        }
        catch 
        {
            $Error.Exception.Message
            Break
        }
    } -ArgumentList $Global:DOMAIN, $Global:NETBIOS, $Global:DSRM, $Global:INSTALLDNS, $Global:ROOTCredentials
}

function SetDNSConfiguration
{
	if([string]::IsNullOrEmpty($Global:DOMAIN))
	{
        Invoke-Command -Session $Global:SESSION -ScriptBlock ${function:findDomain}
    }
    
    $Global:ALLDNSZONE = Invoke-Command -Session $Global:SESSION -ScriptBlock { try{ Get-DnsServerZone }catch{ $Error.Exception.Message; Break; } }

    Invoke-Command -Session $Global:SESSION -ScriptBlock {
        param($Global:ALLDNSZONE)
        try 
        {

        }
        catch
        {

        }
    } -ArgumentList $Global:ALLDNSZONE
    
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

##################################################################
########################### EXECUTION ############################
##################################################################

initVariables
startProcedure
Write-Verbose "SCRIPT TERMINATED : SUCCESS" -Verbose
Pause

##################################################################
######################### END OF SCRIPT ##########################
##################################################################