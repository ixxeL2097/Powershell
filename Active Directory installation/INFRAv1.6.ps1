<# Notes
    ==> Avant d'installer un controleur de domaine secondaire, verifier que le DNS est bien celui du DC principal
    ==> Désactivez le pare-feu windows qui bloque les sessions distantes
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

#VARS pour install DHCP
$SCOPENAME          = $null         #nom de la range, ex : VLAN1, LAN1, ADM...
$STARTRANGE         = $null
$STOPRANGE          = $null
 
##################################################################
########################## ANSWER VARS ###########################
##################################################################

$setTCPIP           = $null
$setHOST            = $null
$setFOREST          = $null
$setDHCP            = $null

function initVariables
{
    [securestring]$Global:MDP                   = ConvertTo-SecureString -String "Root365it" -AsPlainText -Force                                          #password du compte admin distant pour la connexion
    [string]$Global:LOGIN                       = "Administrateur"                                                                                        #login du compte admin distant pour la connexion
    [string]$Global:ROOTlogin                   = "Administrateur"
    [securestring]$Global:ROOTmdp               = ConvertTo-SecureString -String "Root365it" -AsPlainText -Force 
    [string]$Global:REMOTEPCNAME                = "DC0"                                                                                               #hostname du PC distant pour la connexion
    [string]$Global:CIDR                        = "24"
    [securestring]$Global:DSRM                  = ConvertTo-SecureString -String "Root365it" -AsPlainText -Force                                          #password DSRM de l'installation du DC
    [string]$Global:DOMAIN                      = "contoso.local"                                                                                         #nom de domain pour l'installation du DC
    [string]$Global:NETBIOS                     = "CONTOSO" 
    [bool]$Global:INSTALLDNS                    = $True

    $Global:CREDENTIALS         = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $Global:LOGIN, $Global:MDP
}

function setDHCPScope
{
    [string]$Global:SCOPENAME                   = "LAN-1"
    [string]$Global:STARTRANGE                  = "100"
    [string]$Global:STOPRANGE                   = "200"
    [string]$Global:MASK                        = "255.255.255.0"
    [string]$Global:DNS1                        = "192.168.99.100"
    [string]$Global:DNS2                        = "192.168.99.101"
    [string]$Global:GATEWAY                     = "192.168.99.100"
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
    Write-Host -fore Yellow "-------INSTALLATION TYPES--------"
    Write-Host -fore Yellow "------ 1 - NEW FOREST------------"
    Write-Host -fore Yellow "------ 2 - NEW DOMAIN DC---------"
    Write-Host -fore Yellow "------ 3 - SECOND DC-------------"
    Write-Host -fore Yellow "------ 4 - READ-ONLY DC----------"
    Write-Host -fore Yellow "---------------------------------"
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
            1 
            {   InstallForest
                closeSession $Global:SESSION
                $Global:SESSION = initSession $Global:REMOTEPCNAME $Global:CREDENTIALS
                Write-Host -fore Yellow "Waiting a moment to install Reverse lookup zone..."
                tryToInstallReverse
            }
            2 { Write-Host -fore Red "Function not implemented yet !" }
            3 { InstallDomainController }
            4 { Write-Host -fore Red "Function not implemented yet !" }
            default { Write-Host -fore Red "INCORRECT INPUT" }
        }
        closeSession $Global:SESSION
	}
	if($Global:setDHCP -eq "y")
	{
		
	}
}

##################################################################
############################# TOOLS ##############################
##################################################################

function reverseTimer($time)
{
    $k = $time
    do
    { 
        Start-Sleep -Seconds 1
        Write-Host -fore Red "Time remaining : $($k)"
        $k--
    }
    Until($k -eq 0)
}

function tryToInstallReverse
{
    do
    { 
        Start-Sleep -Seconds 30
        Write-Host -fore Yellow "TRYING TO INSTALL REVERSE LOOKUP ZONE..."
        InstallReverseLookupZone -ea SilentlyContinue
        $Global:ALLDNSZONE = Invoke-Command -Session $Global:SESSION -ScriptBlock { try { Get-DnsServerZone }catch { $Error.Exception.Message; Break; } }    
        $jobDone = checkZone $Global:REVERSEZONE $Global:ALLDNSZONE
    }
    Until($jobDone -eq "true")
    Write-Host -fore Green "REVERSE LOOKUP ZONE INSTALLATION SUCCESS !!"
}

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
        Write-Host -fore Yellow "Testing connection on [$($remotePC)]..."
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

function checkZone($zone, $zonesArray)
{
	foreach ($zones in $zonesArray.ZoneName)
    {  
		if($zones -eq $zone)
		{
			return "true"
		}
    }
}

function findMask
{
    switch($Global:CIDR)
    {
        1 {  }
        2 {  }
        3 {  }
        4 {  }
        5 {  }
        6 {  }
        7 {  }
        8 {  }
        9 {  }
        10 {  }
        11 {  }
        12 {  }
        13 {  }
        14 {  }
        15 {  }
        16 {  }
        17 {  }
        18 {  }
        19 {  }
        20 {  }
        default { Write-Host -fore Red "INCORRECT INPUT" }
    }
}

<#function findLocalIPAddress
{
	if([string]::IsNullOrEmpty($Global:IP))
	{
	    $index = findNetInterface
		$inf = Get-NetIPAddress -InterfaceIndex $index
        $Global:IP = $inf.IPv4address
	}
}#>

function findRemoteIPAddress
{
    if([string]::IsNullOrEmpty($Global:IP))
	{
        $Global:ADAPTER = Invoke-Command -Session $Global:SESSION -ScriptBlock { try { Get-NetAdapter }catch { $Error.Exception.Message; Break; } }
        findNetInterface
        $inf = Invoke-Command -Session $Global:SESSION -ScriptBlock { param($Global:INDEXINF)try { Get-NetIPAddress -InterfaceIndex $Global:INDEXINF }catch { $Error.Exception.Message; Break; } } -ArgumentList $Global:INDEXINF
        $Global:IP = $inf.IPv4address
	}
}

function findNetworkID
{
	#findRemoteIPAddress
	$temp = $Global:IP[1].Split('.')
	$Global:NETID = $temp[0]+'.'+$temp[1]+'.'+$temp[2]+'.'+'0/'+$Global:CIDR
}

function findSelfReverseDNSzone
{
	findNetworkID
	$temp = $Global:NETID.Split('.')
	$Global:REVERSEZONE = $temp[2]+'.'+$temp[1]+'.'+$temp[0]+'.in-addr.arpa'
}

function findDomainAndNetbios
{
    #$forest = (Get-WmiObject win32_computersystem)
    $forest = Invoke-Command -Session $Global:SESSION -ScriptBlock { try { (Get-WmiObject win32_computersystem) }catch { $Error.Exception.Message; Break; } } 
    $Global:DOMAIN = $forest.Domain
    $temp = $Global:DOMAIN.Split('.', 2)
    $Global:NETBIOS = $temp[0]
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
        param($Global:DOMAIN, $Global:NETBIOS, $Global:DSRM, $Global:INSTALLDNS, $Global:REMOTEPCNAME)
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
                    write-host -fore green "WORKGROUP DETECTED, STARTING FOREST INSTALLATION [$($Global:DOMAIN)] on serveur [$($Global:REMOTEPCNAME)]..."
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
    } -ArgumentList $Global:DOMAIN, $Global:NETBIOS, $Global:DSRM, $Global:INSTALLDNS, $Global:REMOTEPCNAME
}

function InstallDomainController
{
    getRootCredentials
    Invoke-Command -Session $Global:SESSION -ScriptBlock {
        param($Global:DOMAIN, $Global:NETBIOS, $Global:DSRM, $Global:INSTALLDNS, $Global:ROOTCredentials, $Global:REMOTEPCNAME)
        try 
        {
            $status = Get-WindowsFeature AD-Domain-Services   # ici on verifie si le DC est déja installé ou non sur le serveur
            if($status.InstallState -eq "Available")
            {
                write-host -fore green "STARTING SECOND DOMAIN CONTROLLER INSTALLATION [$($Global:DOMAIN)] ON SERVER [$($Global:REMOTEPCNAME)]..."
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
    } -ArgumentList $Global:DOMAIN, $Global:NETBIOS, $Global:DSRM, $Global:INSTALLDNS, $Global:ROOTCredentials, $Global:REMOTEPCNAME
}

function InstallReverseLookupZone
{

    $Global:ADAPTER = Invoke-Command -Session $Global:SESSION -ScriptBlock { try { Get-NetAdapter }catch { $Error.Exception.Message; Break; } }
    findNetInterface
    $inf = Invoke-Command -Session $Global:SESSION -ScriptBlock { param($Global:INDEXINF)try { Get-NetIPAddress -InterfaceIndex $Global:INDEXINF }catch { $Error.Exception.Message; Break; } } -ArgumentList $Global:INDEXINF
    $Global:IP = $inf.IPv4address
    findSelfReverseDNSzone

    Invoke-Command -Session $Global:SESSION -ScriptBlock {
        param($Global:NETID ,$Global:REVERSEZONE)
        try 
        {
            write-host -fore green "INSTALLING REVERSE LOOKUP ZONE FOR [$($Global:NETID)] NETWORK ON FILE [$($Global:REVERSEZONE)]"   
            Add-DnsServerPrimaryZone `
                -NetworkId $Global:NETID `
                -DynamicUpdate Secure `
                -ReplicationScope Forest
        }
        catch
        {
            $Error.Exception.Message
            Break
        }    
    } -ArgumentList $Global:NETID ,$Global:REVERSEZONE 
}

function InstallDHCP
{
    findDomainAndNetbios
    findRemoteIPAddress
    getRootCredentials
    setDHCPScope

    Invoke-Command -Session $Global:SESSION -ScriptBlock {
        param($Global:NETID, $Global:REMOTEPCNAME, $Global:IP, $Global:INDEXINF, $Global:ROOTCredentials, $Global:SCOPENAME, $Global:STARTRANGE, $Global:STOPRANGE, $Global:MASK, $Global:DOMAIN, $Global:DNS1, $Global:DNS2, $Global:GATEWAY)
        try 
        {
            write-host -fore green "INSTALLING DHCP SERVER FOR [$($Global:NETID)] NETWORK ON SERVER [$($Global:REMOTEPCNAME)]" 
            Install-WindowsFeature -Name DHCP -IncludeManagementTools -Verbose
            Add-DhcpServerSecurityGroup -ComputerName $Global:REMOTEPCNAME
            Set-DHCPServerDnsCredential -Credential:$Global:ROOTCredentials -ComputerName $Global:REMOTEPCNAME
            Restart-Service dhcpserver
            Write-Host -fore Yellow "Waiting a moment, restarting dhcp service..."
            Start-Sleep -Seconds 15

            Add-DhcpServerInDC -DnsName $Global:REMOTEPCNAME -IPAddress $Global:IP
            #Set-DhcpServerv4Binding -BindingState $True -InterfaceAlias "Ethernet"
            Add-DhcpServerv4Scope -Name $Global:SCOPENAME -StartRange $Global:STARTRANGE -EndRange $Global:STOPRANGE -SubnetMask $Global:MASK
            #Add-DHCPServerV4ExclusionRange -ScopeId $ScopeId -StartRange $StartRangeExclusion -EndRange $EndRangeExclusion
            Set-DHCPServerv4OptionValue -ComputerName $Global:REMOTEPCNAME -DnsServer $Global:DNS1 -DnsDomain $Global:DOMAIN -Router $Global:GATEWAY
        }
        catch
        {
            $Error.Exception.Message
            Break
        }    
    } -ArgumentList $Global:NETID, $Global:REMOTEPCNAME, $Global:IP, $Global:INDEXINF, $Global:ROOTCredentials, $Global:SCOPENAME, $Global:STARTRANGE, $Global:STOPRANGE, $Global:MASK, $Global:DOMAIN, $Global:DNS1, $Global:DNS2, $Global:GATEWAY
    Write-Host -fore Green "DHCP SERVER INSTALLED SUCCESS !!!"
}

##################################################################
########################### EXECUTION ############################
##################################################################

Remove-Item -Path "C:\log\log.txt"
Start-Transcript -Path "C:\log\log.txt"
initVariables
startProcedure
Write-Verbose "|||||||||||||||||||||||||||||||||||||||||||||||||||||||" -Verbose
Write-Verbose "||||||||||||| SCRIPT TERMINATED : SUCCESS |||||||||||||" -Verbose
Write-Verbose "|||||||||||||||||||||||||||||||||||||||||||||||||||||||" -Verbose
Pause
Stop-Transcript

##################################################################
######################### END OF SCRIPT ##########################
##################################################################