############################
#         VARIABLES        #
############################

# General
[string]$LogPath        = "C:\logs\logs.log"

# Domain Controller
[string]$DC1_Name            = "SRV-DC1"
[string]$DC1_IP              = "192.168.43.157" #Serveur ADDS principal
[string]$DC2_Name            = "SRV-DC2"
[string]$DC2_IP              = "" #Serveur ADDS secondaire
[string]$Domain_Mode         = "Win2012R2"
[string]$Forest_Mode         = "Win2012R2"
$PASSWORD                    = ConvertTo-SecureString -String "Root365it" -AsPlainText -Force
[string]$Domain_Name         = "contoso.lab"
[string]$NTDS                = "D:\NTDS"
[string]$SYSVOL              = "D:\SYSVOL"
[string]$Logs                = "D:\Logs"

# Credentials
#DC
[string]$DCLocalUser            = "Administrator"
$DCLocalPassword                = ConvertTo-SecureString -String "Root365it" -AsPlainText -Force
$DCLocalCredential              = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $DCLocalUser, $DCLocalPassword

############################
#           EXEC           #
############################

Remove-Item -Path $LogPath
Start-Transcript -Path $LogPath

#Write-Verbose "Attente du demarrage de PowerShell Direct sur $DC1_Name" -Verbose
#while ((Invoke-Command -ComputerName $DC1_IP -Credential $DCLocalCredential {"ONLINE"} -ea SilentlyContinue) -ne "ONLINE") {Start-Sleep -Seconds 1}

Write-Verbose "PowerShell Direct OK sur $DC1_Name" -Verbose
Invoke-Command -ComputerName $DC1_IP -Credential $DCLocalCredential -ScriptBlock 
{
    try 
    {
        Write-Host "Ca marche" -Verbose
    }
    catch 
    {
        $Error.Exception.Message
        Break            
    }
}
Stop-Transcript -Path $LogPath
Pause

