
$Global:sharePath = "\\THSV000009\"
$Global:usersPath = "Users\"
$Global:network = $network = New-Object -ComObject WScript.Network
$Global:netPrinter = @("THPT000001", "THPT000002", "THPT000003")

function deleteMappedDrives
{
    $DriveList = Get-WMIObject Win32_LogicalDisk | Where-Object { $_.DriveType -eq 4 }
    

    # Don't bother running this if we don't have any mapped drives
     if ($DriveList) 
     { 
        Foreach ($drive in $DriveList) 
        {
            Write-host "removing $($drive.DeviceID) drive"
            $Global:network.RemoveNetworkDrive($($drive.DeviceID), $true, $true)
        }
     } 
     else 
     {
        Write-Host "No mapped drives found"
        Return
     }
}

function MapPersonalDrive
{
    $userNetworkPath = $Global:sharePath + $Global:usersPath + $env:USERNAME
    Write-Host "Mapping T: drive as ==> $userNetworkPath"
    $Global:network.MapNetworkDrive('T:', $userNetworkPath, $true)
}

function MapGlobalDrive
{
    Write-Host "Mapping S: drive as ==> $Global:sharePath"
    $Global:network.MapNetworkDrive('S:', $Global:sharePath, $true)
}

function MapSpecificDrive ($sharePath)
{
    
}

function addNetworkPrinter
{
    foreach($printer in $Global:netPrinter)
    {
        $print = $Global:sharePath + $printer
        Write-Host "connecting to printer : $print"
        $Global:network.AddWindowsPrinterConnection($print)
    }
}

function RemoveNetworkPrinter
{
    $printers = Get-WmiObject -Class Win32_printer

    foreach($printer in $printers)
    {
        if($printer.ShareName -ne $null)
        {
            Write-Host "$($printer.Name) is shared over the network"
            $Global:network.RemovePrinterConnection($($printer.Name))
        }
    }
}

function createShortcut
{
    $wshshell = New-Object -ComObject WScript.Shell
    $desktop = [System.Environment]::GetFolderPath('Desktop')
    $lnk = $wshshell.CreateShortcut($desktop+"\File Server THSV000009.lnk")
    $lnk.TargetPath = $Global:sharePath
    $lnk.Save()
}

#powershell –ExecutionPolicy Bypass

deleteMappedDrives
MapPersonalDrive
#MapGlobalDrive
RemoveNetworkPrinter
addNetworkPrinter
createShortcut





#NOTES

#$psDrive = $drive -replace ":" #remove unwanted colon from PSDrive name
#Remove-SmbMapping -LocalPath $Drive -Force -UpdateProfile

#If ( (Get-PSDrive -Name $psDrive) 2>$Null ) 
#{
#   Remove-PSDrive -Name $psDrive -Force
#}


 # Credentials not required
 #net.exe use M: $shareName /PERSISTENT:YES
 #$network.MapNetworkDrive('M:', $shareName, $true)
 
 # Credentials required
 #net.exe use M: $shareName /PERSISTENT:YES /USER:DOMAIN\username *
 #$network.MapNetworkDrive('M:', $shareName, $true, 'DOMAIN\username', 'password')
 
 
# List
#net.exe use M:
#$network.EnumNetworkDrives()
 
# Remove
#net.exe use M: /DELETE
#$network.RemoveNetworkDrive('M:', $true, $true)