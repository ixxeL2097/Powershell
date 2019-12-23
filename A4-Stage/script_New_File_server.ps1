
$Global:sharePath = "\\THSV000009\"
$Global:usersPath = "Users\"
$Global:network = $network = New-Object -ComObject WScript.Network
$Global:netPrinter = @("THPT000001", "THPT000002", "THPT000003")

function deleteMappedDrives
{
    $DriveList = Get-WMIObject Win32_LogicalDisk ` | Where-Object { $_.DriveType -eq 4 }
    

    # Don't bother running this if we don't have any mapped drives
     if ($DriveList) 
     { 
        $SmbDriveList = $DriveList.DeviceID
     } 
     else 
     {
        Write-Host "No mapped drives found"
        Return
     }

    Write-host "Drives currently mapped: " -NoNewLine
    Write-Host $SmbDriveList
    Write-Host " "

    Foreach ($drive in $SmbDriveList) 
    {
        if($drive -eq 'X:')
        {
            Write-host "removing $drive"
            $Global:network.RemoveNetworkDrive($drive, $true, $true)
        }
    }
}

function MapPersonalDrive
{
    $userNetworkPath = $Global:sharePath + $Global:usersPath + $env:USERNAME
    Write-Host "Mapping M: drive as ==> $userNetworkPath"
    $Global:network.MapNetworkDrive('M:', $userNetworkPath, $true)
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
    $printers = Get-Printer -ComputerName "THSV000009"
    foreach($printer in $printers)
    {
        $print = $Global:sharePath + $($printer.Name)
        Write-Host "connecting to printer : $print"
        #$Global:network.AddWindowsPrinterConnection($print)
    }
}

function RemoveNetworkPrinter
{
    $printers = Get-Printer
    foreach($printer in $printers)
    {
        if($printer.Shared -eq $true)
        {
            Write-Host "$($printer.Name) is shared over the network"
            $Global:network.RemovePrinterConnection($($printer.Name))
        }
    }
}

#powershell –ExecutionPolicy Bypass

#deleteMappedDrives
#MapPersonalDrive
#MapGlobalDrive
addNetworkPrinter
#RemoveNetworkPrinter






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