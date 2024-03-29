#---------------------------------USER QUESTIONS------------------------------------------
$IP = Read-Host "Select interface's IP address"
$GATEWAY = Read-Host "Select a gateway address"
$MASK = Read-Host "Select CIDR subnet mask (ex : 24)"
$DNS1 = Read-Host "Select DNS 1 server (ex : 8.8.8.8)"
$DNS2 = Read-Host "Select DNS 2 server (ex : 8.8.4.4)"

#-------------------------------------CHECKING--------------------------------------------
$adapter = get-netadapter
if($adapter.Name.length -gt 1)
{
    $i=1
    echo "Il y a plusieurs interfaces :"
    foreach ($int in $adapter.name)
    {  
        echo "$i : $int"
        $i++
    }
    $i--
    $choice = Read-Host "Laquelle voulez-vous configurer ? [1-$i]"
}
else
{
    $choice=0
    echo "Il y a 1 seule interface : $adapter.Name[$choice]"
}
#$eth = $adapter.Name[$choice-1]
$index = $adapter.ifIndex[$choice-1]

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

echo "----------CONFIGURATION FEEDBACK----------"
echo "IP address set to $($inf.IPv4address) and subnet mask to /$($inf.PrefixLength) on interface $($inf.InterfaceAlias)"
echo "------------------------------------------"