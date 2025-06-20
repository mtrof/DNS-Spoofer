param([string]$InterfaceName)

$interface = Get-NetIPInterface | Where-Object { $_.InterfaceAlias -eq $InterfaceName } | Select-Object -First 1

if ($interface) {
    Set-NetIPInterface -InterfaceIndex $interface.ifIndex -Forwarding Enabled
    Write-Output "Forwarding enabled on interface: $InterfaceName (Index: $($interface.ifIndex))"
} else {
    Write-Output "Interface '$InterfaceName' not found."
}