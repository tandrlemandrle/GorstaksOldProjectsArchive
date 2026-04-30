# Create and Assign GSecurity IPsec Policy using netsh (legacy IPsec compatible with secpol.msc)
# Blocks traffic on commonly exploited ports

# Requires Administrator privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator"
    exit 1
}

Write-Host "Creating GSecurity IPsec Policy (legacy format for secpol.msc)..."

# Define the policy
$policyName = "GSecurity"

# Port definitions: Name, Port, Protocol
$portDefs = @(
    # Original blocks
    @{ Name = "SSH";              Port = 22;   Protocol = "TCP" }
    @{ Name = "Telnet";           Port = 23;   Protocol = "TCP" }
    @{ Name = "RDP";              Port = 3389; Protocol = "TCP" }

    # Worm / lateral movement
    @{ Name = "RPC";              Port = 135;  Protocol = "TCP" }
    @{ Name = "NetBIOS_Name";     Port = 137;  Protocol = "UDP" }
    @{ Name = "NetBIOS_Datagram"; Port = 138;  Protocol = "UDP" }
    @{ Name = "NetBIOS_Session";  Port = 139;  Protocol = "TCP" }
    @{ Name = "SMB";              Port = 445;  Protocol = "TCP" }

    # Remote access / management
    @{ Name = "VNC";              Port = 5900; Protocol = "TCP" }
    @{ Name = "WinRM_HTTP";       Port = 5985; Protocol = "TCP" }
    @{ Name = "WinRM_HTTPS";      Port = 5986; Protocol = "TCP" }

    # Info leak / abuse
    @{ Name = "TFTP";             Port = 69;   Protocol = "UDP" }
    @{ Name = "SNMP";             Port = 161;  Protocol = "UDP" }
    @{ Name = "MSSQL";            Port = 1433; Protocol = "TCP" }
    @{ Name = "MySQL";            Port = 3306; Protocol = "TCP" }
    @{ Name = "PostgreSQL";       Port = 5432; Protocol = "TCP" }

    # FTP
    @{ Name = "FTP_Data";         Port = 20;   Protocol = "TCP" }
    @{ Name = "FTP_Control";      Port = 21;   Protocol = "TCP" }

    # Email
    @{ Name = "SMTP";             Port = 25;   Protocol = "TCP" }
    @{ Name = "SMTP_Submission";  Port = 587;  Protocol = "TCP" }
    @{ Name = "POP3";             Port = 110;  Protocol = "TCP" }
    @{ Name = "POP3S";            Port = 995;  Protocol = "TCP" }
    @{ Name = "IMAP";             Port = 143;  Protocol = "TCP" }
    @{ Name = "IMAPS";            Port = 993;  Protocol = "TCP" }

    # Remote access (additional)
    @{ Name = "VNC_Alt";          Port = 5901; Protocol = "TCP" }

    # SNMP Trap
    @{ Name = "SNMP_Trap";        Port = 162;  Protocol = "UDP" }

    # Database (additional)
    @{ Name = "MongoDB";          Port = 27017; Protocol = "TCP" }

    # Name resolution poisoning
    @{ Name = "LLMNR";            Port = 5355; Protocol = "UDP" }
    @{ Name = "mDNS";             Port = 5353; Protocol = "UDP" }

    # In-memory stores (often exposed without auth)
    @{ Name = "Redis";            Port = 6379;  Protocol = "TCP" }
    @{ Name = "Memcached";        Port = 11211; Protocol = "TCP" }
)

# Delete existing policy if it exists
Write-Host "Checking for existing policy..."
netsh ipsec static delete policy name=$policyName 2>$null

# Create the IPsec Policy
Write-Host "Creating IPsec Policy: $policyName"
netsh ipsec static add policy name=$policyName description="Blocks commonly exploited ports (SSH, Telnet, RDP, RPC, NetBIOS, SMB, VNC, WinRM, FTP, SMTP, POP3, IMAP, TFTP, SNMP, MSSQL, MySQL, PostgreSQL)" assign=yes

# Create filter actions
netsh ipsec static add filteraction name="BlockAction" action=block description="Block traffic"
netsh ipsec static add filteraction name="PermitAction" action=permit description="Permit traffic"

foreach ($p in $portDefs) {
    $port     = $p.Port
    $name     = $p.Name
    $protocol = $p.Protocol

    Write-Host "Creating rules for $name (port $port/$protocol)..."

    # Filter list for inbound traffic (to this port)
    $inboundFilterList = "Inbound_$name"
    netsh ipsec static add filterlist name=$inboundFilterList description="Inbound $name port $port"

    # Filter for inbound (any source to this destination port)
    netsh ipsec static add filter filterlist=$inboundFilterList srcaddr=Any dstaddr=Me protocol=$protocol dstport=$port mirrored=no

    # Rule for inbound (block)
    $inboundRule = "Block_Inbound_$name"
    netsh ipsec static add rule name=$inboundRule policy=$policyName filterlist=$inboundFilterList filteraction="BlockAction"

    # Filter list for outbound traffic (to this port)
    $outboundFilterList = "Outbound_$name"
    netsh ipsec static add filterlist name=$outboundFilterList description="Outbound $name port $port"

    # Filter for outbound (this source to any destination port)
    netsh ipsec static add filter filterlist=$outboundFilterList srcaddr=Me dstaddr=Any protocol=$protocol dstport=$port mirrored=no

    # Rule for outbound (block)
    $outboundRule = "Block_Outbound_$name"
    netsh ipsec static add rule name=$outboundRule policy=$policyName filterlist=$outboundFilterList filteraction="BlockAction"
}

# Assign the policy
Write-Host "Assigning policy..."
netsh ipsec static set policy name=$policyName assign=yes

Write-Host ""
Write-Host "GSecurity IPsec Policy created and assigned successfully!"
Write-Host ""
Write-Host "Blocked ports (inbound + outbound):"
foreach ($p in $portDefs) {
    Write-Host ('  - {0} ({1}/{2})' -f $p.Name, $p.Port, $p.Protocol)
}
Write-Host ""
Write-Host "You can now view the policy in secpol.msc -> IP Security Policies on Local Computer"

# Verify
Write-Host ""
Write-Host "--- Verification ---"
netsh ipsec static show policy name=$policyName verbose
