CJusersIndolDownloadslOneLong.ps1

README. txt

donderdag 12 juni 2014 11:19

PowerShell Options:

1: Domaev01.ServerInstall.ps1

- Sets up the ComputerName, IP, DC and DHCP

2: Domaev02. ServerCofigInfo.ps1 + Domaev. ServerCofigInfo.txt

- Shows some server Hardware information

3: Domaev03. DHCPConfig•ps1

- Configures some DHCP scope and reservations

4: Domaev04. DHCPConfigInfo.ps1 + Domaev. DHCPConfigInfo.txt

- Puts some DHCP Config Info to a Textfile in the root of the script

5: Domaev05. CreateFolders .ps1

- Creates some directories with permissions on the Server

6: Domaev06. CreateOUStructure.ps1

- Creates some Organizational Units

7: Domaev07. CreateUsers.ps1

- Create some users and sets some settings for those users

8: Domaev08. RetriveUsers.ps1

+ DDomaev.ADUsers.txt

- List some users from desired AD/OU

9: Domaev09. PowerShellTools.ps1

- The main Menu for the Script is here.

p. s.

You can always check my GitHub for an updated version of it,

with less hardcoding, and some error ahndling.

https://github.com/Nikolai-D/Angel0fForgiveness/tree/master/PowerShell/Domaev. PowerShell

-Opdrachten9

Have fun :)

Domaev01. ServerInstall.psl

"You will need to start this first option of ServerInstall 3 times.

Because there are 2 reboots between the first two options.

After third option you can happily continue.

So now choose desired option:

1 for Changing the Computer name

2 for Installing Domain Controller

3 and this last one option for installing DHCP"

#Call myScriptl from myScript2

Switch (Read-Host "Make a Choise") {

(. \Domaev01. ServerInstalllCompName.ps1)

2

(. \Domaev01. ServerInstall2DC.ps1}

Domaev01. ServerInstalllCompName.ps1

$CompName = Read-Host "Type in the desired ServerName (W2K8PWSHLL01 for Example) "

Rename-Computer $CompName #setting server name

Restart-Computer #obviousely rebooting the machine

Domaev01. ServerInstall2DC.ps1

Write-Host "Lets install some IP and DNS settings."

$Comp = Read-Host "Give the CompName please,"

- 1-



C:|UsersIndolDownloads|OneLong.ps1

SIP = Read-Host "Now type in the desired IP address of the Server (for example 192.168.126.140),"

SPref = Read-Host "Also please type in the desired Prefixtenth (for example 24),"

$DG = Read-Host "Please type in the desired DefaultGateway (for example

192. 168.126.254),"

SPWD = Read-Host "Please type the desired local Administrator password in. (Like

Admin2012) "

New-Net IPAddress $IP -InterfaceAlias "Ethernet" -PrefixLength $Pref -DefaultGateway $DG #setting some TCPIP settings

Set-DnsClientServerAddress -InterfaceAlias

"Ethernet" -ServerAddresses ($IP)

#setting

DNS

AD SERUCE INTERFACEE

( [adsi] "WinNT://$Comp/Administrator"). SetPassword ("$PWD") #admin PW? Admin2012

Install-WindowsFeature AD-Domain-Services -IncludeManagementTools Install-ADDSForest -DomainName domaev. local

#check for 1SB? THE PREFiT - LENGTCH iN IPVG iS THE EQUiVALENT OF THE

Domaev01. ServerInstallInstDHCP. ps1

SUBNET MASK iN iPU4. HOWEVER, RATHER THAN BRiNG

EXPEESSED EN YOENEOS LiKE iTiS IN IPVI,

I EXPRESSEO AE AN INTECER BETWEEN 2-128,

Add-WindowsFeature - IncludeManagementTools dhcp

• \Domaev09. PowerShellTools.ps1

Domaev02. ServerConfigInfo.ps1

WMi → WiNDOWS MANAGEMENT

#get computer manufacturer and serialnumber

INSTRUMENTATION.

#Get-WmiObject win32 bios | format-table manufacturer, serialnumber #get total physical memory

# ( (Get-WmiObject -class "win32_ physicalmemory" -Namespace "root\cimv2"). capacity) / 1gb

#get disk size

#Get-WmiObject -Class "win32_diskdrive" | Format-Table model, size

Write-Host "Showing some Hardware info in the the Text files in the root of the Script"

#Hardware info to a file

ROOT CMUZ ISTHE DREANLT NAMESDACK

$Bios = Get-WmiObject win32_bios

FOr WMS QUERRiES.

$Ram = ( (Get-WmiObject -class "win32_physicalmemory" -Namespace "root \cimv2"). capacity

) / 1gb

$disk = Get-WniObject -Class "win32_ diskdrive"

$info = ("manufacturer ="* $Bios. manufacturer), ("serialnumber = " + $Bios. serialnumber

), ("physicalMemory = " +$Ram), ("disktype =" +$disk. model), ("diskSize =" +$disk.size)

Sinfo |Out-File . \Domaev. ServerConfIginfo.txt

Sinfo

#Icp/ip configuration to a file

Sip = Get-WmiObject -Class win32_networkadapterconfiguration

Sipinfo = ("dns=" +$ip. dnsdomain), ("defaultgateway = " + $ip. dafaultipgateway), ("ip

address = " + Sip. ipaddress), ("nameserver = " + $ip. dnshostname)

Sipinfo | Out-File. \Domaev. ServerConfIginfor. txt

• PowerShel1Tools.ps1 PiPFLiNING PiPELiNING <COmPuTiNC- PiTELiNE iS A

BOAA BROCRSSiNGELIMENISCONNECTED

Domaev03. DHCPconfig.psl

# PowerShell 3.0 creates a

IN TH WHERE THE ONES OR ONE LEMENT

DHCP Scope

Write-Host "Lets set some DHCP settings"

$StartRange = Read-Host "Please type in the StartRange like 192.168.126.160"

SEndRange = Read-Host "Please type in the EndRange like 192.168.126.189"

$SubnetMask = Read-Host "Please type in the SubnetMask like 255.255.255.0"



JorsIndolDownloadslOneLong,ps1

#scopoID = Road-Host "Please type in the Scopei 11ke 192.169.226.2601

$StartRangeBx = Read-Host "Please type in StartRangeEx the like 192.168.126.180"

SEndRangeEx = Read-Host "Please type in the EndRangeEx like 192. 168.126.189"

donderdag 12 juni 2014 11:19

§IPAddress = Read-Host "Please type in the IPAddress like 192.168.126.182"

$ClientID = Read-Host "Please type in the ClientID like f8-db-7f-4f-a4-90"

Install-WindowsFeature DHCP -IncludeManagementTools

Import-Module DHCPServer -Verbose: $False

Add-DHCPServerv4Scope -Name reservationExl -StartRange $StartRange -EndRange $EndRange

-SubnetMask $SubnetMask

Add-DhcpServerv4ExclusionRange -ScopeID $ScopeID -StartRange $StartRangeEx -EndRange

SEndRangeEx

Add-DhcpServerv4Reservation -ScopeID $ScopeID -IPAddress $IPAddress -ClientID $ClientID

• \Domaev09. PowerShellTools.ps1

Domaev04. DHCPConfigInfo.ps1

Write-Host "This

script will output some DHCP config info."

§ScopeId = Read-Host "Type in the scopeID of the DHCP, like 192.168.126.60"

Get-DhcpServerv4Scope | Out-File c: \Domaev. DHCPConfigInfo. txt

Get-DhcpServerv4Reservation -ScopeId $ScopeId | Out-File •\Domaev. DHCPConfigInfo.txt

Get-DhcpServerv4ExclusionRange -ScopeId $ScopeId |Out-File •\Domaev. DHCPConfigInfo.txt

•\Domaev09. PowerShellTools. PowerShellTools.ps1

Domaev05. CreateFolders.ps1

new-item

"C: \DATA\Daily Communications" -itemtype directory

new-item "C: \DATA \Administratie" -itemtype directory new-item C: \DATA\ProjectX\Managers -itemtype directory new-item C: \DATA\ProjectX\Administrators -itemtype directory

new-item C: \Homes -itemtype directory new-item C: \Profiles -itemtype directory

FOFRACH

Get-Acl "C: \DATA\Daily Communications" | Format-List

Sacl = Get-Acl "C: \DATA\Daily Communications"

$acl. SetAccessRuleProtection ($True, SFalse)

Srule = New-Object System. Security. AccessControl. FileSystemAccessRule ("Everyone",

"FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")

$acl. AddAccessRule ($rule)

Set-Acl "C: \DATA\Daily Communications" Sacl

Get-Acl "C:\DATA\Daily Communications" | Format-List

Get-Acl "C: \DATA\Administratie" | Format-List

Sacl = Get-Acl "C: \DATA\Administratie"

Sacl. SetAccessRuleProtection ($True, $False)

§rule = New-Object System. Security. AccessControl. FileSystemAccessRule ("Everyone",

"FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")

$acl. AddAccessRule ($rule)

Set-Acl "C: \DATA\Administratie" Sacl

Get-Acl "C: \DATA\Administratie" | Format-List

Get-Acl C: \DATA\ProjectX\Managers | Format-List

$ac1 = Get-Acl C: \DATA\ ProjectX \Managers

-3-



C: UsersindolDownloads OneLong.ps1

$acl.SetAccessRuleProtection ($True, $False)

Srule = New-Object System.Security.AccessControl. FileSystemAccessRule ("Everyone"

"FullControl"

• "ContainerInherit, ObjectInherit", "None", "Allow")

Sacl. AddAccessRule (§rule)

Set-Acl C: \DATA\Project\Managers Sacl

Get-Acl C: \DATA\Project\Managers | Format-List

Get-Acl C: \DATA\ProjectX\Administrators | Format-List

Sacl = Get-Acl C: DATA\Project Administrators

Sacl. SetAccessRuleProtection ($True, $False)

Srule = New-Object System. Security AccessControl. FileSystemAccessRule ("Everyone"

"FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")

Sacl. AddAccessRule ($rule)

Set-Acl C: \DATA\ProjectX\Administrators $acl

Get-Acl C: \DATA\ProjectX\Administrators | Format-List

Get-Acl C: \Homes | Format-List

Sacl = Get-Acl C: \Homes

Sacl. SetAccessRuleProtection ($True, $False)

Srule = New-Object System. Security AccessControl. FileSystemAccessRule ("Everyone"

"FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")

Sacl. AddAccessRule ($rule)

Set-Acl C: \Homes Sacl

Get-Acl C: \Homes | Format-List

Get-Acl C: \Profiles | Format-List

Sacl = Get-Acl C: \Profiles

Sacl. SetAccessRuleProtection ($True, $False)

$rule = New-Object System. Security. AccessControl. FileSystemAccessRule ("Everyone",

"FullControl", "ContainerInherit, ObjectInherit", "None", "Allow")

Sacl. AddAccessRule ($rule)

Set-Acl C: \Profiles Sacl

Get-Acl C: \Profiles | Format-List

• \Domaev09. PowerShellTools ps1

Domaev06. CreateOUStructure.ps1

Write-Host "Lets create some OUs on this Domain"

• \Domaev09. PowerShellTools.ps1

Domaev06. CreateUAStrueture.ps1

Write-Host "Let

create some OUs on this Domain"

dadd ou "OUbeheer, DC=domaev, DC=local"

dsadd ou "oU=ITAdmins, DC=domaev, DC=1oca1"

dsadd ou

"OU=Managers, DC=domaev, DC=local"

dadd

"OU-Werkvloer, DC=domaev, DC=local"

dsadd ou "OU=Magazijn, DC-domaev, DC-local"











dsadd ou "OU=Deheer, DC=domaev, DC=local"





dadd ou "OU=ITAdmins, DC=domaev, DC=local"





dsadd ou "OU=Managers, DC=domaev, DC=local"

dsadd



ou "OU=Werkvloer, DC=domaev, DC=local"





dadd ou "OU-Magazijn, DC=domaev, DC=local"

dsadd



ou "OU=Laadkaai, DC=domaev, DC=local"





dadd ou "OU=Administratie, DC=domaev, DC=local"

-4-



sadd ou "OU

aadkaai, DC=domaev, DC=local"

dadd ou

Administratie, DC=domaev, DC-local"

• \Domaevp9. PowerShellTools.ps1

Domaev07 CreateUsers. CreateUsers.ps1

New-ADUSer -SamAccountName rverheyen -Name "Rudy Verheyen" -Account Password ( ConvertTo-SecureString -AsPlainText "Hoboken2660" -Force) -Enabled $true - PasswordNeverExpires Strue -Path 'OU=ITAdmins, DC=domaev, DC=local ' New-ADUser -SamAccountName dveusters -Name "Danny Veusters" -Account Password ( ConvertTo-SecureString -AsPlainText "Hoboken2660" -Force) -Enabled $true - PasswordNeverExpires $true -Path 'OU=Managers, DC=domaev, DC=local' New-ADUser -SamAccountName abertels -Name "An Bertels" -AccountPassword ( ConvertTo-SecureString -AsPlainText "Hoboken2660" -Force) -Enabled Strue - PasswordNeverExpires $true -Path 'OU=Administratie, DC=domaev, DC-local' set-aduser rverheyen -homedirectory |\192.168.126. 140\homes \rverheyen -homedrive h: set-aduser dveusters -homedirectory |\192.168.126.140\homes\dveusters -homedrive h: set-aduser abertels -homedirectory |\192.168.126.140 \homes \abertels -homedrive h: set-aduser rverheyen -profilepath | \192.168.126.140\profiles\rverheyen set-aduser deusters -profilepath | \192.168.126.140\profiles\dveusters set-aduser abertels -profilepath \ \192.168.126.140\profiles\abertels Add-ADGroupMember -Identity 'Domain Admins' -Member rverheyen

• \Domaev09. PowerShellTools.ps1

Domaev08 RetrieveUser. RetrieveUser.ps1

$oU = read-host "Welke OU wilt u bekijken?"

Get-ADUser -Filter * -SearchBase "ou=$OU, do-domaev, dc=local" | Out-File C: \Domaev.

ADUsers.txt

• \Domaev09. PowerShellTools.ps1

Domaev08. RetriveUsers.psl

SOU = read-host

Helke OU wilt u bekijken?"

Get-ADUser

Filter * -SearchBase "ou=$OU, de=domaev, dc=local" | Out-File C: \Domaev.

ADUsers.

• \Domae

v09. PowerShellTools.ps1

Domaev09. PowerShellTools. ps1/

"Lets do some PS hacking, which Script do you want to run?

PowerShell Options:

1: Domaev01. ServerInstall.psl