#required functions for misc uses
function getAdapter{
    param(
        [Parameter(Mandatory=$true)]
        [string]$abinput
    )
    $adapters = Get-NetIPAddress
    foreach($e in $adapters){
       if($e.IPAddress -match $abinput -and $e.AddressFamily -eq "IPv4"){
           $e.InterfaceAlias
       }
    }
}
#start server setup
function setUpNetwork{
    Rename-NetAdapter -Name (getAdapter -abinput "201") -NewName "WAN"
    Rename-NetAdapter -Name (getAdapter -abinput "169") -NewName "LAN"
    New-NetIPAddress -InterfaceAlias "LAN" -IPAddress "10.10.10.1" -PrefixLength 21
    Set-DnsClientServerAddress -InterfaceAlias "LAN" -ServerAddresses 127.0.0.1
}
setUpNetwork
function domainController{
    #install and setup ad-ds
    Install-WindowsFeature -Name ad-Domain-Services -IncludeManagementTools

    #Promote server to DC
    Install-ADDSForest -DomainName 3T.local -InstallDns -SafeModeAdministratorPassword (ConvertTo-SecureString -AsPlainText "pass.123" -Force)

}
#REBOOT --------------------------------------
domainController
function setUpDHCP{
    #install dhcp role
    Install-WindowsFeature -Name DHCP -IncludeManagementTools

    #set up dhcp scope
    Add-DhcpServerv4Scope -Name "Scope 1" -StartRange 10.10.10.3 -EndRange 10.10.15.254 -SubnetMask 255.255.248.0
    Set-DhcpServerv4OptionValue -DnsServer 10.10.10.1 -Router 10.10.10.1
    Add-DhcpServerInDC $($env:COMPUTERNAME + "." + $env:USERDNSDOMAIN)

}


function setUpIIS{
    # Búa til lénið skoli.is, þarf bara að gera einu sinni.
    Add-DnsServerPrimaryZone -Name $($env:USERDOMAIN + ".is") -ReplicationScope Domain

    # Búa til host færslu fyrir www (IPv4)
    Add-DnsServerResourceRecordA -ZoneName $($env:USERDOMAIN + ".is") -Name "www" -IPv4Address "172.16.19.254"
    # Hér mætti svo bæta við fleiri host færslum fyrir t.d. skoli.is (án www)

    ### IIS ###

    # Setja inn IIS role-ið, þarf bara að gera einu sinni.
    Install-WindowsFeature web-server -IncludeManagementTools

    # Búa til nýja möppu í wwwroot
    New-Item $("C:\inetpub\wwwroot\www." + $env:USERDOMAIN + ".is") -ItemType Directory

    # Búa til html skjal sem inniheldur "Vefsíðan www.skoli.is" í nýju möppuna
    New-Item $("C:\inetpub\wwwroot\www."+ $env:USERDOMAIN + ".is" +"\index.html") -ItemType File -Value $("Vefsíðan www."+$env:USERDOMAIN+".is")

}

function setUpWin81{
    #password
    $passwd = ConvertTo-SecureString -AsPlainText "2015P@ssword" -Force
    $win8Notandi = New-Object System.Management.Automation.PSCredential -ArgumentList $("\administrator"), $passwd
    $serverNotandi = New-Object System.Management.Automation.PSCredential -ArgumentList $($env:USERDNSDOMAIN.Split('.')[0] +"\administrator"), $passwd

    #add w8.1 to domain
    Add-Computer -ComputerName "win3a-w81-03" -LocalCredential $win8Notandi -DomainName $env:USERDNSDOMAIN -Credential $serverNotandi -Restart -Force
    Add-Computer -ComputerName "win3a-w81-04" -LocalCredential $win8Notandi -DomainName $env:USERDNSDOMAIN -Credential $serverNotandi -Restart -Force

    #make Ou for computers
    New-ADOrganizationalUnit "Tolvur" -ProtectedFromAccidentalDeletion $false

    #move w8.1 to new Ou
    Move-ADObject -Identity $("CN=WIN3A-W81-03, CN=Computers, DC="+$env:USERDNSDOMAIN.Split('.')[0] + ",DC=local") -TargetPath $("OU=Tolvur, DC="+$env:USERDNSDOMAIN.Split('.')[0] + ", DC="+$env:USERDNSDOMAIN.Split('.')[1])
    Move-ADObject -Identity $("CN=WIN3A-W81-04, CN=Computers, DC="+$env:USERDNSDOMAIN.Split('.')[0] + ",DC=local") -TargetPath $("OU=Tolvur, DC="+$env:USERDNSDOMAIN.Split('.')[0] + ", DC="+$env:USERDNSDOMAIN.Split('.')[1])

}
setUpWin81
function replaceISL($inputISL){
    $s = $inputISL.ToLower()
    $s = $s.replace('ú','u')
    $s = $s.Replace('é','e')
    $s = $s.replace('á','a')
    $s = $s.replace('ð','d')
    $s = $s.replace('í','i')
    $s = $s.replace('ó','o')
    $s = $s.replace('ú','u')
    $s = $s.replace('þ','th')
    $s = $s.replace('æ','ae')
    $s = $s.replace('ö','o')
    $s = $s.replace('ý','y')
    $s = $s.replace('.', '')
    $s = $s.replace(' ','.')
    if($s.Length -gt 20){
        $s = $s.Substring(0, 20)
    }
    if($s[$s.Length-1] -eq '.'){
        $s = $s.Substring(0,19)
    }
    return $s
}

$Script:names = @()
function userName($name){
    write-host $name
    $s = $name.Split(' ');
    $newName = $($s[0].Substring(0,2) + $s[$s.Count-1].Substring(0,2)).ToLower()
    $Script:names += $newName

    $counter = 0
    foreach($n in $Script:names){
        if($n -eq $newName){
            $counter++
        }
    }
    write-Host $counter
    $nr = $counter
    $s = $newName
    $s = $s.replace('ú','u')
    $s = $s.Replace('é','e')
    $s = $s.replace('á','a')
    $s = $s.replace('ð','d')
    $s = $s.replace('í','i')
    $s = $s.replace('ó','o')
    $s = $s.replace('ú','u')
    $s = $s.replace('þ','t')
    $s = $s.replace('æ','a')
    $s = $s.replace('ö','o')
    $s = $s.replace('ý','y')

    if($nr -eq 1){
        return $s
    }
    else{
        return $($s + ($nr -1))
    }
}

function userSetup{

    New-ADOrganizationalUnit "Notendur" -ProtectedFromAccidentalDeletion $false
    New-ADOrganizationalUnit -Name "Starfsmenn" -Path $("ou=notendur,dc="+$env:USERDNSDOMAIN.Split('.')[0] + ",dc=local") -ProtectedFromAccidentalDeletion $false
    New-ADGroup -Name "Allir" -Path $("ou=notendur, dc="+$env:USERDNSDOMAIN.Split('.')[0]+",DC=local") -GroupScope Global
    New-GPO -Name "Notendur_GPO" -Comment "Group Policy fyrir alla notendur"

    #-----------------------------------------------------

    New-GPLink -Name "Notendur_GPO" -Target $("ou=notendur, dc="+$env:USERDNSDOMAIN.Split('.')[0]+",DC=local")

    $notendur = Import-Csv C:\Users\Administrator\Downloads\lokaverk_notendur.csv
    <#
    #búa til möppu og sækja réttindi
    New-Item c:\Data\sameign -ItemType Directory
    $rettindi = Get-Acl -Path c:\Data\sameign
    $nyRettindi = New-Object System.Security.AccessControl.FileSystemAccessRule($($env:USERDOMAIN + "\Allir"), "Modify", "Allow")# þarf að nota netbios nafn ef það er defined
    $rettindi.AddAccessRule($nyRettindi)
    Set-Acl -Path c:\Data\sameign $rettindi
    New-SmbShare sameign -Path c:\Data\sameign -FullAccess Everyone

    #bara keyra printer driver 1 sinni fyrir hvern driver ekki fyrir hvern prentara
    Add-PrinterDriver -Name "HP LaserJet 2300L PCL6 Class Driver"
    Add-Printer -Name "Allir Prentari" -DriverName "HP LaserJet 2300L PCL6 Class Driver" -PortName "LPT1:" -Shared -ShareName "Allir_Prentari" -Published
    #>
    $ouPath
    foreach($n in $notendur){
        $school = $n.Skoli
        $role = $n.Hlutverk
        $course = $n.Braut

        if($role -eq "Kennarar"){
            if((Get-ADOrganizationalUnit -Filter {name -eq $role}).Name -ne $role){
                New-ADOrganizationalUnit -Name $role -Path $("ou=Starfsmenn,ou=notendur,dc="+$env:USERDNSDOMAIN.Split('.')[0] + ",dc=local") -ProtectedFromAccidentalDeletion $false
                New-ADGroup -Name $($role + "_grp") -Path $("ou="+$role + ",ou=Starfsmenn,ou=notendur,dc="+$env:USERDNSDOMAIN.Split('.')[0] + ",dc=local") -GroupScope Global
                Add-ADGroupMember -Identity "Allir" -Members $($role + "_grp")
                <#
                #Búa til möppur fyrir deildir
                New-Item c:\Data\$deild -ItemType Directory
                $rettindi = Get-Acl -Path c:\Data\$deild
                $nyRettindi = New-Object System.Security.AccessControl.FileSystemAccessRule($($env:USERDOMAIN + "\" + $deild +" "+$office+ "_grp"), "Modify", "Allow") # þarf að vera netbios nafn ef það er skilgreint
                $rettindi.AddAccessRule($nyRettindi)
                Set-Acl -Path c:\Data\$deild $rettindi
                New-SmbShare $deild -Path c:\Data\$deild -FullAccess Everyone
        
                #búa til Prentara fyrir deild
                Add-Printer -Name $($deild + " Prentari") -DriverName "HP LaserJet 2300L PCL6 Class Driver" -PortName "LPT1:" -Shared -ShareName $($deild + "_Prentari") -Published
                #>
            }
            if((Get-ADOrganizationalUnit -SearchBase $("ou="+$role+",ou=Starfsmenn,ou=notendur,dc="+$env:USERDNSDOMAIN.Split('.')[0] + ",dc=local") -Filter {name -eq $school}).Name -ne $school){
                New-ADOrganizationalUnit -Name $school -Path $("ou="+$role+",ou=Starfsmenn,ou=notendur,dc="+$env:USERDNSDOMAIN.Split('.')[0] + ",dc=local") -ProtectedFromAccidentalDeletion $false
                New-ADGroup -Name $($role +" "+$school+ "_grp") -Path $("ou="+$school + ",ou="+ $role +",ou=Starfsmenn,ou=notendur,dc="+$env:USERDNSDOMAIN.Split('.')[0] + ",dc=local") -GroupScope Global
                Add-ADGroupMember -Identity $($role+"_grp") -Members $($role +" "+$school+ "_grp")
            }
            if((Get-ADOrganizationalUnit -SearchBase $("ou="+$school+",ou="+$role+",ou=Starfsmenn,ou=notendur,dc="+$env:USERDNSDOMAIN.Split('.')[0] + ",dc=local") -Filter {name -eq $course}).Name -ne $course){
                New-ADOrganizationalUnit -Name $course -Path $("ou="+$school+",ou="+$role+",ou=Starfsmenn,ou=notendur,dc="+$env:USERDNSDOMAIN.Split('.')[0] + ",dc=local") -ProtectedFromAccidentalDeletion $false
                New-ADGroup -Name $($role +" "+$school+ " "+$course+"_grp") -Path $("ou="+$course+",ou="+$school + ",ou="+ $role +",ou=Starfsmenn,ou=notendur,dc="+$env:USERDNSDOMAIN.Split('.')[0] + ",dc=local") -GroupScope Global
                Add-ADGroupMember -Identity $($role +" "+$school+ "_grp") -Members $($role +" "+$school+ " "+$course+"_grp")
                $ouPath = $("ou="+$course+",ou="+$school + ",ou="+ $role +",ou=Starfsmenn,ou=notendur,dc="+$env:USERDNSDOMAIN.Split('.')[0] + ",dc=local");
            }
        }
        if($role -eq "Nemendur"){
            if((Get-ADOrganizationalUnit -Filter {name -eq $role}).Name -ne $role){
                New-ADOrganizationalUnit -Name $role -Path $("ou=notendur,dc="+$env:USERDNSDOMAIN.Split('.')[0] + ",dc=local") -ProtectedFromAccidentalDeletion $false
                New-ADGroup -Name $($role + "_grp") -Path $("ou="+$role + ",ou=notendur,dc="+$env:USERDNSDOMAIN.Split('.')[0] + ",dc=local") -GroupScope Global
                Add-ADGroupMember -Identity "Allir" -Members $($role + "_grp")
                <#
                #Búa til möppur fyrir deildir
                New-Item c:\Data\$deild -ItemType Directory
                $rettindi = Get-Acl -Path c:\Data\$deild
                $nyRettindi = New-Object System.Security.AccessControl.FileSystemAccessRule($($env:USERDOMAIN + "\" + $deild +" "+$office+ "_grp"), "Modify", "Allow") # þarf að vera netbios nafn ef það er skilgreint
                $rettindi.AddAccessRule($nyRettindi)
                Set-Acl -Path c:\Data\$deild $rettindi
                New-SmbShare $deild -Path c:\Data\$deild -FullAccess Everyone
        
                #búa til Prentara fyrir deild
                Add-Printer -Name $($deild + " Prentari") -DriverName "HP LaserJet 2300L PCL6 Class Driver" -PortName "LPT1:" -Shared -ShareName $($deild + "_Prentari") -Published
                #>
            }
            if((Get-ADOrganizationalUnit -SearchBase $("ou="+$role+",ou=notendur,dc="+$env:USERDNSDOMAIN.Split('.')[0] + ",dc=local") -Filter {name -eq $school}).Name -ne $school){
                New-ADOrganizationalUnit -Name $school -Path $("ou="+$role+",ou=notendur,dc="+$env:USERDNSDOMAIN.Split('.')[0] + ",dc=local") -ProtectedFromAccidentalDeletion $false
                New-ADGroup -Name $($role +" "+$school+ "_grp") -Path $("ou="+$school + ",ou="+ $role +",ou=notendur,dc="+$env:USERDNSDOMAIN.Split('.')[0] + ",dc=local") -GroupScope Global
                Add-ADGroupMember -Identity $($role+"_grp") -Members $($role +" "+$school+ "_grp")
            }
            if((Get-ADOrganizationalUnit -SearchBase $("ou="+$school+",ou="+$role+",ou=notendur,dc="+$env:USERDNSDOMAIN.Split('.')[0] + ",dc=local") -Filter {name -eq $course}).Name -ne $course){
                New-ADOrganizationalUnit -Name $course -Path $("ou="+$school+",ou="+$role+",ou=notendur,dc="+$env:USERDNSDOMAIN.Split('.')[0] + ",dc=local") -ProtectedFromAccidentalDeletion $false
                New-ADGroup -Name $($role +" "+$school+ " "+$course+"_grp") -Path $("ou="+$course+",ou="+$school + ",ou="+ $role +",ou=notendur,dc="+$env:USERDNSDOMAIN.Split('.')[0] + ",dc=local") -GroupScope Global
                Add-ADGroupMember -Identity $($role +" "+$school+ "_grp") -Members $($role +" "+$school+ " "+ $course +"_grp")
                $ouPath = $("ou="+$course+",ou="+$school + ",ou="+ $role +",ou=notendur,dc="+$env:USERDNSDOMAIN.Split('.')[0] + ",dc=local")
            }
        }
           
        $tempNameSplit = $n.Nafn.Split(' ')
        $newGivenName = $n.Nafn -replace $tempNameSplit[$tempNameSplit.Count - 1], ''
        $newSurname = $tempNameSplit[$tempNameSplit.Count -1]
            

            
        if($role -eq "Kennarar"){
            $ouPath = $("ou="+$course+",ou="+$school + ",ou="+ $role +",ou=Starfsmenn,ou=notendur,dc="+$env:USERDNSDOMAIN.Split('.')[0] + ",dc=local");
            $newUsername = replaceISL -inputISL $n.Nafn
        }
        elseif($role -eq "Nemendur"){
            $ouPath = $("ou="+$course+",ou="+$school + ",ou="+ $role +",ou=notendur,dc="+$env:USERDNSDOMAIN.Split('.')[0] + ",dc=local");
            $newUsername = userName -name $n.Nafn
        }
        $ouPath
        $user = @{
            'Name' = $n.Nafn;
            'DisplayName' = $n.Nafn;
            'GivenName' = $newGivenName;
            'Surname' = $newSurname;
            'SamAccountName' = $newUsername;
            'UserPrincipalName' = $($newUsername + "@" +$env:USERDNSDOMAIN) 
            'AccountPassword' = (ConvertTo-SecureString -AsPlainText "pass.123" -Force) 
            'Path' = $ouPath
            'Enabled' = $true
        }
            New-ADUser @user
            Add-ADGroupMember -Identity $($role +" "+$school+ " "+$course+"_grp") -Members $newUsername

            
        }
    
}
userSetup



function webSiteSetup{

    $users = Get-ADUser

    if($braut -eq "Tölvubraut"){
        Add-DnsServerResourceRecordA -ZoneName $($env:USERDOMAIN + ".is") -Name $newUsername -IPv4Address "10.10.10.1"
        #New-Item -ItemType directory -Path $( "C:\inetpub\wwwroot\" + $newUsername)
        New-Item $( "C:\inetpub\wwwroot\" + $newUsername +"\index.html") -ItemType File -Value $("Vefsíðan fyrir "+$n.nafn+".is")
        New-Website -Name $($newUsername +"."+ $env:USERDOMAIN + ".is") -HostHeader $($newUsername +"."+ $env:USERDOMAIN + ".is") -PhysicalPath $( "C:\inetpub\wwwroot\" + $newUsername)
    }
}



<#
#code below not required for general use
function miscSetup{
    Set-GPRegistryValue -Name "Notendur_GPO" -Key "HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop\" -ValueName ScreenSaveTimeOut -Type String -Value "700" #VIRKAR LOKINS ÞAÐ ÞURFTI BARA AÐ HAFA TÖLURNAR SEM STRING
    Set-GPRegistryValue -Name "Notendur_GPO" -Key "HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop\" -ValueName SCRNSAVE.EXE -Type String -Value bubbles.scr

    # til að finna registry key fyrir group policy dót : https://www.mysysadmintips.com/windows/clients/370-find-which-registry-entry-group-policy-changes

    #force gpupdate á öllum domain tölvum
    Get-ADComputer -Filter *  | Foreach-Object {Invoke-GPUpdate -Computer $_.name -Force -RandomDelayInMinutes 0}

    #New-GPO -Name "Tolvur_GPO" -Comment "GPO fyrir tölvur"

    #Set-GPRegistryValue -Name "Tolvur_GPO" -Key "HKCU\Software\Policies\Microsoft\MMC" -ValueName 

}
function setUpNat{
    #install and setup NAT
    Install-WindowsFeature -Name RemoteAccess, Routing -IncludeManagementTools

    #virkar ekki ennþá þarf að skoða þetta meira
    netsh routing ip nat install
    netsh routing ip nat add interface "WAN"
    netsh routing ip nat set interface "WAN"mode=full
    netsh routing ip nat add interface "LAN"
}

<#
#not required
function addEmployeeNr($Identity, [int]$empNr){
    if($empNr -eq 0){
        Get-ADUser -Identity $identity -Properties * | Select-Object displayname, starfsmannaNr
    }else{
        Set-ADUser -Identity $identity -Replace @{starfsmannaNr = $empNr};
    }
}
foreach($n in $notendur){
    addEmployeeNr -Identity $n.notendanafn -empNr 0
}
foreach($n in $notendur){
    addEmployeeNr -Identity $n.notendanafn -empNr $n.ID
}

#>
#>