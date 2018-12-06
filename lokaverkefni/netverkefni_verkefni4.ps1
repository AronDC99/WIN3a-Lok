#finna muninn á LAN og WAN
function getAdapter{
    param(
        [Parameter(Mandatory=$true)]
        [string]$abinput
    )
    $adapter = Get-NetIPAddress
    foreach($e in $adapter){
        if($e.IPAddress -match $abinput -and $e.AddressFamily -eq "IPv4") {
            $e.InterfaceAlias
        }
    }
}

#-----------------------------------------------------------------------------------------------------------------------------------------------

#Netstillingar
Rename-NetAdapter -Name (getAdapter -abinput "201") -NewName "WAN"
Rename-NetAdapter -Name (getAdapter -abinput "169") -NewName "LAN"
New-NetIPAddress -InterfaceAlias "LAN" -IPAddress 10.10.0.1 -PrefixLength 21
Set-DnsClientServerAddress -InterfaceAlias "LAN" -ServerAddresses 127.0.0.1

#Setja inn AD-DS role-ið
Install-WindowsFeature -Name ad-domain-services -IncludeManagementTools

#Promote server í DC
Install-ADDSForest -DomainName EEP-Ulfur.local -InstallDns -SafeModeAdministratorPassword (ConvertTo-SecureString -AsPlainText "pass.123" -Force)

#REBOOT-----------------------------------------------------------------------------------------------------------------------------------------

#setja inn DHCP role-ið
Install-WindowsFeature -Name DHCP -IncludeManagementTools

#Setja upp DHCP Scope
Add-DhcpServerv4Scope -Name "Scope 1" -StartRange 10.10.0.2 -EndRange 10.10.7.254 -SubnetMask 255.255.248.0
Set-DhcpServerv4OptionValue -DnsServer 10.10.0.1 -Router 10.10.0.1
Add-DhcpServerInDC $($env:COMPUTERNAME + "." + $env:USERDNSDOMAIN)

#-----------------------------------------------------------------------------------------------------------------------------------------------

#Græja lykilorð
$passwd = ConvertTo-SecureString -AsPlainText "2015P@ssword" -Force
$win8notandi = New-Object System.Management.Automation.PSCredential -ArgumentList $("win3a-w81-15\administrator"), $passwd
$serverNotandi = New-Object System.Management.Automation.PSCredential -ArgumentList $($env:USERDOMAIN + "\administrator"), $passwd

#Setja win8 vél á domain
Add-Computer -ComputerName "win3a-w81-15" -LocalCredential $win8notandi -DomainName $env:USERDNSDOMAIN -Credential $serverNotandi -Restart -Force

#Búa til OU fyrir tölvur
New-ADOrganizationalUnit -Name "Tölvur" -ProtectedFromAccidentalDeletion $false

#Færa win8 vél yfir í nýja OU-ið
Move-ADObject -Identity $("CN=WIN3A-W81-15,CN=Computers,DC=" + $env:USERDOMAIN + ",DC=local") -TargetPath $("OU=tölvur, DC=" + $env:USERDOMAIN + ", DC=" + $env:USERDNSDOMAIN.Split('.')[1])


#-----------------------------------------------------------------------------------------------------------------------------------------------
#Nýtt skjal
New-ADOrganizationalUnit "Notendur" -ProtectedFromAccidentalDeletion $false
New-ADGroup -Name "Allir" -Path $("ou=notendur,dc="+ $env:USERDOMAIN + ",DC=local") -GroupScope Global

#-----------------------------------------------------------------------------------------------------------------------------------------------

function replaceISL($inputISL){
    $s = $inputISL.ToLower()
    $s = $s.replace('á','a')
    $s = $s.replace('é','e')
    $s = $s.replace('ú','u')
    $s = $s.replace('ð','d')
    $s = $s.replace('í','i')
    $s = $s.replace('ó','o')
    $s = $s.replace('ú','u')
    $s = $s.replace('þ','th')
    $s = $s.replace('æ','ae')
    $s = $s.replace('ö','o')
    $s = $s.replace('ý','y')
    $s = $s.replace('.','')
    $s = $s.replace(' ','.')
    
    if($s.Length -gt 20){
        $s = $s.subString(0,20) 
    }

    if($s[$s.Length-1] -eq '.'){
        $s.Substring(0,19)
    }
    
    return $s
   
}

#-----------------------------------------------------------------------------------------------------------------------------------------------

#import notendu
$notendur = Import-Csv .\documents\Verkefni4_notendur_u.csv

#-----------------------------------------------------------------------------------------------------------------------------------------------
#foreach loop sem býr til OU, möppur
foreach($n in $notendur) {
    $office = $n.Skrifstofa
        $deild = $n.deild

    if((Get-ADOrganizationalUnit -Filter { name -eq $office }).Name -ne $office) {
        New-ADOrganizationalUnit -Name $office -Path $("ou=notendur,dc="+ $env:USERDOMAIN + ",DC=local") -ProtectedFromAccidentalDeletion $false
        New-ADGroup -Name $($office + "_grp") -Path $("ou=" + $office + ",ou=notendur,dc=" + $env:USERDOMAIN + ",dc=local") -GroupScope Global
        Add-ADGroupMember -Identity "Allir" -Members $($office + "_grp")

    }

    
    if((Get-ADOrganizationalUnit -SearchBase $("ou=" + $office + ",ou=notendur,dc="+ $env:USERDOMAIN + ",DC=local") -Filter { name -eq $deild}).Name -ne $deild) {
        New-ADOrganizationalUnit -Name $deild -Path $("ou=" + $office + ",ou=notendur,dc="+ $env:USERDOMAIN + ",DC=local") -ProtectedFromAccidentalDeletion $false
        New-ADGroup -Name $($deild +" "+ $office +"_grp") -Path $("ou=" + $deild + ",ou=" + $office + ",ou=notendur,dc=" + $env:USERDOMAIN + ",dc=local") -GroupScope Global
        Add-ADGroupMember -Identity $($office + "_grp") -Members $($deild + "_grp")
    }
                                   


    $tempNameSplit = $n.Nafn.Split(' ')
    $newGivenName = $n.Nafn -replace $tempNameSplit[$tempNameSplit.Count -1], ''
    $newSurname = $tempNameSplit[$tempNameSplit.Count -1]
    $newUsername = replaceISL -inputISL $n.Nafn

    $user = @{
            'Name' = $n.Nafn;
            'DisplayName' = $n.Nafn;
            'GivenName' = $newGivenName;
            'Surname' = $newSurname;
            'City' = $n.Sveitarfelag;
            'Department' = $n.Deild;
            'Office' = $n.Skrifstofa;
            'SamAccountName' = $newUsername;
            'employeeID' = $n.Starfsmannanr;
            'employeeNumber' = $n.Kennitala;
            'Title' = $n.Titill;
            'StreetAddress' = $n.Heimilisfang;
            'UserPrincipalName' = $($newUsername + "@" +$env:USERDNSDOMAIN.Split('.')[0]) 
            'AccountPassword' = (ConvertTo-SecureString -AsPlainText "pass.123" -Force) 
            'Path' = $("ou=" +$deild+",ou=" + $office + ",ou=notendur,dc="+$env:USERDNSDOMAIN.Split('.')[0]+",dc=local") 
            'Enabled' = $true
        }

        New-ADUser @user
        Add-ADGroupMember -Identity $($deild+ " " +$office + "_grp") -Members $newUsername
       
}

#-----------------------------------------------------------------------------------------------------------------------------------------------
#Swap tæknideild akureyri við tæknideild kópavogur

$users = Get-ADUser -Filter * -SearchBase $("OU=Tæknideild,OU=Akureyri,OU=Notendur,DC="+$env:USERDOMAIN+",DC=local") -Properties *
$users += Get-ADUser -Filter * -SearchBase $("OU=Tæknideild,OU=Kópavogur,OU=Notendur,DC="+$env:USERDOMAIN+",DC=local") -Properties *


foreach($n in $users){
$office = $n.Office
$deild = $n.Department

    if($office -eq "Akureyri" -and $deild -eq "Tæknideild"){
        $tempOff = "Kópavogur"
        $tempNr = $($tempOff.Substring(0,2) + $deild.Substring(0,4) + $n.employeeID.Substring(6,$n.employeeID.Length-6))
        $tempPath = $("ou=" +$deild+",ou="+$tempOff+",ou=notendur,DC="+$env:USERDOMAIN+",DC=local")
        Set-ADUser -Office $tempOff -EmployeeID $tempNr -Identity $n.DistinguishedName
        Move-ADObject -Identity $n.DistinguishedName -TargetPath $tempPath
        Remove-ADGroupMember -Identity $($deild +" "+$office+ "_grp") -Members $n.SamAccountName -Confirm: $false
        Add-ADGroupMember -Identity $($deild+" "+$tempOff+"_grp") -Members $n.SamAccountName
    }
    if($office -eq "Kópavogur" -and $deild -eq "Tæknideild"){
        $tempOff = "Akureyri"
        $tempNr = $($tempOff.Substring(0,2) + $deild.Substring(0,4) + $n.employeeID.Substring(6,$n.employeeID.Length-6)) 
        $tempPath = $("ou=" +$deild+",ou="+$tempOff+",ou=notendur,DC="+$env:USERDOMAIN+",DC=local")
        Set-ADUser -Office $tempOff -EmployeeID $tempNr -Identity $n.DistinguishedName
        Move-ADObject -Identity $n.DistinguishedName -TargetPath $tempPath
        Remove-ADGroupMember -Identity $($deild +" "+$office+ "_grp") -Members $n.SamAccountName -Confirm: $false
        Add-ADGroupMember -Identity $($deild+" "+$tempOff+"_grp") -Members $n.SamAccountName
    }
}


#-----------------------------------------------------------------------------------------------------------------------------------------------

