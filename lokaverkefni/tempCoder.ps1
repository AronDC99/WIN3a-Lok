function setUpIIS{
    # Búa til lénið skoli.is, þarf bara að gera einu sinni.
    Add-DnsServerPrimaryZone -Name $($env:USERDOMAIN + ".is") -ReplicationScope Domain

    # Búa til host færslu fyrir www (IPv4)
    Add-DnsServerResourceRecordA -ZoneName $($env:USERDOMAIN + ".is") -Name "www" -IPv4Address "10.10.10.1"
    # Hér mætti svo bæta við fleiri host færslum fyrir t.d. skoli.is (án www)

    ### IIS ###

    # Setja inn IIS role-ið, þarf bara að gera einu sinni.
    Install-WindowsFeature web-server -IncludeManagementTools

    # Búa til nýja möppu í wwwroot
    New-Item $("C:\inetpub\wwwroot\www." + $env:USERDOMAIN + ".is") -ItemType Directory

    # Búa til html skjal sem inniheldur "Vefsíðan www.skoli.is" í nýju möppuna
    New-Item $("C:\inetpub\wwwroot\www."+ $env:USERDOMAIN + ".is" +"\index.html") -ItemType File -Value "Vefsíðan www.skoli.is"

}
setUpIIS


function userName($name){
    $s = $name.Split(' ');
    $newName = $($s[0].Substring(0,2) + $s[$s.Count-1].Substring(0,2)).ToLower()
    $names += $newName

    $counter = 0
    foreach($n in $names){
        if($n -eq $newName){
            $n
            $counter++
        }
        
    }

    $nr = $counter
    $s = $newName
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
    $newName = $s

    if($nr -eq 0){
        return $newName
    }
    else{
        return $($newName + $nr)
    }
}


#Prentari fyrir alla hópa
Add-PrinterDriver -Name "HP LaserJet 2300L PCL6 Class Driver"
Add-Printer -Name "Allir Prentari" -DriverName "HP LaserJet 2300L PCL6 Class Driver" -PortName "LPT1:" -Shared -ShareName "Allir_Prentari" -Published


#foreach loop sem býr til OU, möppur og setur upp prentara fyrir notendu
foreach($n in $notendur) {
    $deild = $n.Braut
    $OU = $("OU=Tölvubraut,OU=Upplýsingatækniskólinn,OU=Nemendur,OU=Notendur,DC=" + $env:USERDOMAIN + ",DC=Local")
    $users = Get-ADUser -Filter * -SearchBase $OU -Properties *


        if($deild -eq "Tölvubraut"){
        Add-DnsServerResourceRecordA -ZoneName $($env:USERDOMAIN + ".is") -Name $newUsername -IPv4Address "10.10.10.1"
        #New-Item -ItemType directory -Path $( "C:\inetpub\wwwroot\" + $newUsername +"."+ $env:USERDOMAIN + ".is\")
        New-Item $( "C:\inetpub\wwwroot\" + $newUsername +"\index.html") -ItemType File -Value $("Vefsíðan fyrir "+ $n.Nafn+".is")
        New-Website -Name $($newUsername +"."+ $env:USERDOMAIN + ".is") -HostHeader $($newUsername +"."+ $env:USERDOMAIN + ".is") -PhysicalPath $( "C:\inetpub\wwwroot\" + $newUsername)
        }

          #Búa til möppu og sækja réttindin
       New-Item C:\data\$deild -ItemType Directory
       $rettindi = Get-Acl -Path C:\data\$deild
       $nyRettindi = New-Object System.Security.AccessControl.FileSystemAccessRule($($env:USERDOMAIN + "\"+ $deild + "_grp"), "Modify","Allow")
       $rettindi.AddAccessRule($nyRettindi)
       Set-Acl -Path C:\data\$deild $rettindi
       New-SmbShare -name $deild -Path C:\data\$deild -FullAccess "Everyone"

       Add-Printer -Name $($deild + "_prentari") -DriverName "HP LaserJet 2300L PCL6 Class Driver" -PortName "LPT1:" -Location "Fyrir framan kaffistofuna" -Shared -ShareName $($deild + "_prentari") -Published

       
}


