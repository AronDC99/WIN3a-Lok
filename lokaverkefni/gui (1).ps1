
0,,,,,,,,,,,,,,,,,,,,,,,,,0,0000000,,,,,,,,,,,,,#Hleð inn klösum fyrir GUI, svipað og References í C#
[System.Reflection.Assembly]::LoadWithPartialName("System.Drawing") 
[System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")

#Breytan notendur er hashtafla sem heldur utan um alla notendur sem finnast, 
#breytan þarf að vera "global" innan skriptunnar
$Script:notendur = @{} 

#Fall sem sér um að leita að notendum og skilar niðurstöðunni í ListBox-ið
function LeitaAdNotendum  {
    #útbý leitarstrenginn set * sitthvoru megin við það sem er í textaboxinu
    $leitarstrengur = "*" + $txtLeita.Text + "*"
    #finn alla notendur þar sem leitarstrengurinn kemur fram í nafninu, tek nafnið
    #og samaccountname, nafnið birti ég en nota svo samaccount til að fá frekari
    #upplýsingar um notanda sem valinn er. Set þetta í global notendur breytuna
    $Script:notendur = Get-ADUser -Filter { name -like $leitarstrengur } | select name, samaccountname
    #set svo niðurstöðurnar í listboxið
    foreach($notandi in $Script:notendur) {
        $lstNidurstodur.Items.Add($notandi.name)
    }
}

#fall sem keyrir þegar eitthvað er valið úr listboxinu
function NotandiValinn {
    #TODO hér væri einhver virkni sem keyrði þegar notandi er valinn í listbox-inu
    $samName = $Script:notendur[$lstNidurstodur.SelectedIndex].samaccountname
    Write-Host $samName
    #enable / disable takkinn
    #B� til tilvik af Button
    $btnEnableDisable = New-Object System.Windows.Forms.Button
    #Set sta�setningu � takkanum
    $btnEnableDisable.Location = New-Object System.Drawing.Point(300,115)
    #Set st�r�ina � takkanum
    $btnEnableDisable.Size = New-Object System.Drawing.Size(75,35)
    #Set texta � takkann
    if( (Get-ADUser -Identity $samName).enabled -eq $true){
    $btnEnableDisable.Text = "Disable"
    #B� til event sem keyrir �egar smellt er � takkann. �egar smellt er � takkan � a� kalla � falli� LeitaAdNotendum
    $btnEnableDisable.add_Click({ DisableUser })
    }
    elseif( (Get-ADUser -Identity $samName).enabled -eq $false){
    $btnEnableDisable.Text = "Enable"
    #B� til event sem keyrir �egar smellt er � takkann. �egar smellt er � takkan � a� kalla � falli� LeitaAdNotendum
    $btnEnableDisable.add_Click({ EnableUser })
    }
    #Sett takkann � formi�
    $frmLeita.Controls.Add($btnEnableDisable)

}

function changePass {
    Set-ADAccountPassword -Identity $Script:notendur[$lstNidurstodur.SelectedIndex].samaccountname -NewPassword (ConvertTo-SecureString -AsPlainText "pass.123" -Force)
    Write-Host $("breytti password fyrir: " + $Script:notendur[$lstNidurstodur.SelectedIndex].name)
}
#Aðalglugginn 
#Bý til tilvik af Form úr Windows Forms
$frmLeita = New-Object System.Windows.Forms.Form
#Set stærðina á forminu
$frmLeita.ClientSize = New-Object System.Drawing.Size(550,400)
#Set titil á formið
$frmLeita.Text = "Leita að notendum"

#Leita takkinn
#Bý til tilvik af Button
$btnLeita = New-Object System.Windows.Forms.Button
#Set staðsetningu á takkanum
$btnLeita.Location = New-Object System.Drawing.Point(300,25)
#Set stærðina á takkanum
$btnLeita.Size = New-Object System.Drawing.Size(75,25)
#Set texta á takkann
$btnLeita.Text = "Leita"
#Bý til event sem keyrir þegar smellt er á takkann. Þegar smellt er á takkan á að kalla í fallið LeitaAdNotendum
$btnLeita.add_Click({ LeitaAdNotendum })
#Sett takkann á formið
$frmLeita.Controls.Add($btnLeita)

#Label Nafn:
#Bý til tilvik af Label
$lblNafn = New-Object System.Windows.Forms.Label
#Set staðsetningu á label-inn
$lblNafn.Location = New-Object System.Drawing.Point(30,30)
#Set stærðina
$lblNafn.Size = New-Object System.Drawing.Size(50,20)
#Set texta á 
$lblNafn.Text = "Nafn:"
#Set label-inn á formið
$frmLeita.Controls.Add($lblNafn)

#Textabox fyrir leitarskilyrðin
#Bý til tilvik af TextBox
$txtLeita = New-Object System.Windows.Forms.TextBox
#Set staðsetninguna
$txtLeita.Location = New-Object System.Drawing.Point(80,30)
#Set stærðina
$txtLeita.Size = New-Object System.Drawing.Size(210,30)
#Set textboxið á formið
$frmLeita.Controls.Add($txtLeita)

#Listbox fyrir leitarniðurstöður
#Bý til tilvik af ListBox
$lstNidurstodur = New-Object System.Windows.Forms.ListBox
#Set staðsetningu
$lstNidurstodur.Location = New-Object System.Drawing.Point(80,60)
#Set stærðina
$lstNidurstodur.Size = New-Object System.Drawing.Size(210,100)
#Bý til event sem keyrir þegar eitthvað er valið í listboxinu, kalla þá í fallið NotandiValinn
$lstNidurstodur.add_SelectedIndexChanged( { NotandiValinn } )
#Set listboxið á formið
$frmLeita.Controls.Add($lstNidurstodur)


$btnBreytaPass = New-Object System.Windows.Forms.Button
#Set sta�setningu � takkanum
$btnBreytaPass.Location = New-Object System.Drawing.Point(300,60)
#Set st�r�ina � takkanum
$btnBreytaPass.Size = New-Object System.Drawing.Size(75,35)
#Set texta � takkann
$btnBreytaPass.Text = "Breyta password"
#B� til event sem keyrir �egar smellt er � takkann. �egar smellt er � takkan � a� kalla � falli� LeitaAdNotendum
$btnBreytaPass.add_Click({ changePass })
#Sett takkann � formi�
$frmLeita.Controls.Add($btnBreytaPass)
$frmLeita.ShowDialog()

