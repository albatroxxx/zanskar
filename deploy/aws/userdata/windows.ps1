<powershell>
# Enable the WinRM HTTPS listener with a self-signed certificate. Zanskar's
# probe records this certificate's fingerprint and pins it (ADR 0012).
$host_name = $env:COMPUTERNAME
$cert = New-SelfSignedCertificate -DnsName $host_name -CertStoreLocation Cert:\LocalMachine\My -NotAfter (Get-Date).AddYears(2)
winrm quickconfig -q -force
Get-ChildItem WSMan:\localhost\Listener | Where-Object { $_.Keys -contains "Transport=HTTPS" } | Remove-Item -Recurse -ErrorAction SilentlyContinue
New-Item -Path WSMan:\localhost\Listener -Transport HTTPS -Address * -CertificateThumbPrint $cert.Thumbprint -Force | Out-Null
Set-Item WSMan:\localhost\Service\Auth\Basic -Value $true
Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $false
netsh advfirewall firewall add rule name="WinRM HTTPS" dir=in action=allow protocol=TCP localport=5986
# RDP is on by default in the AMI; make sure NLA stays on.
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1
</powershell>
