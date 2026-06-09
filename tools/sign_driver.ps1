param(
    [Parameter(Mandatory=$true)]
    [string]$DriverPath
)

$ErrorActionPreference = 'Stop'

Write-Host "  Checking existing signature..." -NoNewline

$sig = Get-AuthenticodeSignature -FilePath $DriverPath
if ($sig.Status -eq 'Valid') {
    Write-Host " already signed and valid." -ForegroundColor Green
    exit 0
}
Write-Host " not signed." -ForegroundColor Yellow

Write-Host "  Creating self-signed certificate..." -NoNewline

$existingCert = Get-ChildItem Cert:\LocalMachine\My |
    Where-Object { $_.Subject -eq 'CN=NanahiraTestCert' } |
    Select-Object -First 1

if ($existingCert) {
    $cert = $existingCert
    Write-Host " reusing existing." -ForegroundColor Cyan
} else {
    $cert = New-SelfSignedCertificate `
        -Subject 'CN=NanahiraTestCert' `
        -CertStoreLocation 'Cert:\LocalMachine\My' `
        -KeyUsage DigitalSignature `
        -Type CodeSigningCert `
        -HashAlgorithm SHA256
    Write-Host " created." -ForegroundColor Green
}

Write-Host "  Installing certificate to trusted stores..." -NoNewline

$tmpCer = [System.IO.Path]::GetTempFileName() + '.cer'
Export-Certificate -Cert $cert -FilePath $tmpCer | Out-Null

$rootStore = Get-Item 'Cert:\LocalMachine\Root'
$rootStore.Open('ReadWrite')
$rootStore.Add($cert)
$rootStore.Close()

$pubStore = Get-Item 'Cert:\LocalMachine\TrustedPublisher'
$pubStore.Open('ReadWrite')
$pubStore.Add($cert)
$pubStore.Close()

Remove-Item $tmpCer -Force -ErrorAction SilentlyContinue
Write-Host " OK" -ForegroundColor Green

Write-Host "  Signing driver.sys..." -NoNewline

$result = Set-AuthenticodeSignature `
    -FilePath $DriverPath `
    -Certificate $cert `
    -HashAlgorithm SHA256

if ($result.Status -ne 'Valid') {
    Write-Host " failed: $($result.StatusMessage)" -ForegroundColor Red
    exit 1
}

Write-Host " OK" -ForegroundColor Green

Write-Host "  Verifying signature..." -NoNewline
$verify = Get-AuthenticodeSignature -FilePath $DriverPath
if ($verify.Status -eq 'Valid') {
    Write-Host " valid." -ForegroundColor Green
} else {
    Write-Host " $($verify.Status)" -ForegroundColor Yellow
}
