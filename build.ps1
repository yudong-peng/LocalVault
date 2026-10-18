param([ValidateSet('win-x64','win-arm64')][string]$Runtime = 'win-x64', [string]$OfflineInstallerPath = '')
$ErrorActionPreference = 'Stop'
$env:DOTNET_CLI_TELEMETRY_OPTOUT = '1'
Set-Location $PSScriptRoot
if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
    throw 'Install the .NET 10 SDK, then run this script again.'
}
dotnet run --project tests/LocalVault.SmokeTests -c Release
if ($LASTEXITCODE -ne 0) { throw 'Core safety tests failed. Publishing stopped.' }
dotnet publish src/LocalVault.Desktop/LocalVault.Desktop.csproj -c Release -r $Runtime --self-contained true -p:PublishSingleFile=false -p:PublishTrimmed=false -o "artifacts/LocalVault-$Runtime"
if ($LASTEXITCODE -ne 0) { throw 'Publish failed.' }
Copy-Item '使用说明.md' "artifacts/LocalVault-$Runtime/使用说明.md"
foreach ($document in @('升级说明.md', 'SECURITY.md', 'TEST-REPORT.md', 'THIRD-PARTY-NOTICES.md')) {
    Copy-Item $document "artifacts/LocalVault-$Runtime/$document"
}
Copy-Item 'LICENSES' "artifacts/LocalVault-$Runtime/" -Recurse -Force
Write-Host "Ready: $PSScriptRoot/artifacts/LocalVault-$Runtime/LocalVault.exe"

if ($OfflineInstallerPath) {
    if ($Runtime -ne 'win-x64') { throw 'This installer parameter currently accepts the x64 offline installer only.' }
    if (-not (Test-Path -LiteralPath $OfflineInstallerPath -PathType Leaf)) { throw 'Offline installer file not found.' }
    New-Item -ItemType Directory -Force "artifacts/LocalVault-$Runtime/Prerequisites" | Out-Null
    Copy-Item -LiteralPath $OfflineInstallerPath -Destination "artifacts/LocalVault-$Runtime/Prerequisites/MicrosoftEdgeWebView2RuntimeInstallerX64.exe"
}
