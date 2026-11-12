# Runs INSIDE the lab VM for the length of the detonation, started by detonate.ps1 in the background.
# Many samples beacon in short bursts (a failed-TLS connect dies in well under a second, then retries),
# so a single netstat at capture time misses them. This appends a netstat snapshot every few seconds;
# collect.ps1 unions them so the answer key records what the sample really talked to.
$ErrorActionPreference = "SilentlyContinue"
$out  = "C:\lab\out\netsamples.txt"
$stop = "C:\lab\out\stop-net.flag"
$deadline = (Get-Date).AddMinutes(30)   # hard safety cap: never run forever
while ((Get-Date) -lt $deadline) {
    if (Test-Path $stop) { break }
    netstat.exe -ano 2>$null | Out-File -Append -Encoding ascii $out
    Start-Sleep -Seconds 3
}
exit 0
