# DNS-AI quick setup for Windows.
#   irm https://raw.githubusercontent.com/confeden/DNS-AI/main/setup.ps1 | iex
#   undo: & ([scriptblock]::Create((irm https://raw.githubusercontent.com/confeden/DNS-AI/main/setup.ps1))) -Undo
# Windows 11: writes the current resolver addresses with native DoH (encrypted only, no fallback).
# Windows 7/8/10: have no built-in encrypted DNS, so the DNS-AI program is downloaded and installed.
# Saved WITHOUT a BOM on purpose: `irm | iex` keeps the BOM as a character and fails on line 1.
# The server must send `charset=utf-8` (raw.githubusercontent.com does) or the Russian text breaks.
param([switch]$Undo)

function Invoke-DnsAiSetup {
    param([bool]$Undo)

    $ErrorActionPreference = 'Stop'
    $Url       = 'https://raw.githubusercontent.com/confeden/DNS-AI/main/setup.ps1'
    $Manifests = @('https://raw.githubusercontent.com/confeden/DNS-AI/main/endpoints.json',
                   'https://dns-ai.ru/endpoints.json')
    $Template  = 'https://dns.dns-ai.ru/dns-query'
    $ExeUrl    = 'https://github.com/confeden/DNS-AI/releases/latest/download/DNS-AI.exe'
    $BuiltinV4 = @('186.246.49.127', '192.144.59.14')
    $BuiltinV6 = @('2a0a:2b41:0:500d::53', '2a0d:8480:0:67c::14')
    $DohKey    = 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters'
    $SkipName  = 'Hyper-V|VMware|VirtualBox|WSL|vEthernet|TAP|WireGuard|Wintun|Tailscale|ZeroTier|Amnezia|OpenVPN|Loopback|Virtual'

    # --- elevation: the script arrives through a pipe, so the child fetches it again
    $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $admin) {
        Write-Host 'Нужны права администратора — Windows сейчас спросит разрешение.' -ForegroundColor Yellow
        $cmd = if ($Undo) { "& ([scriptblock]::Create((irm $Url))) -Undo" } else { "irm $Url | iex" }
        $cmd = "[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072; $cmd; Read-Host 'Нажмите Enter, чтобы закрыть окно'"
        try {
            Start-Process powershell.exe -Verb RunAs -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', $cmd)
        } catch {
            Write-Host 'Запуск от имени администратора отменён.' -ForegroundColor Red
        }
        return
    }

    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

    # --- OS
    $cv    = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $build = [int]$cv.CurrentBuildNumber
    $name  = if ($build -ge 22000) { 'Windows 11' } elseif ($build -ge 10240) { 'Windows 10' } else { 'Windows 7/8' }
    Write-Host ("Система: {0} ({1}), сборка {2}" -f $name, $cv.EditionID, $build)

    # --- current addresses: GitHub, then the site's mirror, then the built-in pair
    $v4 = @(); $v6 = @(); $retired = @()
    foreach ($m in $Manifests) {
        try {
            $j = Invoke-RestMethod -Uri $m -UseBasicParsing -TimeoutSec 10
            $a4 = @($j.v4 | Where-Object { $_ -match '^\d{1,3}(\.\d{1,3}){3}$' })
            if ($a4.Count -gt 0) {
                $v4 = @($a4 | Select-Object -First 2)
                $v6 = @($j.v6 | Where-Object { $_ -match ':' } | Select-Object -First 2)
                $retired = @($j.retired)
                Write-Host ("Адреса получены: {0} (выпуск {1})" -f $m, $j.serial)
                break
            }
        } catch {
            Write-Host ("Не удалось прочитать {0}: {1}" -f $m, $_.Exception.Message) -ForegroundColor DarkYellow
        }
    }
    if ($v4.Count -eq 0) {
        $v4 = $BuiltinV4; $v6 = $BuiltinV6
        Write-Host 'Список адресов недоступен — использую встроенные.' -ForegroundColor Yellow
    }

    if ($build -lt 22000) {
        if ($Undo) {
            Write-Host 'На этой Windows DNS-AI ставится программой. Удалите её в «Приложения и возможности»'
            Write-Host 'или командой:  & "$env:ProgramFiles\DNS-AI\DNS-AI.exe" remove'
            return
        }
        Write-Host 'В этой Windows нет встроенного шифрованного DNS, поэтому ставлю программу DNS-AI.'
        $exe = Join-Path $env:TEMP 'DNS-AI.exe'
        try {
            Invoke-WebRequest -Uri $ExeUrl -OutFile $exe -UseBasicParsing -TimeoutSec 120
        } catch {
            Write-Host ("Не удалось скачать программу: {0}" -f $_.Exception.Message) -ForegroundColor Red
            Write-Host 'Скачайте её вручную: https://github.com/confeden/DNS-AI/releases или см. https://dns-ai.ru/#setup'
            return
        }
        Unblock-File -Path $exe -ErrorAction SilentlyContinue
        $p = Start-Process -FilePath $exe -ArgumentList 'setup' -Wait -PassThru
        if ($p.ExitCode -eq 0) {
            Write-Host 'Готово: программа установлена, служба запущена. Проверка: https://dns-ai.ru/ip' -ForegroundColor Green
        } else {
            Write-Host ("Установка завершилась с кодом {0}." -f $p.ExitCode) -ForegroundColor Red
        }
        return
    }

    # --- Windows 11: native DoH
    $ours = @($v4 + $v6 + $BuiltinV4 + $BuiltinV6 + $retired | Where-Object { $_ } | Select-Object -Unique)
    $adapters = @(Get-NetAdapter | Where-Object {
        $_.Status -eq 'Up' -and -not $_.Virtual -and
        $_.Name -notmatch $SkipName -and $_.InterfaceDescription -notmatch $SkipName })
    if ($adapters.Count -eq 0) {
        Write-Host 'Не найдено ни одного подключённого физического адаптера.' -ForegroundColor Red
        return
    }

    if ($Undo) {
        foreach ($a in $adapters) {
            try {
                Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ResetServerAddresses
                foreach ($fam in 'Doh', 'Doh6') {
                    $k = Join-Path $DohKey ("{0}\DohInterfaceSettings\{1}" -f $a.InterfaceGuid, $fam)
                    foreach ($ip in $ours) {
                        if (Test-Path (Join-Path $k $ip)) { Remove-Item (Join-Path $k $ip) -Recurse -Force }
                    }
                }
                Write-Host ("{0}: DNS снова автоматический" -f $a.Name)
            } catch {
                Write-Host ("{0}: {1}" -f $a.Name, $_.Exception.Message) -ForegroundColor Red
            }
        }
        foreach ($ip in $ours) {
            if (Get-DnsClientDohServerAddress -ServerAddress $ip -ErrorAction SilentlyContinue) {
                Remove-DnsClientDohServerAddress -ServerAddress $ip -ErrorAction SilentlyContinue
            }
        }
        Clear-DnsClientCache
        Write-Host 'Настройки DNS-AI удалены.' -ForegroundColor Green
        return
    }

    foreach ($ip in $v4 + $v6) {
        if (Get-DnsClientDohServerAddress -ServerAddress $ip -ErrorAction SilentlyContinue) {
            Set-DnsClientDohServerAddress -ServerAddress $ip -DohTemplate $Template -AllowFallbackToUdp $false -AutoUpgrade $true | Out-Null
        } else {
            Add-DnsClientDohServerAddress -ServerAddress $ip -DohTemplate $Template -AllowFallbackToUdp $false -AutoUpgrade $true | Out-Null
        }
    }

    $done = 0
    foreach ($a in $adapters) {
        try {
            $hasV6 = $false
            $b = Get-NetAdapterBinding -Name $a.Name -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
            if ($b -and $b.Enabled) { $hasV6 = $true }
            $servers = if ($hasV6) { @($v4 + $v6) } else { @($v4) }
            Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ServerAddresses $servers

            # The adapter's own "encrypted only" switch: DohFlags = 1 per server address.
            $sets = @(@{ Fam = 'Doh'; Ips = $v4 })
            if ($hasV6) { $sets += @{ Fam = 'Doh6'; Ips = $v6 } }
            foreach ($s in $sets) {
                $k = Join-Path $DohKey ("{0}\DohInterfaceSettings\{1}" -f $a.InterfaceGuid, $s.Fam)
                if (Test-Path $k) {
                    Get-ChildItem $k | Where-Object { $s.Ips -notcontains $_.PSChildName } | Remove-Item -Recurse -Force
                }
                foreach ($ip in $s.Ips) {
                    $ik = Join-Path $k $ip
                    if (-not (Test-Path $ik)) { New-Item -Path $ik -Force | Out-Null }
                    New-ItemProperty -Path $ik -Name 'DohFlags' -PropertyType QWord -Value 1 -Force | Out-Null
                }
            }
            # Writing the list again makes the DNS client re-read the switch.
            Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ServerAddresses $servers
            Write-Host ("{0}: {1}" -f $a.Name, ($servers -join ', ')) -ForegroundColor Green
            $done++
        } catch {
            Write-Host ("{0}: {1}" -f $a.Name, $_.Exception.Message) -ForegroundColor Red
        }
    }
    Clear-DnsClientCache

    if ($done -eq 0) {
        Write-Host 'Ни один адаптер настроить не удалось.' -ForegroundColor Red
        return
    }
    Write-Host ''
    Write-Host 'Готово. В «Параметры → Сеть и Интернет» рядом с адресами должно стоять «Зашифровано».' -ForegroundColor Green
    Write-Host 'Проверка: https://dns-ai.ru/ip'
    Write-Host ("Отменить:  & ([scriptblock]::Create((irm {0}))) -Undo" -f $Url)
}

Invoke-DnsAiSetup -Undo:([bool]$Undo -or $env:DNSAI_UNDO -eq '1')
