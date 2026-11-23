#Requires -Version 5.1
<#
.SYNOPSIS
    Интерактивная консоль (в стиле sconfig) для просмотра и удаления установленных
    программ и приложений на компьютерах, серверах и ВМ домена.

.DESCRIPTION
    Источники:
      * Реестр Uninstall: HKLM (x64 и x86) и HKU\<SID> всех профилей пользователей
        (незагруженные NTUSER.DAT временно подключаются);
      * Приложения Microsoft Store (Appx) для всех пользователей.

    Удаление выполняется на самих компьютерах (через WinRM):
      * MSI-программы        : msiexec /x {GUID} /qn /norestart
      * есть QuietUninstallString : выполняется он
      * Inno Setup (unins000.exe) : добавляются /VERYSILENT /SUPPRESSMSGBOXES /NORESTART
      * остальные             : только если вы укажете дополнительные аргументы (например /S)
      * Appx                 : Remove-AppxPackage -AllUsers; если пакет остался - удаление по каждому
                               пользователю (+ по запросу удаление из образа системы)
    Каждое удаление ограничено по времени ($UninstallTimeoutSec).

    Требования: запуск от доменного администратора, RSAT (ActiveDirectory),
    на целевых компьютерах включён WinRM (порт 5985).
    Файл сохранён в UTF-8 с BOM для корректной кириллицы в PowerShell 5.1.

.EXAMPLE
    .\Manage-DomainSoftware.ps1 -Domain corp.example.com -StaleDays 60
#>

[CmdletBinding()]
param(
    # DNS-имя домена AD (по умолчанию - домен текущего пользователя)
    [string]$Domain = $(if ($env:USERDNSDOMAIN) { $env:USERDNSDOMAIN } else { 'example.local' }),

    # Пропускать компьютеры, не заходившие в домен более N дней
    [int]$StaleDays = 90,

    # Максимум секунд на удаление одной программы
    [int]$UninstallTimeoutSec = 900
)

# ----------------------------- НАСТРОЙКИ ------------------------------------
$LogBase            = if ($PSScriptRoot) { $PSScriptRoot } else { $env:TEMP }
$LogPath            = Join-Path $LogBase 'DomainSoftwareManager.log'
# ----------------------------------------------------------------------------

Import-Module ActiveDirectory -ErrorAction Stop

$script:Computers  = @()
$script:CompMap    = @{}
$script:Items      = @()
$script:ShowSystem = $false   # системные компоненты, обновления, служебные пакеты
$script:ShowAppx   = $true    # приложения Microsoft Store
$script:LastScan   = $null
$script:ScanType   = 'All'    # All | Client | Server (что сканировать)
$script:ScanOU     = $null    # DN выбранной OU; $null = весь домен

# ======================= КОД, КОТОРЫЙ ВЫПОЛНЯЕТСЯ НА ЦЕЛЕВЫХ ПК =======================
$script:RemoteBlock = {
    param([string]$Op, $Records, $Opts)
    $ErrorActionPreference = 'SilentlyContinue'
    $comp = $env:COMPUTERNAME
    $HKLM = @{ Base = [Microsoft.Win32.Registry]::LocalMachine; Prefix = '' }

    function Open-K($ctx, $sub) {
        try { $ctx.Base.OpenSubKey($ctx.Prefix + $sub, $false) } catch { $null }
    }

    function Get-UserProfiles {
        $pl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
        foreach ($key in (Get-ChildItem $pl)) {
            $sid = $key.PSChildName
            if ($sid -notmatch '^S-1-(5-21|12-1)-') { continue }
            $pp = (Get-ItemProperty $key.PSPath).ProfileImagePath
            if (-not $pp) { continue }
            $name = $null
            try { $name = (New-Object Security.Principal.SecurityIdentifier($sid)).Translate([Security.Principal.NTAccount]).Value } catch { }
            if (-not $name) { $name = Split-Path $pp -Leaf }
            [pscustomobject]@{ Sid = $sid; Path = $pp; Name = $name }
        }
    }

    function Invoke-WithUserHive($Sid, [scriptblock]$Script) {
        $users = [Microsoft.Win32.Registry]::Users
        $k = $users.OpenSubKey($Sid)
        if ($k) { $k.Close(); & $Script @{ Base = $users; Prefix = "$Sid\" }; return }
        $pp = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$Sid").ProfileImagePath
        if (-not $pp) { throw 'Профиль пользователя не найден' }
        $dat = Join-Path $pp 'NTUSER.DAT'
        if (-not (Test-Path -LiteralPath $dat)) { throw 'Нет файла NTUSER.DAT' }
        $tmp = 'TmpHive_' + ($Sid -replace '-', '_')
        $null = & reg.exe load "HKU\$tmp" $dat 2>&1
        if ($LASTEXITCODE -ne 0) { throw 'Не удалось загрузить профиль пользователя (файл занят?)' }
        try { & $Script @{ Base = $users; Prefix = "$tmp\" } }
        finally {
            [gc]::Collect(); [gc]::WaitForPendingFinalizers()
            $null = & reg.exe unload "HKU\$tmp" 2>&1
        }
    }

    function Get-UninstallItems($ctx, $scope, $hive) {
        $base = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
        $defs = @()
        if ($hive -eq 'HKLM') {
            $defs += @{ Sub = $base; Src = 'Reg64' }
            $defs += @{ Sub = 'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'; Src = 'Reg32' }
        } else {
            $defs += @{ Sub = $base; Src = 'User' }
        }
        foreach ($d in $defs) {
            $root = Open-K $ctx $d.Sub
            if (-not $root) { continue }
            try {
                foreach ($sn in $root.GetSubKeyNames()) {
                    $k = $root.OpenSubKey($sn)
                    if (-not $k) { continue }
                    try {
                        $dn = [string]$k.GetValue('DisplayName')
                        if (-not $dn) { continue }
                        $us   = [string]$k.GetValue('UninstallString')
                        $qs   = [string]$k.GetValue('QuietUninstallString')
                        $rel  = [string]$k.GetValue('ReleaseType')
                        $isSys = ($k.GetValue('SystemComponent') -eq 1) -or
                                 [bool]$k.GetValue('ParentKeyName') -or [bool]$k.GetValue('ParentDisplayName') -or
                                 ($rel -match 'Update|Hotfix|Service Pack') -or
                                 ($dn -match '^(Security Update|Update for|Hotfix for)')
                        $isMsi = ($k.GetValue('WindowsInstaller') -eq 1) -or ($us -match '(?i)msiexec')
                        $size  = $k.GetValue('EstimatedSize')
                        $date  = [string]$k.GetValue('InstallDate')
                        if ($date -match '^(\d{4})(\d{2})(\d{2})$') { $date = "$($Matches[3]).$($Matches[2]).$($Matches[1])" }
                        [pscustomobject]@{
                            Computer = $comp; Source = $d.Src; Scope = $scope; Hive = $hive
                            Location = "$($d.Sub)\$sn"; KeyName = $sn; Name = $dn
                            Version = [string]$k.GetValue('DisplayVersion'); Publisher = [string]$k.GetValue('Publisher')
                            InstallDate = $date
                            SizeMB = $(if ($size) { [math]::Round([double]$size / 1024, 1) } else { $null })
                            Uninstall = $us; Quiet = $qs; IsMsi = [bool]$isMsi; IsSystem = [bool]$isSys
                        }
                    } finally { $k.Close() }
                }
            } finally { $root.Close() }
        }
    }

    function Get-AppxItems {
        try { $pk = Get-AppxPackage -AllUsers -ErrorAction Stop } catch { return }
        foreach ($p in $pk) {
            $isSys = [bool]($p.IsFramework -or $p.NonRemovable -or $p.IsResourcePackage -or $p.SignatureKind -eq 'System')
            $pub = [string]$p.Publisher
            if ($pub -match 'CN=([^,]+)') { $pub = $Matches[1] }
            [pscustomobject]@{
                Computer = $comp; Source = 'Appx'; Scope = 'Все пользователи'; Hive = ''
                Location = [string]$p.InstallLocation; KeyName = [string]$p.PackageFullName; Name = [string]$p.Name
                Version = [string]$p.Version; Publisher = $pub; InstallDate = ''; SizeMB = $null
                Uninstall = ''; Quiet = ''; IsMsi = $false; IsSystem = $isSys
            }
        }
    }

    function Get-AppxLeft($name, $full) {
        @(Get-AppxPackage -AllUsers -Name $name | Where-Object { $_.PackageFullName -eq $full })
    }

    function Get-AppxUserSids($pkg) {
        foreach ($ui in @($pkg.PackageUserInformation)) {
            $sid = if ($ui.UserSecurityId.Sid) { [string]$ui.UserSecurityId.Sid } else { [string]$ui.UserSecurityId }
            if ($sid -and ([string]$ui.InstallState) -match 'Installed') { $sid }
        }
    }

    # Удаление Appx: сначала -AllUsers; если пакет остался (например, ошибка 0x80073D19 «пользователь вышел
    # из системы») - удаление отдельно для каждого пользователя. Успех определяется проверкой, что пакета больше нет.
    function Remove-AppxFull($r, $Opts) {
        $name = [string]$r.Name; $full = [string]$r.KeyName
        $firstErr = ''
        try { Remove-AppxPackage -Package $full -AllUsers -ErrorAction Stop }
        catch { $firstErr = (($_.Exception.Message) -split "`n")[0] }
        $left = Get-AppxLeft $name $full

        # из образа системы (чтобы не появлялось у новых пользователей) - по запросу или при ошибке
        if ($Opts.Deprovision -or $left.Count -gt 0) {
            try {
                Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -eq $name } |
                    ForEach-Object { $null = Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName -ErrorAction Stop }
            } catch { }
        }
        if ($left.Count -eq 0) { return [pscustomobject]@{ Ok = $true; Message = '' } }

        foreach ($p in $left) {
            foreach ($sid in @(Get-AppxUserSids $p)) {
                try { Remove-AppxPackage -Package $full -User $sid -ErrorAction Stop } catch { }
            }
        }
        $left = Get-AppxLeft $name $full
        if ($left.Count -eq 0) { return [pscustomobject]@{ Ok = $true; Message = 'Удалено запасным способом (по пользователям)' } }

        $who = @()
        foreach ($p in $left) {
            foreach ($sid in @(Get-AppxUserSids $p)) {
                $n = $null
                try { $n = (New-Object Security.Principal.SecurityIdentifier($sid)).Translate([Security.Principal.NTAccount]).Value } catch { }
                $who += $(if ($n) { $n } else { $sid })
            }
        }
        [pscustomobject]@{ Ok = $false; Message = ('Осталось у пользователей: {0}. {1}' -f (($who | Select-Object -Unique) -join ', '), $firstErr) }
    }

    function Invoke-Uninstall($r, $Opts) {
        $cmdExe = "$env:windir\System32\cmd.exe"
        $msiExe = "$env:windir\System32\msiexec.exe"
        $guidRx = '^\{[0-9A-Fa-f]{8}-([0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}\}$'
        $exe = $null; $argLine = $null
        $u = [string]$r.Uninstall
        if ($r.IsMsi -and ($r.KeyName -match $guidRx)) {
            $exe = $msiExe; $argLine = "/x $($r.KeyName) /qn /norestart"
        }
        elseif ($r.Quiet) {
            $exe = $cmdExe; $argLine = '/c "' + $r.Quiet + '"'
        }
        elseif ($u) {
            if ($u -match '(?i)msiexec(\.exe)?"?\s+/[IX]\s*(\{[0-9A-Fa-f-]{36}\})') {
                $exe = $msiExe; $argLine = "/x $($Matches[2]) /qn /norestart"
            }
            elseif ($u -match '(?i)unins\d{3}\.exe') {
                $exe = $cmdExe; $argLine = '/c "' + $u + ' /VERYSILENT /SUPPRESSMSGBOXES /NORESTART"'
            }
            elseif ($Opts.ExtraArgs) {
                $exe = $cmdExe; $argLine = '/c "' + $u + ' ' + $Opts.ExtraArgs + '"'
            }
            else { return [pscustomobject]@{ Ok = $false; Message = 'Нет тихого режима удаления (нужны доп. аргументы, например /S)' } }
        }
        else { return [pscustomobject]@{ Ok = $false; Message = 'В реестре нет команды удаления' } }

        $p = Start-Process -FilePath $exe -ArgumentList $argLine -PassThru -WindowStyle Hidden
        if (-not $p) { return [pscustomobject]@{ Ok = $false; Message = 'Не удалось запустить процесс удаления' } }
        if (-not $p.WaitForExit([int]$Opts.TimeoutSec * 1000)) {
            $null = & taskkill.exe /T /F /PID $p.Id 2>&1
            return [pscustomobject]@{ Ok = $false; Message = "Таймаут $($Opts.TimeoutSec) с — процесс остановлен" }
        }
        $code = $p.ExitCode
        switch ($code) {
            0       { [pscustomobject]@{ Ok = $true;  Message = '' } }
            3010    { [pscustomobject]@{ Ok = $true;  Message = 'Удалено, нужна перезагрузка' } }
            1641    { [pscustomobject]@{ Ok = $true;  Message = 'Удалено, нужна перезагрузка' } }
            1605    { [pscustomobject]@{ Ok = $true;  Message = 'Уже не установлено' } }
            1618    { [pscustomobject]@{ Ok = $false; Message = 'Занят другой установкой (код 1618)' } }
            default { [pscustomobject]@{ Ok = $false; Message = "Код возврата $code" } }
        }
    }

    # ------------------------------- Сбор -------------------------------
    if ($Op -eq 'Collect') {
        Get-UninstallItems $HKLM 'Система' 'HKLM'
        foreach ($p in (Get-UserProfiles)) {
            try {
                Invoke-WithUserHive $p.Sid {
                    param($ctx)
                    Get-UninstallItems $ctx $p.Name $p.Sid
                }
            } catch { }
        }
        Get-AppxItems
        return
    }

    # ------------------------------ Удаление ----------------------------
    $mine = @($Records | Where-Object { $_.Computer -eq $comp })
    foreach ($r in $mine) {
        $res = [pscustomobject]@{ Computer = $comp; IdKey = $r.IdKey; Ok = $false; Message = '' }
        try {
            if ($r.Source -eq 'Appx') {
                $o = Remove-AppxFull $r $Opts
                $res.Ok = [bool]$o.Ok; $res.Message = [string]$o.Message
            } else {
                $o = Invoke-Uninstall $r $Opts
                $res.Ok = [bool]$o.Ok; $res.Message = [string]$o.Message
            }
        } catch {
            $res.Message = (($_.Exception.Message) -split "`n")[0]
        }
        $res
    }
}
# =======================================================================================

# ------------------------------ Вспомогательное -----------------------------

function Write-Log {
    param([string]$Message)
    $line = '{0:yyyy-MM-dd HH:mm:ss} [{1}] {2}' -f (Get-Date), $env:USERNAME, $Message
    Add-Content -Path $LogPath -Value $line -Encoding UTF8
}

function Read-Key {
    try { [Console]::ReadKey($true).KeyChar.ToString() }
    catch { Read-Host }
}

function Wait-Key {
    Write-Host ''
    Write-Host 'Нажмите любую клавишу для возврата в меню...' -ForegroundColor DarkGray
    [void](Read-Key)
}

function Limit-Text {
    param($Text, [int]$Max = 70)
    $s = [string]$Text
    if ($s.Length -gt $Max) { $s.Substring(0, $Max - 1) + '…' } else { $s }
}

function Write-Header {
    param([string]$Title)
    Clear-Host
    Write-Host ('=' * 78) -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host ('=' * 78) -ForegroundColor Cyan
    Write-Host ''
}

function Get-SourceName {
    param($Source)
    switch ($Source) {
        'Reg64' { 'Реестр (x64)' }
        'Reg32' { 'Реестр (x86)' }
        'User'  { 'Реестр пользователя' }
        'Appx'  { 'Microsoft Store' }
        default { $Source }
    }
}

function Test-PortAsync {
    param([string[]]$Names, [int]$Port, [int]$TimeoutMs = 3000)
    $clients = @{}; $tasks = @{}
    foreach ($n in $Names) {
        try {
            $c = New-Object System.Net.Sockets.TcpClient
            $clients[$n] = $c
            $tasks[$n]   = $c.ConnectAsync($n, $Port)
        } catch { }
    }
    try {
        [void][System.Threading.Tasks.Task]::WaitAll(
            [System.Threading.Tasks.Task[]]@($tasks.Values), $TimeoutMs)
    } catch { }
    $res = @{}
    foreach ($n in $Names) {
        $res[$n] = ($tasks.ContainsKey($n) -and
                    $tasks[$n].Status -eq 'RanToCompletion' -and
                    $clients[$n].Connected)
        if ($clients.ContainsKey($n)) { $clients[$n].Dispose() }
    }
    $res
}

function Test-EscPressed {
    try {
        while ([Console]::KeyAvailable) {
            if ([Console]::ReadKey($true).Key -eq 'Escape') { return $true }
        }
    } catch { }
    $false
}

# Ожидание фонового задания Invoke-Command с индикатором выполнения. Возвращает $true, если нажат Esc.
function Wait-JobProgress {
    param($Job, [int]$Total, [string]$Activity, [string]$StepText, $Stopwatch)
    $cancelled = $false
    while ($true) {
        $children = @($Job.ChildJobs)
        $done     = @($children | Where-Object { $_.State -notin 'NotStarted', 'Running' }).Count
        $running  = @($children | Where-Object { $_.State -eq 'Running' } | Select-Object -First 3 | ForEach-Object { $_.Location })
        Write-Progress -Id 1 -Activity $Activity `
            -Status ("{0}: {1} из {2} | {3:mm\:ss} | сейчас: {4} | Esc — прервать" -f $StepText, $done, $Total, $Stopwatch.Elapsed, ($running -join ', ')) `
            -PercentComplete ([int](100 * $done / [math]::Max(1, $Total)))
        if ($Job.State -notin 'Running', 'NotStarted') { break }
        if (Test-EscPressed) { $cancelled = $true; Stop-Job $Job -ErrorAction SilentlyContinue; break }
        Start-Sleep -Milliseconds 400
    }
    $cancelled
}

function Get-ChildReason {
    param($Child)
    $reason = $null
    try { $reason = $Child.JobStateInfo.Reason.Message } catch { }
    if (-not $reason) { $reason = if ($Child.State -in 'Stopped', 'NotStarted') { 'Прервано' } else { "Состояние: $($Child.State)" } }
    Limit-Text (($reason -split "`n")[0]) 120
}

function Get-VisibleItems {
    param([string]$Type)
    $items = $script:Items
    if (-not $script:ShowSystem) { $items = $items | Where-Object { -not $_.IsSystem } }
    if (-not $script:ShowAppx)   { $items = $items | Where-Object { $_.Source -ne 'Appx' } }
    if ($Type)                   { $items = $items | Where-Object { $_.Type -eq $Type } }
    @($items)
}

function Get-ItemGroups {
    param([string]$Filter)
    $items = Get-VisibleItems
    if ($Filter) { $items = $items | Where-Object { $_.Name -like "*$Filter*" -or $_.Publisher -like "*$Filter*" } }
    @($items | Group-Object -Property Key | Sort-Object { $_.Group[0].Name })
}

function Show-GroupTable {
    param($Groups)
    $i = 0
    $view = foreach ($g in $Groups) {
        $i++
        $vers = @($g.Group | Select-Object -ExpandProperty Version -Unique)
        [pscustomobject][ordered]@{
            '#'         = $i
            'Программа' = Limit-Text $g.Group[0].Name 44
            'Версия'    = $(if ($vers.Count -eq 1) { Limit-Text $vers[0] 16 } else { "разные ($($vers.Count))" })
            'Издатель'  = Limit-Text $g.Group[0].Publisher 22
            'Клиенты'   = @($g.Group | Where-Object { $_.Type -eq 'Client' }).Count
            'Серверы'   = @($g.Group | Where-Object { $_.Type -eq 'Server' }).Count
            'Всего'     = $g.Count
        }
    }
    $view | Format-Table -AutoSize | Out-Host
}

# ------------------------------- Сканирование -------------------------------

function Get-ScanTypeName {
    switch ($script:ScanType) {
        'Client' { 'только компьютеры пользователей' }
        'Server' { 'только серверы и ВМ' }
        default  { 'все компьютеры' }
    }
}

function Switch-ScanType {
    $script:ScanType = switch ($script:ScanType) { 'All' { 'Client' } 'Client' { 'Server' } default { 'All' } }
}

function Clear-Results {
    $script:Computers = @(); $script:Items = @(); $script:CompMap = @{}; $script:LastScan = $null
}

function Update-CompMap {
    $script:CompMap = @{}
    foreach ($c in $script:Computers) { $script:CompMap[$c.Name] = $c }
}

function Get-ScanTargets {
    $limit = (Get-Date).AddDays(-$StaleDays)
    $p = @{
        Server = $Domain; Filter = 'Enabled -eq $true'
        Properties = 'OperatingSystem', 'LastLogonDate'; ErrorAction = 'Stop'
    }
    if ($script:ScanOU) { $p.SearchBase = $script:ScanOU; $p.SearchScope = 'Subtree' }
    Get-ADComputer @p | Where-Object {
        $_.OperatingSystem -like 'Windows*' -and $_.LastLogonDate -gt $limit -and
        ($script:ScanType -eq 'All' -or
         ($script:ScanType -eq 'Server' -and $_.OperatingSystem -like '*Server*') -or
         ($script:ScanType -eq 'Client' -and $_.OperatingSystem -notlike '*Server*'))
    }
}

function Select-ScanOU {
    Write-Header 'Выбор OU для сканирования'
    Write-Host 'Загружаю список OU из AD...' -ForegroundColor Cyan
    try { $ous = @(Get-ADOrganizationalUnit -Server $Domain -Filter * -ErrorAction Stop | Sort-Object DistinguishedName) }
    catch { Write-Host "Ошибка AD: $($_.Exception.Message)" -ForegroundColor Red; Wait-Key; return }

    Write-Host ("Текущая область: {0}" -f $(if ($script:ScanOU) { $script:ScanOU } else { "весь домен $Domain" }))
    Write-Host 'Сканируется выбранная OU вместе со всеми вложенными.' -ForegroundColor DarkGray
    Write-Host ''
    $f = Read-Host 'Фильтр по части имени OU (Enter — показать все)'
    $list = if ($f) { @($ous | Where-Object { $_.DistinguishedName -like "*$f*" }) } else { $ous }
    if ($list.Count -eq 0) { Write-Host 'OU не найдены.' -ForegroundColor Yellow; Wait-Key; return }

    $i = 0
    $view = foreach ($o in $list) { $i++; [pscustomobject]@{ '#' = $i; 'OU' = $o.DistinguishedName } }
    $fmt = $view | Format-Table -AutoSize
    try { $fmt | Out-Host -Paging } catch { $fmt | Out-Host }
    Write-Host ''
    $sel = (Read-Host 'Номер OU, либо DN целиком, либо 0 — весь домен (Enter — без изменений)').Trim()
    if (-not $sel) { return }
    if ($sel -eq '0') { $script:ScanOU = $null; return }
    if ($sel -match '^\d+$') {
        $n = [int]$sel
        if ($n -ge 1 -and $n -le $list.Count) { $script:ScanOU = $list[$n - 1].DistinguishedName }
        else { Write-Host 'Неверный номер.' -ForegroundColor Yellow; Wait-Key }
        return
    }
    if ($sel -match '^(OU|CN|DC)=') {
        try { $null = Get-ADObject -Identity $sel -Server $Domain -ErrorAction Stop; $script:ScanOU = $sel }
        catch { Write-Host 'Такой объект в AD не найден.' -ForegroundColor Red; Wait-Key }
        return
    }
    Write-Host 'Неверный ввод.' -ForegroundColor Yellow; Wait-Key
}

function Invoke-Scan {
    Write-Header 'Сканирование'
    Write-Host ("Тип компьютеров : {0}" -f (Get-ScanTypeName))
    Write-Host ("Область (OU)    : {0}" -f $(if ($script:ScanOU) { $script:ScanOU } else { "весь домен $Domain" }))
    Write-Host 'Прервать опрос можно клавишей Esc.' -ForegroundColor DarkGray
    Write-Host ''
    $act = 'Сканирование установленных программ'
    $sw  = [Diagnostics.Stopwatch]::StartNew()

    # ---- Шаг 1: список компьютеров из AD
    Write-Progress -Id 1 -Activity $act -Status 'Шаг 1 из 3: получаю список компьютеров из AD...' -PercentComplete 0
    try { $ad = @(Get-ScanTargets | Sort-Object Name) }
    catch {
        Write-Progress -Id 1 -Activity $act -Completed
        Write-Host "Ошибка AD: $($_.Exception.Message)" -ForegroundColor Red
        Wait-Key; return
    }
    if ($ad.Count -eq 0) {
        Write-Progress -Id 1 -Activity $act -Completed
        Write-Host 'Подходящих компьютеров не найдено.' -ForegroundColor Yellow
        Wait-Key; return
    }
    Write-Host "Найдено компьютеров: $($ad.Count)" -ForegroundColor Cyan

    # прежние данные заменяются только для сканируемых компьютеров
    $newSet = @{}; foreach ($c in $ad) { $newSet[$c.Name] = $true }
    $script:Computers = @($script:Computers | Where-Object { -not $newSet.ContainsKey($_.Name) })
    $script:Items     = @($script:Items     | Where-Object { -not $newSet.ContainsKey($_.Computer) })

    $new = @(foreach ($c in $ad) {
        [pscustomobject]@{
            Name      = $c.Name
            OS        = $c.OperatingSystem
            Type      = $(if ($c.OperatingSystem -like '*Server*') { 'Server' } else { 'Client' })
            Online    = $false
            Connected = $false
            Error     = ''
        }
    })
    $script:Computers = @($script:Computers) + $new
    Update-CompMap

    # ---- Шаг 2: проверка доступности WinRM
    $names = @($new | Select-Object -ExpandProperty Name)
    $winrm = @{}
    $chunk = 100
    for ($i = 0; $i -lt $names.Count; $i += $chunk) {
        $end  = [math]::Min($i + $chunk, $names.Count)
        $part = @($names[$i..($end - 1)])
        $r = Test-PortAsync -Names $part -Port 5985
        foreach ($k in $r.Keys) { $winrm[$k] = $r[$k] }
        Write-Progress -Id 1 -Activity $act `
            -Status ("Шаг 2 из 3: проверка доступности WinRM: {0} из {1}" -f $end, $names.Count) `
            -PercentComplete ([int](100 * $end / $names.Count))
    }
    foreach ($c in $new) {
        $c.Online = [bool]$winrm[$c.Name]
        $c.Connected = $c.Online
        if (-not $c.Online) { $c.Error = 'Недоступен (выключен или закрыт порт 5985 / WinRM)' }
    }

    # ---- Шаг 3: опрос
    $targets   = @($new | Where-Object { $_.Online } | Select-Object -ExpandProperty Name)
    $cancelled = $false
    $okCount   = 0
    $itemCount = 0
    if ($targets.Count -gt 0) {
        $opt = New-PSSessionOption -OpenTimeout 20000 -OperationTimeout 300000
        $job = Invoke-Command -ComputerName $targets -ScriptBlock $script:RemoteBlock `
               -ArgumentList 'Collect', $null, $null -SessionOption $opt -ThrottleLimit 32 -AsJob
        $cancelled = Wait-JobProgress -Job $job -Total $targets.Count -Activity $act -StepText 'Шаг 3 из 3: опрошено' -Stopwatch $sw
        $raw = @(Receive-Job $job -ErrorAction SilentlyContinue)

        foreach ($ch in $job.ChildJobs) {
            $c = $script:CompMap[[string]$ch.Location]
            if (-not $c) { continue }
            if ($ch.State -eq 'Completed') { $c.Connected = $true; $c.Error = ''; $okCount++ }
            else { $c.Connected = $false; $c.Error = Get-ChildReason $ch }
        }
        Remove-Job $job -Force -ErrorAction SilentlyContinue

        $list = foreach ($x in $raw) {
            $c = $script:CompMap[[string]$x.Computer]
            if (-not $c) { continue }
            $isMachine = ($x.Source -eq 'Appx') -or ($x.Hive -eq 'HKLM')
            [pscustomobject]@{
                Computer    = $c.Name
                Type        = $c.Type
                Source      = $x.Source
                SourceName  = Get-SourceName $x.Source
                KindName    = $(if ($isMachine) { 'Система' } else { 'Пользователь' })
                Scope       = $x.Scope
                Name        = $x.Name
                Version     = $x.Version
                Publisher   = $x.Publisher
                InstallDate = $x.InstallDate
                SizeMB      = $x.SizeMB
                Uninstall   = $x.Uninstall
                Quiet       = $x.Quiet
                IsMsi       = [bool]$x.IsMsi
                IsSystem    = [bool]$x.IsSystem
                Hive        = $x.Hive
                Location    = $x.Location
                KeyName     = $x.KeyName
                IdKey       = ('{0}|{1}|{2}|{3}' -f $c.Name, $x.Source, $x.Hive, $x.KeyName)
                Key         = ('{0}|{1}' -f $(if ($x.Source -eq 'Appx') { 'Appx' } else { 'Reg' }), $x.Name)
            }
        }
        $list = @($list)
        $itemCount = $list.Count
        $script:Items = @($script:Items) + $list
    }

    Write-Progress -Id 1 -Activity $act -Completed
    $script:LastScan = Get-Date
    $failed = $new.Count - $okCount
    Write-Log ("Скан [{0}; {1}]: компьютеров {2}, опрошено {3}, ошибок/недоступно {4}, записей {5}{6}" -f
        (Get-ScanTypeName), $(if ($script:ScanOU) { $script:ScanOU } else { 'весь домен' }),
        $new.Count, $okCount, $failed, $itemCount, $(if ($cancelled) { ' (прервано)' } else { '' }))
    Write-Host ''
    Write-Host ("Готово за {0:mm\:ss}{1}. Компьютеров: {2}, опрошено: {3}, недоступно/ошибок: {4}, записей: {5}." -f
        $sw.Elapsed, $(if ($cancelled) { ' (прервано пользователем)' } else { '' }), $new.Count, $okCount, $failed, $itemCount) -ForegroundColor Green
    Write-Host 'Список проблемных компьютеров — в разделе «Недоступные».' -ForegroundColor DarkGray
    Wait-Key
}

# --------------------------------- Просмотр ---------------------------------

function Show-Items {
    param([string]$Type, [string]$Title)
    Write-Header $Title
    $comps = @($script:Computers | Where-Object { $_.Type -eq $Type })
    $ok    = @($comps | Where-Object { $_.Connected })
    Write-Host ("Компьютеров: {0}, опрошено: {1}, недоступно: {2}" -f $comps.Count, $ok.Count, ($comps.Count - $ok.Count))
    $items = @(Get-VisibleItems $Type | Sort-Object Computer, Name, Version)
    Write-Host ("Программ: {0}  (системные компоненты: {1}, Store-приложения: {2})" -f $items.Count,
                $(if ($script:ShowSystem) { 'показаны' } else { 'скрыты' }), $(if ($script:ShowAppx) { 'показаны' } else { 'скрыты' }))
    Write-Host ''
    if ($items.Count -eq 0) { Write-Host 'Нет данных. Запустите сканирование (пункт 1).' -ForegroundColor Yellow; Wait-Key; return }

    $fmt = $items | Format-Table -GroupBy Computer -Property `
        @{n='Программа'; e={ Limit-Text $_.Name 42 }},
        @{n='Версия'; e={ Limit-Text $_.Version 16 }},
        @{n='Издатель'; e={ Limit-Text $_.Publisher 22 }},
        @{n='МБ'; e={ $_.SizeMB }},
        @{n='Установлена'; e={ $_.InstallDate }},
        @{n='Источник'; e={ $_.SourceName }},
        @{n='Кому'; e={ Limit-Text $_.Scope 16 }} -AutoSize -Wrap
    try { $fmt | Out-Host -Paging } catch { $fmt | Out-Host }
    Wait-Key
}

function Show-Summary {
    Write-Header 'Сводка: какая программа на скольких компьютерах'
    $f = Read-Host 'Фильтр по названию или издателю (Enter — все)'
    $groups = Get-ItemGroups $f
    if ($groups.Count -eq 0) { Write-Host 'Ничего не найдено.' -ForegroundColor Yellow; Wait-Key; return }
    Show-GroupTable $groups
    Wait-Key
}

function Show-Unreachable {
    Write-Header 'Компьютеры, с которых не удалось получить данные'
    $bad = @($script:Computers | Where-Object { -not $_.Connected })
    if ($bad.Count -eq 0) { Write-Host 'Все компьютеры опрошены.' -ForegroundColor Green }
    else {
        $bad | Sort-Object Type, Name |
            Format-Table Name, Type, @{n='ОС';e={ Limit-Text $_.OS 28 }}, @{n='Причина';e={ Limit-Text $_.Error 60 }} -AutoSize |
            Out-Host
    }
    Wait-Key
}

# ---------------------------------- Удаление --------------------------------

# Есть ли для записи способ тихого удаления (без дополнительных аргументов)
function Test-HasSilent {
    param($r)
    if ($r.Source -eq 'Appx') { return $true }
    if ($r.IsMsi -and $r.KeyName -match '^\{[0-9A-Fa-f]{8}-([0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}\}$') { return $true }
    if ($r.Quiet) { return $true }
    $u = [string]$r.Uninstall
    if ($u -match '(?i)msiexec(\.exe)?"?\s+/[IX]\s*\{') { return $true }
    if ($u -match '(?i)unins\d{3}\.exe') { return $true }
    $false
}

function Invoke-Uninstall {
    param($Records)
    $Records = @($Records)
    if ($Records.Count -eq 0) { Write-Host 'Нечего удалять.' -ForegroundColor Yellow; return }

    Write-Host ''
    Write-Host 'Будут УДАЛЕНЫ следующие программы:' -ForegroundColor Red
    $Records | Sort-Object Computer, Name |
        Format-Table Computer, Type, @{n='Программа';e={ Limit-Text $_.Name 44 }}, @{n='Версия';e={ Limit-Text $_.Version 16 }}, SourceName -AutoSize |
        Out-Host
    if ($Records | Where-Object { $_.IsSystem }) {
        Write-Host 'ВНИМАНИЕ: среди выбранного есть системные компоненты/обновления/служебные пакеты.' -ForegroundColor Red
    }
    if ($Records | Where-Object { $_.Source -eq 'User' }) {
        Write-Host 'Внимание: программы, установленные для пользователя, могут не удаляться в контексте администратора.' -ForegroundColor Yellow
    }

    $extra = ''
    $noSilent = @($Records | Where-Object { -not (Test-HasSilent $_) })
    if ($noSilent.Count -gt 0) {
        Write-Host ("Для {0} программ нет известного тихого режима удаления." -f $noSilent.Count) -ForegroundColor Yellow
        $extra = (Read-Host 'Доп. аргументы для них (например /S или /quiet). Enter — эти программы пропустить').Trim()
        if (-not $extra) { $Records = @($Records | Where-Object { Test-HasSilent $_ }) }
    }
    if ($Records.Count -eq 0) { Write-Host 'Нечего удалять.' -ForegroundColor Yellow; return }

    $deprov = $false
    if (@($Records | Where-Object { $_.Source -eq 'Appx' }).Count -gt 0) {
        Write-Host 'Также удалить приложения Store из образа системы (чтобы не появлялись у новых пользователей)? [Y — да, другая клавиша — нет] ' -NoNewline
        $dk = (Read-Key).ToUpper(); Write-Host ''
        $deprov = ($dk -in 'Y', 'Н')
    }

    $cnt = @($Records | Select-Object -ExpandProperty Computer -Unique).Count
    $ans = Read-Host ("Удаление необратимо. Программ: {0}, компьютеров: {1}. Введите YES для подтверждения" -f $Records.Count, $cnt)
    if ($ans -cne 'YES') { Write-Host 'Отменено.' -ForegroundColor Yellow; return }

    $targets = @($Records | Select-Object -ExpandProperty Computer -Unique)
    $slim = @($Records | Select-Object IdKey, Computer, Source, KeyName, Name, IsMsi, Uninstall, Quiet)
    $opts = @{ TimeoutSec = $UninstallTimeoutSec; ExtraArgs = $extra; Deprovision = $deprov }
    $act  = 'Удаление программ'
    $sw   = [Diagnostics.Stopwatch]::StartNew()
    Write-Host 'Выполняю на удалённых компьютерах (Esc — прервать; уже запущенные удаления на ПК продолжатся)...' -ForegroundColor Cyan
    $sopt = New-PSSessionOption -OpenTimeout 20000 -OperationTimeout 3600000
    $job  = Invoke-Command -ComputerName $targets -ScriptBlock $script:RemoteBlock `
            -ArgumentList 'Uninstall', $slim, $opts -SessionOption $sopt -ThrottleLimit 32 -AsJob
    $cancelled = Wait-JobProgress -Job $job -Total $targets.Count -Activity $act -StepText 'Удалено на компьютерах' -Stopwatch $sw
    $res = @(Receive-Job $job -ErrorAction SilentlyContinue)
    $connErr = @{}
    foreach ($ch in $job.ChildJobs) {
        if ($ch.State -ne 'Completed') { $connErr[[string]$ch.Location] = Get-ChildReason $ch }
    }
    Remove-Job $job -Force -ErrorAction SilentlyContinue
    Write-Progress -Id 1 -Activity $act -Completed

    $byId = @{}
    foreach ($r in $res) { $byId[[string]$r.IdKey] = $r }

    $done = @(); $fail = 0
    foreach ($rec in $Records) {
        $r = $byId[$rec.IdKey]
        $label = '{0}: {1} {2}' -f $rec.Computer, $rec.Name, $rec.Version
        if ($r -and $r.Ok) {
            $note = if ($r.Message) { " ($($r.Message))" } else { '' }
            Write-Host "  [OK]  $label$note" -ForegroundColor Green
            Write-Log ("УДАЛЕНО {0}{1} | {2}" -f $label, $note, $(if ($rec.Quiet) { $rec.Quiet } else { $rec.Uninstall }))
            $done += $rec
        } else {
            $fail++
            $msg = if ($r) { $r.Message } elseif ($connErr.ContainsKey($rec.Computer)) { $connErr[$rec.Computer] } else { 'нет ответа' }
            Write-Host "  [ERR] $label — $msg" -ForegroundColor Red
            Write-Log ("ОШИБКА удаления {0} — {1}" -f $label, $msg)
        }
    }
    if ($done.Count -gt 0) { $script:Items = @($script:Items | Where-Object { $done -notcontains $_ }) }
    Write-Host ''
    Write-Host ("Готово за {0:mm\:ss}{1}. Успешно: {2}, ошибок: {3}. Лог: {4}" -f
        $sw.Elapsed, $(if ($cancelled) { ' (прервано)' } else { '' }), $done.Count, $fail, $LogPath) -ForegroundColor Cyan
}

function Test-GridView {
    if (-not (Get-Command Out-GridView -ErrorAction SilentlyContinue)) {
        Write-Host 'Out-GridView недоступен (Server Core или нет компонента ISE/GraphicalTools).' -ForegroundColor Red
        return $false
    }
    $true
}

function Invoke-ByName {
    Write-Header 'Удаление программы по имени'
    $f = Read-Host 'Фильтр по названию или издателю (Enter — все)'
    $groups = Get-ItemGroups $f
    if ($groups.Count -eq 0) { Write-Host 'Ничего не найдено.' -ForegroundColor Yellow; Wait-Key; return }
    Show-GroupTable $groups

    $sel = Read-Host 'Номера программ через запятую (Enter — отмена)'
    if (-not $sel) { return }
    $idx = @($sel -split '[,\s]+' | Where-Object { $_ -match '^\d+$' } | ForEach-Object { [int]$_ })
    $records = @()
    foreach ($n in $idx) {
        if ($n -ge 1 -and $n -le $groups.Count) { $records += @($groups[$n - 1].Group) }
    }
    if ($records.Count -eq 0) { Write-Host 'Неверный выбор.' -ForegroundColor Yellow; Wait-Key; return }

    $ver = (Read-Host 'Только версия (можно маску, например 11.*; Enter — любая)').Trim()
    if ($ver) { $records = @($records | Where-Object { $_.Version -like $ver }) }
    if ($records.Count -eq 0) { Write-Host 'Нет записей с такой версией.' -ForegroundColor Yellow; Wait-Key; return }

    Write-Host ''
    Write-Host 'Область удаления:' -ForegroundColor Cyan
    Write-Host '  [A] все компьютеры, где есть программа'
    Write-Host '  [C] только компьютеры пользователей'
    Write-Host '  [S] только серверы и ВМ'
    Write-Host '  [G] выбрать компьютеры вручную (окно Out-GridView)'
    Write-Host '  [любая другая] отмена'
    $k = (Read-Key).ToUpper()
    switch ($k) {
        { $_ -in 'A','Ф' } { $target = $records }
        { $_ -in 'C','С' } { $target = @($records | Where-Object { $_.Type -eq 'Client' }) }
        { $_ -in 'S','Ы' } { $target = @($records | Where-Object { $_.Type -eq 'Server' }) }
        { $_ -in 'G','П' } {
            if (-not (Test-GridView)) { Wait-Key; return }
            $picked = @($records | Sort-Object Computer | Select-Object Computer, Type, Name, Version, SourceName, IdKey |
                        Out-GridView -PassThru -Title 'Выделите строки (Ctrl/Shift), затем OK')
            $ids = @{}; foreach ($p in $picked) { $ids[$p.IdKey] = $true }
            $target = @($records | Where-Object { $ids.ContainsKey($_.IdKey) })
        }
        default { Write-Host 'Отменено.' -ForegroundColor Yellow; Wait-Key; return }
    }
    Invoke-Uninstall -Records $target
    Wait-Key
}

function Invoke-ByGrid {
    Write-Header 'Удаление выбранных строк (компьютер + программа)'
    if (-not (Test-GridView)) { Wait-Key; return }
    $items = @(Get-VisibleItems | Sort-Object Type, Computer, Name)
    if ($items.Count -eq 0) { Write-Host 'Нет данных. Запустите сканирование.' -ForegroundColor Yellow; Wait-Key; return }
    Write-Host 'Откроется окно: отметьте строки (Ctrl/Shift), нажмите OK.' -ForegroundColor Cyan
    $picked = @($items | Select-Object Computer, Type, Name, Version, Publisher, SizeMB, InstallDate, SourceName, Scope, IdKey |
                Out-GridView -PassThru -Title 'Выберите программы для удаления')
    if ($picked.Count -eq 0) { return }
    $ids = @{}; foreach ($p in $picked) { $ids[$p.IdKey] = $true }
    Invoke-Uninstall -Records @($items | Where-Object { $ids.ContainsKey($_.IdKey) })
    Wait-Key
}

# --------------------------------- Экспорт ----------------------------------

function Export-Data {
    Write-Header 'Экспорт в CSV'
    if ($script:Items.Count -eq 0) { Write-Host 'Нет данных.' -ForegroundColor Yellow; Wait-Key; return }
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $f1 = Join-Path $LogBase "Software_$stamp.csv"
    $f2 = Join-Path $LogBase "SoftwareComputers_$stamp.csv"
    $script:Items | Select-Object Computer, Type, Name, Version, Publisher, InstallDate, SizeMB, SourceName, KindName, Scope, IsSystem, Uninstall |
        Export-Csv $f1 -NoTypeInformation -Encoding UTF8
    $script:Computers | Select-Object Name, Type, OS, Online, Connected, Error |
        Export-Csv $f2 -NoTypeInformation -Encoding UTF8
    Write-Host "Сохранено:`n  $f1`n  $f2" -ForegroundColor Green
    Wait-Key
}

# ----------------------------------- Меню -----------------------------------

function Show-MainMenu {
    Write-Header "Установленные программы домена $Domain"
    $cl = @($script:Computers | Where-Object { $_.Type -eq 'Client' })
    $sv = @($script:Computers | Where-Object { $_.Type -eq 'Server' })
    $on = @($script:Computers | Where-Object { $_.Connected })
    if ($script:Computers.Count -eq 0) {
        Write-Host '  Данных пока нет. Задайте параметры (пункты 2 и 3) и запустите сканирование (пункт 1).' -ForegroundColor Yellow
    } else {
        Write-Host ("  Просканировано компьютеров: {0} (клиенты: {1}, серверы/ВМ: {2}), опрошено успешно: {3}" -f
                    $script:Computers.Count, $cl.Count, $sv.Count, $on.Count)
        Write-Host ("  Записей о программах: {0} (с учётом фильтров: {1})" -f $script:Items.Count, @(Get-VisibleItems).Count)
        if ($script:LastScan) { Write-Host ("  Последнее сканирование: {0:dd.MM.yyyy HH:mm:ss}" -f $script:LastScan) }
    }
    Write-Host ''
    Write-Host '  Сканирование' -ForegroundColor Cyan
    Write-Host '   1) Запустить сканирование с текущими параметрами' -ForegroundColor Green
    Write-Host ("   2) Тип компьютеров: [{0}]  (нажмите, чтобы переключить)" -f (Get-ScanTypeName))
    Write-Host ("   3) Область (OU): [{0}]" -f $(if ($script:ScanOU) { $script:ScanOU } else { "весь домен $Domain" }))
    Write-Host '   C) Очистить результаты'
    Write-Host ''
    Write-Host '  Просмотр' -ForegroundColor Cyan
    Write-Host '   4) Программы: компьютеры пользователей'
    Write-Host '   5) Программы: серверы и виртуальные машины'
    Write-Host '   6) Сводка (программа → на скольких ПК)'
    Write-Host '   U) Недоступные компьютеры'
    Write-Host ''
    Write-Host '  Удаление' -ForegroundColor Cyan
    Write-Host '   7) Удалить программу по имени (все / выборочно)' -ForegroundColor Red
    Write-Host '   8) Выбрать строки (Out-GridView) и удалить' -ForegroundColor Red
    Write-Host ''
    Write-Host '  Прочее' -ForegroundColor Cyan
    Write-Host ("   S) Системные компоненты и обновления: {0}" -f $(if ($script:ShowSystem) { 'показаны' } else { 'скрыты' }))
    Write-Host ("   A) Приложения Microsoft Store: {0}" -f $(if ($script:ShowAppx) { 'показаны' } else { 'скрыты' }))
    Write-Host '   E) Экспорт в CSV'
    Write-Host '   0) Выход'
    Write-Host ''
    Write-Host '  Выберите пункт: ' -NoNewline
}

# Программа сначала показывает меню, сканирование запускается только по пункту 1.
while ($true) {
    Show-MainMenu
    $key = (Read-Key).ToUpper()
    switch ($key) {
        '1' { Invoke-Scan }
        '2' { Switch-ScanType }
        '3' { Select-ScanOU }
        '4' { Show-Items -Type 'Client' -Title 'Программы: компьютеры пользователей' }
        '5' { Show-Items -Type 'Server' -Title 'Программы: серверы и виртуальные машины' }
        '6' { Show-Summary }
        '7' { Invoke-ByName }
        '8' { Invoke-ByGrid }
        { $_ -in 'U','Г' } { Show-Unreachable }
        { $_ -in 'S','Ы' } { $script:ShowSystem = -not $script:ShowSystem }
        { $_ -in 'A','Ф' } { $script:ShowAppx   = -not $script:ShowAppx }
        { $_ -in 'E','У' } { Export-Data }
        { $_ -in 'C','С' } { Clear-Results }
        '0' { Clear-Host; return }
    }
}
