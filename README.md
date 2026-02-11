# MSRansom / MSiRig Ransomware

A repository dedicated to the analysis and recovery steps for the **MSiRiG** and **Girism** ransomware strains.

---

## 🛠 Recovery: Re-enabling Task Manager
If the ransomware has disabled your Task Manager, you can manually restore access by modifying the Windows Registry.

**Registry Path:** `HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System`  
**Value Name:** `DisableTaskMgr`  
**Action:** Set to `0` to re-enable.

### Automated PowerShell Fix
Run the following command in a PowerShell window to immediately re-enable access:

```powershell
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableTaskMgr" -Value 0
```

Important Notices

DO NOT EDIT THIS REPOSITORY
This project is strictly connected to the MSiRiG and Girism ecosystems. Unauthorized changes or edits may disrupt ongoing research, connectivity, or data integrity.

Related Resources
Simulation Tool: If you need a fake ransomware executable that displays a dark screen with a timer for demonstration or testing purposes, use: v3gard/FakeRansomware
