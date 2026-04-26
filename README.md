G.A.L - Gamers As Legions
A comprehensive Windows optimization utility for gamers and power users.

Overview
G.A.L (Gamers As Legions) is an all-in-one system optimization tool focused on cleanup, performance tuning, game-oriented process management, power plan control, real-time monitoring, and utility shortcuts for advanced Windows users. The current app exposes major functions through tabs for System Optimizer, Game Optimizer, Performance Monitor, and Help, plus a Tools menu for advanced actions such as DNS restore, polling-rate actions, debug console access, restore actions, and reservable-bandwidth controls .

Key Features
System Optimizer
Clean RAM cache and review high-memory processes.

Clean Windows Temp, Prefetch, thumbnails, browser cache, Delivery Optimization files, and temporary folders.

Flush DNS cache and set Cloudflare DNS.

Restore original DNS settings from backup.

Clean Windows Update cache, Defender scan files, Windows upgrade logs, and system recovery logs.

Disable Telemetry, Cortana, and Game Bar.

Optimize network adapter settings.

Supports Run Preferred and Run All workflows in the System Optimizer tab .

Game Optimizer
Manage power plans, including refresh, activate, delete, create, and restore-default actions.

Add programs and directories for monitoring.

Start and stop monitoring for optimization workflows.

Apply manual process optimization with affinity and priority controls.

Designed for game-focused process and power-management usage .

Performance Monitor
Monitor live CPU, memory, disk, and network activity.

Review performance text output inside the app.

Use built-in logging and utility actions for troubleshooting and repeat testing .

Advanced Tools Menu
The Tools menu currently includes:

Clear Log

Save Log

Advanced System Info

Set Window Size

Debug Console

Disable Limit Reservable Bandwidth

Revert LRB

Restore Original DNS

Optimize Polling Rate

Revert Polling Rate

Priority Bypasser

Restore Standard Windows Settings

Trickster

Exit

Debug and Logging
Debug Console includes Refresh and Clear actions.

The Clear action clears both debug.log and debug_log.txt for a clean testing session.

Cleanup paths now summarize deleted vs. skipped locked/protected items instead of flooding the UI with repetitive file-lock errors .

Safety Features
Safe Mode limits changes to reduce risk during testing or cautious use.

DNS changes support backup and restore behavior.

Cleanup and optimizer actions log status output for troubleshooting.

Cleanup flow warns users that open programs may need to be closed for best results .

Limit Reservable Bandwidth
G.A.L now includes a dedicated Tools-menu action for Disable Limit Reservable Bandwidth and a matching Revert LRB option. The disable action creates or verifies the registry key HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Psched, then creates or updates the NonBestEffortLimit DWORD and sets it to 0. The revert action removes NonBestEffortLimit, allowing Windows to fall back to default behavior .

Installation
Install Python 3.7 or newer on Windows.

Run the application with Administrator privileges for full functionality.

Allow the application to install required dependencies if prompted.

Launch the latest script build rather than an older local copy if you want the newest Tools-menu options and logging improvements .

System Requirements
Windows 10 or Windows 11.

Python 3.7 or higher.

Administrator privileges for full functionality.

4 GB RAM minimum, 8 GB or more recommended.

Enough free disk space for temporary cleanup and logs.

Usage
System Optimization
Open the System Optimizer tab.

Select desired actions with the checkboxes.

Use Run Preferred for checked actions or Run All for the full batch.

Review the status box for deleted/skipped summaries and operation results .

Game Optimization
Open the Game Optimizer tab.

Configure power plans, monitored programs, and process options.

Start monitoring or apply manual process optimization as needed .

Performance Monitoring
Open the Performance Monitor tab.

Start monitoring to view live system statistics.

Use Advanced System Info from the Tools menu for extended hardware and software information .

Tools Menu Usage
Use the Tools menu for utility actions that do not fit cleanly inside the main tabs, including:

Debug Console access and clearing logs.

DNS restore.

Polling-rate actions.

Priority bypass tools.

Standard Windows settings restore.

Disable Limit Reservable Bandwidth and Revert LRB .

Notes
Some cleanup targets may still be skipped if Windows or another application is actively locking them.

Force-closing applications can cause unsaved work to be lost, so users should save work before running cleanup flows that may require open programs to close.

Registry and power-related actions should be used carefully and ideally with a system restore point or backup in place .

Legal
This software is provided as-is without warranty. Use at your own risk. Always create backups before making major system changes.

Version
README updated for current feature set reflected in the latest session build.

Current referenced build: G.A.L_V1.2_updated.pyw
