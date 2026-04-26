#!/usr/bin/env python3
from __future__ import annotations

import ctypes
import importlib
import json
import logging
import os
import platform
import queue
import re
import shutil
import subprocess
import sys
import threading
import time
import webbrowser
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

WINDOWS = os.name == "nt"
APP_TITLE = "Tools"
APP_VERSION = "1.3.0"
BASE_DIR = Path(__file__).resolve().parent
LOG_FILE = BASE_DIR / "debug.log"
DEBUG_LOG_FILE = BASE_DIR / "debug_log.txt"
DNS_BACKUP_FILE = BASE_DIR / "dns_backup.json"
SETTINGS_BACKUP_FILE = BASE_DIR / "tool_settings_backup.json"
CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

logging.basicConfig(
    filename=str(LOG_FILE),
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("tools")
logger.info("Script started")
DEBUG_LOG_FILE.touch(exist_ok=True)

REQUIRED_PACKAGES = {
    "psutil": "psutil",
    "customtkinter": "customtkinter",
    "GPUtil": "gputil",
    "speedtest": "speedtest-cli",
    "wmi": "wmi",
}


def ensure_dependencies() -> None:
    if not WINDOWS:
        return
    if sys.executable.lower().endswith("pythonw.exe"):
        return
    missing: list[str] = []
    for module_name, package_name in REQUIRED_PACKAGES.items():
        try:
            importlib.import_module(module_name)
        except ImportError:
            missing.append(package_name)
    if missing:
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", *missing])
        except Exception as exc:
            logger.error("Dependency install failed: %s", exc)


ensure_dependencies()

import psutil  # type: ignore
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
import customtkinter as ctk  # type: ignore
try:
    import GPUtil  # type: ignore
except Exception:
    GPUtil = None
try:
    import speedtest  # type: ignore
except Exception:
    speedtest = None
try:
    import wmi  # type: ignore
except Exception:
    wmi = None
if WINDOWS:
    import winreg  # type: ignore
else:
    winreg = None

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

if WINDOWS:
    try:
        ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
    except Exception:
        pass

monitoring_event = threading.Event()
monitoring_thread: threading.Thread | None = None
performance_monitoring = False
performance_thread: threading.Thread | None = None
safe_mode = False
program_list: list[str] = []
detected_processes: set[str] = set()
update_queue: queue.Queue[str] = queue.Queue()
app: "App | None" = None

priority_levels = [
    psutil.BELOW_NORMAL_PRIORITY_CLASS,
    psutil.IDLE_PRIORITY_CLASS,
    psutil.NORMAL_PRIORITY_CLASS,
    psutil.HIGH_PRIORITY_CLASS,
    psutil.REALTIME_PRIORITY_CLASS,
]
priority_names = ["Below Normal", "Idle", "Normal", "High", "Realtime"]

REGISTRY_BACKUPS: dict[str, tuple[str, str | int | None, int | None]] = {
    "telemetry": (r"SOFTWARE\Policies\Microsoft\Windows\DataCollection", "AllowTelemetry", None, None),
    "cortana": (r"SOFTWARE\Policies\Microsoft\Windows\Windows Search", "AllowCortana", None, None),
    "gamebar": (r"SOFTWARE\Policies\Microsoft\Windows\GameDVR", "AllowGameDVR", None, None),
    "appearance_visualfx": (r"Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects", "VisualFXSetting", None, None),
}


@dataclass
class PowerPlan:
    guid: str
    name: str
    active: bool = False


def write_debug_log(message: str) -> None:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with DEBUG_LOG_FILE.open("a", encoding="utf-8") as fh:
        fh.write(f"[{timestamp}] {message}\n")


def run_command(args: list[str] | str, *, shell: bool = False, timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(
        args,
        shell=shell,
        capture_output=True,
        text=True,
        timeout=timeout,
        creationflags=CREATE_NO_WINDOW if WINDOWS else 0,
    )


def run_powershell(command: str, timeout: int = 90) -> subprocess.CompletedProcess:
    return run_command(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command], timeout=timeout)


def is_admin() -> bool:
    if not WINDOWS:
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def elevate_privileges() -> None:
    if not WINDOWS or is_admin():
        return
    params = subprocess.list2cmdline(sys.argv)
    try:
        result = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
        if result <= 32:
            try:
                messagebox.showerror("Error", f"Failed to elevate privileges. Code: {result}")
            except Exception:
                pass
        raise SystemExit
    except Exception as exc:
        logger.error("Elevation failed: %s", exc)


def update_text_box(message: str) -> None:
    try:
        write_debug_log(message)
    except Exception:
        pass
    update_queue.put(message)
    if app is not None:
        app.root.after(50, process_update_queue)

def clear_debug_logs() -> None:
    for path in (DEBUG_LOG_FILE, LOG_FILE):
        try:
            path.write_text("", encoding="utf-8")
        except Exception:
            pass
    if app is not None:
        app.show_debug_message("Debug logs cleared.")




def apply_limit_reservable_bandwidth(enabled: bool, percentage: int = 0) -> None:
    if not WINDOWS:
        update_text_box("Limit reservable bandwidth is supported only on Windows.")
        return
    try:
        reg_key = r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched"
        create_key = subprocess.run(
            f'reg add "{reg_key}" /f',
            shell=True, capture_output=True, text=True
        )
        if create_key.returncode != 0:
            raise RuntimeError(create_key.stderr.strip() or create_key.stdout.strip() or "Failed to create or verify Psched key.")

        if enabled:
            result = subprocess.run(
                f'reg add "{reg_key}" /v NonBestEffortLimit /t REG_DWORD /d {int(percentage)} /f',
                shell=True, capture_output=True, text=True
            )
            if result.returncode != 0:
                raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "Failed to set NonBestEffortLimit.")
            update_text_box(f"Disable Limit Reservable Bandwidth applied. Created/verified Psched and set NonBestEffortLimit to {int(percentage)}.")
        else:
            result = subprocess.run(
                f'reg delete "{reg_key}" /v NonBestEffortLimit /f',
                shell=True, capture_output=True, text=True
            )
            if result.returncode == 0:
                update_text_box("Revert LRB completed. Removed NonBestEffortLimit from Psched; Windows will use default behavior.")
            else:
                update_text_box("Revert LRB completed. NonBestEffortLimit was already absent; Psched was created/verified.")
    except Exception as exc:
        update_text_box(f"Failed to change reservable bandwidth: {exc}")

def terminate_target_processes(process_names: list[str] | None = None) -> tuple[int, int]:
    names = {n.lower() for n in (process_names or []) if n}
    if not names:
        names = {"brave.exe", "msedge.exe", "chrome.exe", "code.exe", "discord.exe", "steam.exe", "explorer.exe"}
    killed = 0
    skipped = 0
    for proc in psutil.process_iter(["pid", "name"]):
        name = (proc.info.get("name") or "").lower()
        if name in names:
            try:
                psutil.Process(proc.info["pid"]).terminate()
                killed += 1
            except Exception:
                skipped += 1
    return killed, skipped


def process_update_queue() -> None:
    if app is None:
        return
    while not update_queue.empty():
        message = update_queue.get_nowait()
        app.text_box.configure(state="normal")
        app.text_box.delete("1.0", "end")
        app.text_box.insert("1.0", message)
        app.text_box.configure(state="disabled")


def save_json(path: Path, data: dict[str, Any]) -> None:
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def backup_registry_value(name: str, hive: Any, path: str, value_name: str) -> None:
    if not WINDOWS or winreg is None:
        return
    data = load_json(SETTINGS_BACKUP_FILE)
    registry = data.setdefault("registry", {})
    if name in registry:
        return
    try:
        key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
        try:
            value, reg_type = winreg.QueryValueEx(key, value_name)
            registry[name] = {"path": path, "value_name": value_name, "value": value, "type": reg_type, "exists": True, "hive": "HKLM" if hive == winreg.HKEY_LOCAL_MACHINE else "HKCU"}
        finally:
            winreg.CloseKey(key)
    except FileNotFoundError:
        registry[name] = {"path": path, "value_name": value_name, "value": None, "type": None, "exists": False, "hive": "HKLM" if hive == winreg.HKEY_LOCAL_MACHINE else "HKCU"}
    save_json(SETTINGS_BACKUP_FILE, data)


def restore_backed_registry_value(name: str) -> bool:
    if not WINDOWS or winreg is None:
        return False
    data = load_json(SETTINGS_BACKUP_FILE)
    registry = data.get("registry", {})
    if name not in registry:
        return False
    item = registry[name]
    hive = winreg.HKEY_LOCAL_MACHINE if item.get("hive") == "HKLM" else winreg.HKEY_CURRENT_USER
    key = winreg.CreateKey(hive, item["path"])
    try:
        if item.get("exists"):
            winreg.SetValueEx(key, item["value_name"], 0, item["type"], item.get("value"))
        else:
            try:
                winreg.DeleteValue(key, item["value_name"])
            except FileNotFoundError:
                pass
    finally:
        winreg.CloseKey(key)
    return True


def toggle_safe_mode() -> None:
    global safe_mode
    safe_mode = not safe_mode
    status = "ENABLED" if safe_mode else "DISABLED"
    if app is not None:
        app.safe_mode_label.configure(text=f"Safe Mode: {status}", text_color="#00ff00" if safe_mode else "#ff0000")
    if safe_mode:
        messagebox.showwarning(
            "Safe Mode Enabled",
            "Safe Mode is now ENABLED.\n\n"
            "The following optimizations will be skipped:\n"
            "• DNS changes\n• Registry modifications\n• Power plan changes\n• Service modifications\n\n"
            "Only cleaning actions will be performed.",
        )
    else:
        messagebox.showinfo("Safe Mode Disabled", "All optimizations will run normally.")


def is_safe_mode_operation(operation_type: str) -> bool:
    if not safe_mode:
        return False
    restricted = {"dns", "registry", "power", "service", "network", "telemetry", "cortana", "gamebar", "defender", "animations", "polling", "appearance"}
    lowered = operation_type.lower()
    return any(item in lowered for item in restricted)


def force_delete_folder_contents(folder_path: str | Path) -> tuple[int, int]:
    folder = Path(folder_path)
    if not folder.exists():
        return 0
    deleted = 0
    skipped = 0
    for entry in folder.iterdir():
        try:
            if entry.is_symlink():
                entry.unlink(missing_ok=True)
            elif entry.is_file():
                try:
                    os.chmod(entry, 0o666)
                except Exception:
                    pass
                entry.unlink(missing_ok=True)
            elif entry.is_dir():
                shutil.rmtree(entry, ignore_errors=False)
            deleted += 1
        except (PermissionError, OSError) as exc:
            code = getattr(exc, 'winerror', None) or getattr(exc, 'errno', None)
            if code in (5, 32):
                skipped += 1
                write_debug_log(f"Skipped locked/protected item: {entry}")
            else:
                skipped += 1
                logger.error("Delete failed for %s: %s", entry, exc)
        except Exception as exc:
            logger.error("Delete failed for %s: %s", entry, exc)
    return deleted, skipped


def flush_dns_cache() -> None:
    if not WINDOWS:
        update_text_box("DNS flush is supported only on Windows.")
        return
    result = run_command(["ipconfig", "/flushdns"])
    if result.returncode == 0:
        update_text_box("Flushed DNS cache successfully.")
    else:
        update_text_box(f"Failed to flush DNS cache.\n{result.stderr.strip()}")


def get_primary_physical_interface_index() -> int | None:
    if not WINDOWS:
        return None
    ps = run_powershell("$a = Get-NetAdapter -Physical | Where-Object {$_.Status -eq 'Up'} | Select-Object -First 1 -ExpandProperty ifIndex; if ($a) { Write-Output $a }")
    try:
        return int((ps.stdout or '').strip().splitlines()[-1]) if (ps.stdout or '').strip() else None
    except Exception:
        return None


def get_target_interface_indices() -> list[int]:
    idx = get_primary_physical_interface_index()
    return [idx] if idx is not None else []


def set_cloudflare_dns() -> None:
    if is_safe_mode_operation("dns"):
        update_text_box("DNS change skipped (Safe Mode)")
        return
    if not WINDOWS or winreg is None:
        update_text_box("DNS change is supported only on Windows.")
        return
    proceed = messagebox.askyesno("Warning", "This will change DNS settings to Cloudflare (1.1.1.1 / 1.0.0.1).\n\nContinue?")
    if not proceed:
        return
    original_dns: dict[str, dict[str, str | None]] = {}
    changed_interfaces: list[str] = []
    reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces", 0, winreg.KEY_READ)
    try:
        for i in range(winreg.QueryInfoKey(reg_key)[0]):
            interface_name = winreg.EnumKey(reg_key, i)
            interface_read = winreg.OpenKey(reg_key, interface_name, 0, winreg.KEY_READ)
            try:
                values = {"NameServer": None, "DhcpNameServer": None}
                for key_name in ("NameServer", "DhcpNameServer"):
                    try:
                        values[key_name] = winreg.QueryValueEx(interface_read, key_name)[0]
                    except FileNotFoundError:
                        values[key_name] = None
                original_dns[interface_name] = values
            finally:
                winreg.CloseKey(interface_read)
            interface_write = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, rf"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{interface_name}", 0, winreg.KEY_SET_VALUE)
            try:
                winreg.SetValueEx(interface_write, "NameServer", 0, winreg.REG_SZ, "1.1.1.1,1.0.0.1")
                changed_interfaces.append(interface_name)
            finally:
                winreg.CloseKey(interface_write)
    finally:
        winreg.CloseKey(reg_key)
    save_json(DNS_BACKUP_FILE, {"interfaces": original_dns, "changed_interfaces": changed_interfaces})
    run_powershell(
        "$targets = Get-DnsClient | Where-Object {$_.InterfaceAlias -and $_.InterfaceOperationalStatus -ne 'Disconnected'};"
        "foreach ($t in $targets) { try { Set-DnsClientServerAddress -InterfaceIndex $t.InterfaceIndex -ServerAddresses @('1.1.1.1','1.0.0.1') -ErrorAction Stop } catch {} }"
    )
    for cmd in (["ipconfig", "/flushdns"], ["ipconfig", "/registerdns"]):
        try:
            run_command(cmd, timeout=90)
        except Exception:
            pass
    update_text_box(f"Set Cloudflare DNS for {len(changed_interfaces)} interface(s). IPv4 is now set to use the following DNS server addresses.")


def restore_original_dns() -> None:
    if not WINDOWS or winreg is None:
        update_text_box("DNS restore is supported only on Windows.")
        return
    data = load_json(DNS_BACKUP_FILE)
    if not data:
        messagebox.showerror("Error", "No DNS backup found.")
        return
    original_dns = data.get("interfaces", {})
    restored = 0
    switched_to_auto = 0
    for interface_name, original_values in original_dns.items():
        try:
            interface_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, rf"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{interface_name}", 0, winreg.KEY_SET_VALUE)
        except Exception:
            continue
        try:
            name_server = original_values.get("NameServer")
            dhcp_name_server = original_values.get("DhcpNameServer")
            if name_server:
                winreg.SetValueEx(interface_key, "NameServer", 0, winreg.REG_SZ, name_server)
            else:
                try:
                    winreg.DeleteValue(interface_key, "NameServer")
                except FileNotFoundError:
                    pass
            if dhcp_name_server:
                winreg.SetValueEx(interface_key, "DhcpNameServer", 0, winreg.REG_SZ, dhcp_name_server)
            else:
                try:
                    winreg.DeleteValue(interface_key, "DhcpNameServer")
                except FileNotFoundError:
                    pass
            restored += 1
        finally:
            winreg.CloseKey(interface_key)
    targets = get_target_interface_indices()
    if not targets:
        update_text_box("No active physical adapter found.")
        return
    switched_to_auto = 0
    for idx in targets:
        ps = run_powershell(f"Set-DnsClientServerAddress -InterfaceIndex {idx} -ResetServerAddresses")
        if ps.returncode == 0:
            switched_to_auto += 1
    try:
        run_command(["ipconfig", "/flushdns"], timeout=90)
        run_command(["ipconfig", "/registerdns"], timeout=90)
    except Exception:
        pass
    update_text_box(
        f"Restored original DNS registry values for {restored} interface(s). "
        f"Switched {switched_to_auto} active adapter(s) from 'Use the following DNS server addresses' to 'Obtain DNS server address automatically'."
    )


def get_power_plans() -> list[PowerPlan]:
    if not WINDOWS:
        return []
    result = run_command(["powercfg", "/list"])
    plans: list[PowerPlan] = []
    for line in result.stdout.splitlines():
        match = re.search(r"([a-fA-F0-9-]{36}).*?\((.*?)\)", line)
        if match:
            guid, name = match.groups()
            plans.append(PowerPlan(guid=guid, name=name.strip(), active="*" in line))
    return plans


def set_active_power_plan_by_guid(guid: str) -> bool:
    if is_safe_mode_operation("power"):
        update_text_box("Power plan change skipped (Safe Mode)")
        return False
    return run_command(["powercfg", "/setactive", guid]).returncode == 0


def delete_power_plan_by_guid(guid: str) -> bool:
    if is_safe_mode_operation("power"):
        update_text_box("Power plan deletion skipped (Safe Mode)")
        return False
    return run_command(["powercfg", "/delete", guid]).returncode == 0


def create_power_plan_from_template(template_guid: str, new_name: str) -> str | None:
    if is_safe_mode_operation("power"):
        update_text_box("Power plan creation skipped (Safe Mode)")
        return None
    result = run_command(["powercfg", "-duplicatescheme", template_guid])
    if result.returncode != 0:
        return None
    match = re.search(r"([a-fA-F0-9-]{36})", result.stdout)
    if not match:
        return None
    new_guid = match.group(1)
    rename_result = run_command(["powercfg", "/changename", new_guid, new_name])
    if rename_result.returncode != 0:
        return None
    return new_guid


def restore_default_power_plans() -> bool:
    if is_safe_mode_operation("power"):
        update_text_box("Power plan restoration skipped (Safe Mode)")
        return False
    result = run_command(["powercfg", "-restoredefaultschemes"])
    if result.returncode != 0:
        messagebox.showerror("Error", result.stderr.strip() or "Failed to restore default power plans.")
        return False
    if app is not None:
        app.refresh_power_plans()
    messagebox.showinfo("Success", "Default power plans restored.")
    return True


def clean_ram_cache() -> None:
    names: list[str] = []
    for proc in psutil.process_iter(["name", "memory_info"]):
        try:
            mem = proc.info.get("memory_info")
            if mem and mem.rss > 100 * 1024 * 1024:
                names.append(proc.info.get("name") or "Unknown")
        except Exception:
            continue
    shown = ", ".join(names[:5]) if names else "No heavy processes found"
    if len(names) > 5:
        shown += f" and {len(names)-5} more"
    update_text_box(f"RAM cache analysis complete.\nHigh-memory processes: {shown}")


def clean_windows_temp_folder() -> None:
    path = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "Temp"
    deleted, skipped = force_delete_folder_contents(path)
    update_text_box(f"Cleaned Windows Temp Folder.\nDeleted {deleted} item(s), skipped {skipped} locked/protected item(s).")


def clean_prefetch_folder() -> None:
    path = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "Prefetch"
    deleted, skipped = force_delete_folder_contents(path)
    update_text_box(f"Cleaned Prefetch Folder.\nDeleted {deleted} item(s), skipped {skipped} locked/protected item(s).")


def clean_recycle_bin() -> None:
    if not WINDOWS:
        update_text_box("Recycle Bin cleanup is supported only on Windows.")
        return
    try:
        ctypes.windll.shell32.SHEmptyRecycleBinW(None, None, 0x00000001 | 0x00000002 | 0x00000004)
        update_text_box("Recycle Bin emptied.")
    except Exception as exc:
        update_text_box(f"Recycle Bin cleanup skipped: {exc}")


def clean_windows_update_cache() -> None:
    path = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "SoftwareDistribution" / "Download"
    deleted, skipped = force_delete_folder_contents(path)
    update_text_box(f"Cleaned Windows Update Cache.\nDeleted {deleted} item(s), skipped {skipped} locked/protected item(s).")


def clean_temporary_internet_files() -> None:
    user_profile = os.environ.get("USERPROFILE", "")
    folders = [
        Path(user_profile) / "AppData" / "Local" / "Microsoft" / "Edge" / "User Data" / "Default" / "Cache",
        Path(user_profile) / "AppData" / "Local" / "Microsoft" / "Windows" / "INetCache",
        Path(user_profile) / "AppData" / "Local" / "Google" / "Chrome" / "User Data" / "Default" / "Cache",
    ]
    total = sum(force_delete_folder_contents(folder) for folder in folders)
    update_text_box(f"Cleaned browser caches.\nDeleted {total} item(s), skipped locked items were logged quietly.")


def clean_thumbnails() -> None:
    user_profile = os.environ.get("USERPROFILE", "")
    explorer = Path(user_profile) / "AppData" / "Local" / "Microsoft" / "Windows" / "Explorer"
    deleted = 0
    if explorer.exists():
        for entry in explorer.iterdir():
            if entry.name.startswith("thumbcache_"):
                try:
                    entry.unlink(missing_ok=True)
                    deleted += 1
                except Exception:
                    pass
    update_text_box(f"Cleaned thumbnails.\nDeleted {deleted} file(s), skipped locked items were logged quietly.")


def clean_delivery_optimization_files() -> None:
    path = Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "ServiceProfiles" / "NetworkService" / "AppData" / "Local" / "Microsoft" / "Windows" / "DeliveryOptimization"
    deleted, skipped = force_delete_folder_contents(path)
    update_text_box(f"Cleaned Delivery Optimization Files.\nDeleted {deleted} item(s), skipped {skipped} locked/protected item(s).")


def clean_temp_folder() -> None:
    folders = [Path(os.environ.get("TEMP", "")), Path(os.environ.get("TMP", "")), Path(os.environ.get("SystemRoot", r"C:\Windows")) / "Temp"]
    total = 0
    skipped = 0
    for folder in folders:
        if not str(folder):
            continue
        d, s = force_delete_folder_contents(folder)
        total += d
        skipped += s
    update_text_box(f"Cleaned temp folders.\nDeleted {total} item(s), skipped locked items were logged quietly.")


def clean_windows_update_cleanup() -> None:
    clean_windows_update_cache()


def clean_microsoft_defender_antivirus() -> None:
    path = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "Microsoft" / "Windows Defender" / "Scans"
    deleted, skipped = force_delete_folder_contents(path)
    update_text_box(f"Cleaned Defender scan files.\nDeleted {deleted} item(s), skipped {skipped} locked/protected item(s).")


def clean_windows_upgrade_log_files() -> None:
    path = Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "Logs" / "CBS"
    deleted, skipped = force_delete_folder_contents(path)
    update_text_box(f"Cleaned Windows upgrade logs.\nDeleted {deleted} item(s), skipped {skipped} locked/protected item(s).")


def clean_system_recovery_log_files() -> None:
    path = Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32" / "LogFiles"
    deleted, skipped = force_delete_folder_contents(path)
    update_text_box(f"Cleaned system recovery logs.\nDeleted {deleted} item(s), skipped {skipped} locked/protected item(s).")


def disable_telemetry() -> None:
    if is_safe_mode_operation("telemetry"):
        update_text_box("Telemetry disable skipped (Safe Mode)")
        return
    backup_registry_value("telemetry", winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\DataCollection", "AllowTelemetry")
    run_powershell("New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection' -Force | Out-Null; Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection' -Name 'AllowTelemetry' -Type DWord -Value 0")
    update_text_box("Telemetry policy updated.")


def disable_cortana() -> None:
    if is_safe_mode_operation("cortana"):
        update_text_box("Cortana disable skipped (Safe Mode)")
        return
    backup_registry_value("cortana", winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\Windows Search", "AllowCortana")
    run_powershell("New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search' -Force | Out-Null; Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search' -Name 'AllowCortana' -Type DWord -Value 0")
    update_text_box("Cortana policy updated.")


def disable_game_bar() -> None:
    if is_safe_mode_operation("gamebar"):
        update_text_box("Game Bar disable skipped (Safe Mode)")
        return
    backup_registry_value("gamebar", winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\GameDVR", "AllowGameDVR")
    run_powershell("New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\GameDVR' -Force | Out-Null; Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\GameDVR' -Name 'AllowGameDVR' -Type DWord -Value 0")
    update_text_box("Game Bar policy updated.")


def optimize_network_adapter() -> None:
    if is_safe_mode_operation("network"):
        update_text_box("Network optimization skipped (Safe Mode)")
        return
    result = run_command(["netsh", "int", "tcp", "set", "global", "autotuninglevel=normal"])
    if result.returncode == 0:
        update_text_box("Optimized network adapter settings.")
    else:
        update_text_box(result.stderr.strip() or "Failed to optimize network adapter settings.")


def optimize_polling_rate() -> None:
    if is_safe_mode_operation("polling"):
        update_text_box("Polling rate optimization skipped (Safe Mode)")
        return
    data = load_json(SETTINGS_BACKUP_FILE)
    tweaks = data.setdefault("polling_rate", {"backed_up": True})
    save_json(SETTINGS_BACKUP_FILE, data)
    run_command(["bcdedit", "/set", "useplatformclock", "false"], timeout=60)
    run_command(["bcdedit", "/set", "disabledynamictick", "yes"], timeout=60)
    run_command(["bcdedit", "/set", "tscsyncpolicy", "Enhanced"], timeout=60)
    update_text_box("Polling rate optimization applied for snappier input response. A reboot may be required.")


def revert_polling_rate() -> None:
    if not WINDOWS:
        update_text_box("Polling rate revert is supported only on Windows.")
        return
    run_command(["bcdedit", "/deletevalue", "useplatformclock"], timeout=60)
    run_command(["bcdedit", "/deletevalue", "disabledynamictick"], timeout=60)
    run_command(["bcdedit", "/deletevalue", "tscsyncpolicy"], timeout=60)
    update_text_box("Polling rate settings reverted to default behavior. A reboot may be required.")


def optimize_appearance_settings() -> None:
    if is_safe_mode_operation("appearance"):
        update_text_box("Appearance optimization skipped (Safe Mode)")
        return
    if not WINDOWS or winreg is None:
        update_text_box("Appearance optimization is supported only on Windows.")
        return
    backup_registry_value("appearance_visualfx", winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects", "VisualFXSetting")
    result = run_powershell(
        "New-Item -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\VisualEffects' -Force | Out-Null;"
        "Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\VisualEffects' -Name 'VisualFXSetting' -Type DWord -Value 2;"
        "$p='HKCU:\\Control Panel\\Desktop';"
        "Set-ItemProperty -Path $p -Name 'DragFullWindows' -Value '0';"
        "Set-ItemProperty -Path $p -Name 'MenuShowDelay' -Value '0';"
        "Set-ItemProperty -Path $p -Name 'UserPreferencesMask' -Value ([byte[]](0x90,0x12,0x03,0x80,0x10,0x00,0x00,0x00));"
        "RUNDLL32.EXE user32.dll,UpdatePerUserSystemParameters"
    )
    if result.returncode == 0:
        update_text_box("Optimize Appearance Setting applied: Adjust for best performance selected.")
    else:
        update_text_box(result.stderr.strip() or "Failed to optimize appearance settings.")


def restore_standard_windows_settings() -> None:
    restored: list[str] = []
    if restore_backed_registry_value("telemetry"):
        restored.append("Telemetry")
    if restore_backed_registry_value("cortana"):
        restored.append("Cortana")
    if restore_backed_registry_value("gamebar"):
        restored.append("Game Bar")
    if restore_backed_registry_value("appearance_visualfx"):
        restored.append("Appearance Settings")
    revert_polling_rate()
    try:
        restore_original_dns()
        restored.append("DNS")
    except Exception:
        pass
    if restored:
        update_text_box("Restored standard Windows settings for: " + ", ".join(restored))
    else:
        update_text_box("No backed-up settings found to restore.")


def add_registry_entry(exe_name: str, priority: int) -> None:
    if not WINDOWS or winreg is None:
        raise RuntimeError("Registry editing is supported only on Windows.")
    reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", 0, winreg.KEY_WRITE)
    try:
        exe_key = winreg.CreateKey(reg_key, exe_name)
        try:
            perf_key = winreg.CreateKey(exe_key, "PerfOptions")
            try:
                winreg.SetValueEx(perf_key, "CpuPriorityClass", 0, winreg.REG_DWORD, priority)
            finally:
                winreg.CloseKey(perf_key)
        finally:
            winreg.CloseKey(exe_key)
    finally:
        winreg.CloseKey(reg_key)


def remove_registry_entry(exe_name: str) -> None:
    if not WINDOWS or winreg is None:
        raise RuntimeError("Registry editing is supported only on Windows.")
    reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", 0, winreg.KEY_WRITE)
    try:
        try:
            winreg.DeleteKey(reg_key, exe_name + r"\PerfOptions")
        except Exception:
            pass
        try:
            winreg.DeleteKey(reg_key, exe_name)
        except Exception:
            pass
    finally:
        winreg.CloseKey(reg_key)


def is_process_running(exe_name: str) -> bool:
    for proc in psutil.process_iter(["pid", "name"]):
        if proc.info.get("name") == exe_name:
            return True
    return False


def set_priority(pid: int, priority: int) -> None:
    process = psutil.Process(pid)
    process.nice(priority)


def priority_bypasser_window() -> None:
    if app is None:
        return
    window = ctk.CTkToplevel(app.root)
    window.title("Priority Bypasser")
    window.geometry("480x360")
    window.transient(app.root)
    window.grab_set()
    ctk.CTkLabel(window, text="Priority Bypasser", font=("Courier New", 20, "bold"), text_color="#ff0000").pack(pady=10)
    ctk.CTkLabel(window, text="Select Process Priority:", font=("Courier New", 14, "bold"), text_color="#ff0000").pack(pady=5)
    priority_var = tk.StringVar(value="Normal")
    dropdown = ctk.CTkComboBox(window, variable=priority_var, values=priority_names, width=200, fg_color="#333333", button_color="#333333", button_hover_color="#444444", border_color="#555555", text_color="#ffffff")
    dropdown.pack(pady=10)

    def load_and_set_priority() -> None:
        file_path = filedialog.askopenfilename(title="Select an executable", filetypes=[("Executable files", "*.exe")])
        if not file_path:
            return
        exe_name = os.path.basename(file_path)
        if is_process_running(exe_name):
            messagebox.showwarning("Already Running", f"{exe_name} is already running.")
            return
        try:
            selected_priority = priority_var.get()
            priority = priority_levels[priority_names.index(selected_priority)]
            add_registry_entry(exe_name, priority)
            process = psutil.Popen(file_path)
            set_priority(process.pid, priority)
            messagebox.showinfo("Success", f"Priority set to {selected_priority} for {exe_name}")
        except Exception as exc:
            messagebox.showerror("Error", f"Failed to launch or set priority: {exc}")

    def revert_to_default() -> None:
        file_path = filedialog.askopenfilename(title="Select an executable", filetypes=[("Executable files", "*.exe")])
        if not file_path:
            return
        exe_name = os.path.basename(file_path)
        try:
            remove_registry_entry(exe_name)
            for proc in psutil.process_iter(["pid", "name"]):
                if proc.info.get("name") == exe_name:
                    set_priority(proc.info["pid"], psutil.NORMAL_PRIORITY_CLASS)
            messagebox.showinfo("Success", f"{exe_name} has been reverted to default priority.")
        except Exception as exc:
            messagebox.showerror("Error", f"Failed to revert to default: {exc}")

    ctk.CTkButton(window, text="Load EXE and Set Priority", fg_color="#333333", hover_color="#444444", command=load_and_set_priority).pack(pady=20)
    ctk.CTkButton(window, text="Revert to Default", fg_color="#ff0000", hover_color="#cc0000", command=revert_to_default).pack(pady=10)
    ctk.CTkButton(window, text="Exit", fg_color="#333333", hover_color="#444444", command=window.destroy).pack(pady=10)


def get_gpu_info() -> list[dict[str, Any]]:
    if GPUtil is None:
        return []
    try:
        gpus = GPUtil.getGPUs()
    except Exception:
        return []
    info: list[dict[str, Any]] = []
    for gpu in gpus:
        total_mem = getattr(gpu, "memoryTotal", 0) or 0
        used_mem = getattr(gpu, "memoryUsed", 0) or 0
        info.append({
            "name": getattr(gpu, "name", "Unknown"),
            "temperature": getattr(gpu, "temperature", 0),
            "memory_used": used_mem,
            "memory_total": total_mem,
            "memory_percent": (used_mem / total_mem * 100) if total_mem else 0,
            "load": getattr(gpu, "load", 0) * 100,
            "driver": getattr(gpu, "driver", "Unknown"),
            "uuid": getattr(gpu, "uuid", "Unknown"),
        })
    return info


def get_enhanced_system_performance() -> dict[str, Any] | None:
    try:
        cpu_percent = psutil.cpu_percent(interval=1)
        cpu_freq = psutil.cpu_freq()
        memory = psutil.virtual_memory()
        disk_info: list[dict[str, Any]] = []
        for partition in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                disk_info.append({
                    "device": partition.device,
                    "mountpoint": partition.mountpoint,
                    "total": usage.total / (1024**3),
                    "used": usage.used / (1024**3),
                    "free": usage.free / (1024**3),
                    "percent": usage.percent,
                })
            except Exception:
                continue
        return {
            "cpu_percent": cpu_percent,
            "cpu_frequency": cpu_freq.current if cpu_freq else "N/A",
            "physical_cores": psutil.cpu_count(logical=False),
            "logical_cores": psutil.cpu_count(logical=True),
            "memory_percent": memory.percent,
            "memory_used_gb": memory.used / (1024**3),
            "memory_total_gb": memory.total / (1024**3),
            "memory_available_gb": memory.available / (1024**3),
            "disk_info": disk_info,
            "active_processes": len(psutil.pids()),
            "gpu_info": get_gpu_info(),
            "timestamp": datetime.now().strftime("%H:%M:%S"),
        }
    except Exception:
        return None


def update_performance_text(widget: ctk.CTkTextbox, text: str) -> None:
    widget.configure(state="normal")
    widget.delete("1.0", "end")
    widget.insert("1.0", text)
    widget.configure(state="disabled")


def monitor_performance(status_label: ctk.CTkLabel, performance_text: ctk.CTkTextbox) -> None:
    global performance_monitoring
    prev_net = psutil.net_io_counters()
    prev_time = time.time()
    while performance_monitoring:
        perf = get_enhanced_system_performance()
        if not perf:
            time.sleep(2)
            continue
        now = time.time()
        net = psutil.net_io_counters()
        diff = max(now - prev_time, 0.001)
        down = (net.bytes_recv - prev_net.bytes_recv) / diff / 1024
        up = (net.bytes_sent - prev_net.bytes_sent) / diff / 1024
        prev_net = net
        prev_time = now
        lines = [
            "=== Enhanced System Performance Monitor ===",
            f"Last Update: {perf['timestamp']}",
            "",
            "--- CPU ---",
            f"Usage: {perf['cpu_percent']:.1f}%",
            f"Frequency: {perf['cpu_frequency']} MHz",
            f"Cores: {perf['physical_cores']} physical, {perf['logical_cores']} logical",
            "",
            "--- Memory ---",
            f"Usage: {perf['memory_percent']:.1f}%",
            f"Used: {perf['memory_used_gb']:.1f} GB",
            f"Available: {perf['memory_available_gb']:.1f} GB",
            f"Total: {perf['memory_total_gb']:.1f} GB",
            "",
            "--- Storage ---",
        ]
        for disk in perf["disk_info"]:
            lines.append(f"{disk['device']} ({disk['mountpoint']}): {disk['percent']:.1f}%")
            lines.append(f"  Used: {disk['used']:.1f} GB / {disk['total']:.1f} GB")
        lines.extend(["", "--- Network ---", f"Download: {down:.1f} KB/s", f"Upload: {up:.1f} KB/s", f"Active Processes: {perf['active_processes']}", "", "--- GPU ---"])
        if perf["gpu_info"]:
            for index, gpu in enumerate(perf["gpu_info"], start=1):
                lines.extend([
                    f"GPU {index}: {gpu['name']}",
                    f"  Driver: {gpu['driver']}",
                    f"  UUID: {gpu['uuid']}",
                    f"  Temperature: {gpu['temperature']}°C",
                    f"  Usage: {gpu['load']:.1f}%",
                    f"  Memory: {gpu['memory_used']} / {gpu['memory_total']} MB ({gpu['memory_percent']:.1f}%)",
                ])
        else:
            lines.append("No GPU detected or monitoring unavailable.")
        text = "\n".join(lines)
        if app is not None:
            app.root.after(0, lambda t=text: update_performance_text(performance_text, t))
            app.root.after(0, lambda: status_label.configure(text=f"Monitoring... Last update: {perf['timestamp']}"))
        time.sleep(2)


def start_performance_monitoring(status_label: ctk.CTkLabel, performance_text: ctk.CTkTextbox) -> None:
    global performance_monitoring, performance_thread
    if performance_monitoring:
        return
    performance_monitoring = True
    performance_thread = threading.Thread(target=monitor_performance, args=(status_label, performance_text), daemon=True)
    performance_thread.start()
    status_label.configure(text="Performance monitoring started...")


def stop_performance_monitoring(status_label: ctk.CTkLabel) -> None:
    global performance_monitoring, performance_thread
    performance_monitoring = False
    if performance_thread and performance_thread.is_alive() and threading.current_thread() is not performance_thread:
        performance_thread.join(timeout=2)
    status_label.configure(text="Performance monitoring stopped")


def test_internet_speed() -> dict[str, float] | None:
    if speedtest is None:
        return None
    try:
        st = speedtest.Speedtest()
        st.get_best_server()
        return {"download": round(st.download() / 1_000_000, 2), "upload": round(st.upload() / 1_000_000, 2), "ping": round(st.results.ping, 2)}
    except Exception:
        return None


def open_nvidia_drivers() -> None:
    webbrowser.open("https://www.nvidia.com/Download/index.aspx")


def open_support_page() -> None:
    webbrowser.open("https://www.paypal.com/paypalme/robbybarnedt")


def get_running_processes() -> list[str]:
    names: set[str] = set()
    for proc in psutil.process_iter(["name"]):
        try:
            if proc.info.get("name"):
                names.add(proc.info["name"])
        except Exception:
            continue
    return sorted(names)


def set_cpu_affinity(process_name: str, cores: list[int]) -> bool:
    for proc in psutil.process_iter(["pid", "name"]):
        if proc.info.get("name") == process_name:
            try:
                psutil.Process(proc.info["pid"]).cpu_affinity(cores)
                return True
            except Exception:
                return False
    return False


def set_process_priority(process_name: str, priority: int) -> bool:
    for proc in psutil.process_iter(["pid", "name"]):
        if proc.info.get("name") == process_name:
            try:
                psutil.Process(proc.info["pid"]).nice(priority)
                return True
            except Exception:
                return False
    return False


def disable_windows_defender() -> None:
    if is_safe_mode_operation("defender"):
        return
    run_powershell("Set-MpPreference -DisableRealtimeMonitoring $true")


def disable_windows_animations() -> None:
    if is_safe_mode_operation("animations"):
        return
    run_powershell("Set-ItemProperty -Path 'HKCU:\\Control Panel\\Desktop' -Name UserPreferencesMask -Value ([byte[]](0x90,0x12,0x03,0x80,0x10,0x00,0x00,0x00))")


def optimize_system(status_log: ctk.CTkTextbox, progress_bar: ctk.CTkProgressBar) -> None:
    status_log.configure(state="normal")
    status_log.insert("end", "Applying process optimizations...\n")
    status_log.configure(state="disabled")
    progress_bar.set(0.25)
    for process_name in program_list:
        set_process_priority(process_name, psutil.HIGH_PRIORITY_CLASS)
    progress_bar.set(0.50)
    disable_windows_defender()
    progress_bar.set(0.75)
    disable_windows_animations()
    progress_bar.set(1.0)
    status_log.configure(state="normal")
    status_log.insert("end", "Optimizations complete!\n")
    status_log.see("end")
    status_log.configure(state="disabled")


def monitor_processes(status_log: ctk.CTkTextbox, progress_bar: ctk.CTkProgressBar) -> None:
    global detected_processes
    while not monitoring_event.is_set():
        for proc in psutil.process_iter(["name"]):
            name = proc.info.get("name")
            if name in program_list and name not in detected_processes:
                detected_processes.add(name)
                status_log.configure(state="normal")
                status_log.insert("end", f"Detected {name}. Applying optimizations...\n")
                status_log.configure(state="disabled")
                optimize_system(status_log, progress_bar)
        time.sleep(5)


def start_monitoring(status_log: ctk.CTkTextbox, progress_bar: ctk.CTkProgressBar) -> None:
    global monitoring_thread, detected_processes
    if not program_list:
        messagebox.showerror("Error", "No programs in the list to monitor!")
        return
    detected_processes.clear()
    monitoring_event.clear()
    monitoring_thread = threading.Thread(target=monitor_processes, args=(status_log, progress_bar), daemon=True)
    monitoring_thread.start()
    status_log.configure(state="normal")
    status_log.insert("end", f"Monitoring for programs: {', '.join(program_list)}\n")
    status_log.configure(state="disabled")


def stop_monitoring(status_log: ctk.CTkTextbox) -> None:
    global monitoring_thread
    if monitoring_thread and monitoring_thread.is_alive():
        monitoring_event.set()
        monitoring_thread.join(timeout=1)
        status_log.configure(state="normal")
        status_log.insert("end", "Monitoring stopped.\n")
        status_log.configure(state="disabled")


def clear_log(status_log: ctk.CTkTextbox) -> None:
    status_log.configure(state="normal")
    status_log.delete("1.0", "end")
    status_log.insert("end", "Log cleared.\n")
    status_log.configure(state="disabled")


def save_log(status_log: ctk.CTkTextbox) -> None:
    filename = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
    if not filename:
        return
    with open(filename, "w", encoding="utf-8") as fh:
        status_log.configure(state="normal")
        fh.write(status_log.get("1.0", "end"))
        status_log.configure(state="disabled")
    messagebox.showinfo("Log Saved", f"Saved log to {filename}")


def load_program_list(status_log: ctk.CTkTextbox) -> None:
    global program_list
    filename = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
    if not filename:
        return
    with open(filename, "r", encoding="utf-8") as fh:
        program_list = [line.strip() for line in fh if line.strip()]
    status_log.configure(state="normal")
    status_log.insert("end", f"Loaded program list: {', '.join(program_list)}\n")
    status_log.configure(state="disabled")


def save_program_list() -> None:
    filename = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
    if not filename:
        return
    with open(filename, "w", encoding="utf-8") as fh:
        fh.write("\n".join(program_list))
    messagebox.showinfo("List Saved", f"Saved program list to {filename}")


def add_program(program_entry: ctk.CTkEntry, status_log: ctk.CTkTextbox) -> None:
    program_name = program_entry.get().strip()
    if not program_name:
        messagebox.showerror("Error", "Please enter a program name!")
        return
    if program_name not in program_list:
        program_list.append(program_name)
    program_entry.delete(0, "end")
    status_log.configure(state="normal")
    status_log.insert("end", f"Added {program_name} to the program list.\n")
    status_log.configure(state="disabled")


def add_directory(status_log: ctk.CTkTextbox) -> None:
    directory = filedialog.askdirectory()
    if not directory:
        return
    found = 0
    for root, _, files in os.walk(directory):
        for file in files:
            if file.lower().endswith(".exe") and file not in program_list:
                program_list.append(file)
                found += 1
    status_log.configure(state="normal")
    status_log.insert("end", f"Added {found} executable(s) from {directory}.\n")
    status_log.configure(state="disabled")


def reset_progress_bar(progress_bar: ctk.CTkProgressBar) -> None:
    progress_bar.set(0)


def check_and_set_ultimate_power_plan() -> None:
    if is_safe_mode_operation("power"):
        update_text_box("Power plan change skipped (Safe Mode)")
        return
    plans = get_power_plans()
    for plan in plans:
        if "Ultimate Performance" in plan.name:
            if set_active_power_plan_by_guid(plan.guid):
                update_text_box("Activated Ultimate Performance power plan.")
            return
    guid = create_power_plan_from_template("e9a42b02-d5df-448d-aa00-03f14749eb61", "Ultimate Performance")
    if guid and set_active_power_plan_by_guid(guid):
        update_text_box("Created and activated Ultimate Performance power plan.")
    else:
        update_text_box("Failed to activate Ultimate Performance power plan.")


def unlock_and_configure_trickster() -> None:
    guid = create_power_plan_from_template("e9a42b02-d5df-448d-aa00-03f14749eb61", "High Performance")
    if not guid:
        messagebox.showerror("Error", "Failed to create disguised High Performance plan.")
        return
    if set_active_power_plan_by_guid(guid):
        messagebox.showinfo("Success", "Ultimate Performance was unlocked and renamed to High Performance.\nYou can now assign apps to High Performance in Windows graphics settings.")
        if app is not None:
            app.refresh_power_plans()


def get_advanced_system_info() -> dict[str, Any]:
    return {
        "python": {"version": platform.python_version(), "path": sys.executable, "architecture": platform.architecture()[0]},
        "os": {"name": platform.system(), "version": platform.version(), "release": platform.release(), "architecture": platform.architecture()[0], "processor": platform.processor()},
        "memory": {
            "total_physical": f"{psutil.virtual_memory().total / (1024**3):.2f} GB",
            "available_physical": f"{psutil.virtual_memory().available / (1024**3):.2f} GB",
            "used_physical": f"{psutil.virtual_memory().used / (1024**3):.2f} GB",
            "physical_percent": f"{psutil.virtual_memory().percent}%",
        },
        "storage": [{"device": p.device, "mountpoint": p.mountpoint, "fstype": p.fstype} for p in psutil.disk_partitions()],
        "network": [{"name": n} for n in psutil.net_if_addrs().keys()],
        "directx": "Unknown",
    }


def format_summary_info(info: dict[str, Any]) -> str:
    os_info = info.get("os", {})
    memory_info = info.get("memory", {})
    lines = [
        "=== SYSTEM SUMMARY ===", "",
        f"Operating System: {os_info.get('name', 'N/A')} {os_info.get('release', 'N/A')}",
        f"Architecture: {os_info.get('architecture', 'N/A')}", "",
        f"Memory: {memory_info.get('total_physical', 'N/A')} total",
        f"Available: {memory_info.get('available_physical', 'N/A')}",
        f"Usage: {memory_info.get('physical_percent', 'N/A')}", "",
        f"Storage Drives: {len(info.get('storage', []))}",
        f"Network Adapters: {len(info.get('network', []))}",
        f"Python Version: {info.get('python', {}).get('version', 'N/A')}",
        f"DirectX Version: {info.get('directx', 'Unknown')}",
    ]
    return "\n".join(lines)


def export_system_info(info: dict[str, Any]) -> None:
    filename = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")], title="Export System Information")
    if not filename:
        return
    with open(filename, "w", encoding="utf-8") as fh:
        fh.write("=== Tools - Advanced System Information Report ===\n\n")
        fh.write(f"Generated on: {datetime.now():%Y-%m-%d %H:%M:%S}\n\n")
        fh.write(format_summary_info(info))
    messagebox.showinfo("Export Successful", f"System information exported to:\n{filename}")


def show_advanced_system_info() -> None:
    if app is None:
        return
    info_window = ctk.CTkToplevel(app.root)
    info_window.title("Advanced System Information")
    info_window.geometry("900x700")
    info_window.transient(app.root)
    info_window.grab_set()
    notebook = ctk.CTkTabview(info_window)
    notebook.pack(fill="both", expand=True, padx=10, pady=10)
    notebook.add("Summary")
    system_info = get_advanced_system_info()
    textbox = ctk.CTkTextbox(notebook.tab("Summary"), font=("Courier New", 11), wrap="word")
    textbox.pack(fill="both", expand=True, padx=10, pady=10)
    textbox.insert("1.0", format_summary_info(system_info))
    textbox.configure(state="disabled")
    ctk.CTkButton(info_window, text="Export to Text File", font=("Courier New", 12, "bold"), fg_color="#ff0000", hover_color="#cc0000", command=lambda: export_system_info(system_info)).pack(pady=10)


def set_monitor_dimensions() -> None:
    if app is None:
        return
    window = ctk.CTkToplevel(app.root)
    window.title("Set Window Size")
    window.geometry("400x500")
    window.transient(app.root)
    window.grab_set()
    resolutions = [("1024x768", "XGA"), ("1280x720", "HD"), ("1366x768", "FWXGA"), ("1600x900", "HD+"), ("1920x1080", "Full HD")]
    choice = tk.StringVar(value="800x600")
    ctk.CTkLabel(window, text="Select Window Size", font=("Courier New", 18, "bold"), text_color="#ff0000").pack(pady=10)
    frame = ctk.CTkScrollableFrame(window, height=250)
    frame.pack(fill="both", expand=True, padx=10, pady=10)
    for resolution, name in resolutions:
        holder = ctk.CTkFrame(frame)
        holder.pack(fill="x", pady=2)
        ctk.CTkRadioButton(holder, text=f"{resolution} - {name}", variable=choice, value=resolution, font=("Courier New", 12)).pack(side="left", padx=5, pady=2)
    custom_entry = ctk.CTkEntry(window, placeholder_text="e.g., 800x600", font=("Courier New", 12))
    custom_entry.pack(fill="x", padx=10, pady=10)

    def apply_resolution() -> None:
        resolution = custom_entry.get().strip() or choice.get()
        if not re.fullmatch(r"\d+x\d+", resolution):
            messagebox.showerror("Error", "Invalid format. Use WIDTHxHEIGHT, e.g. 800x600")
            return
        app.root.geometry(resolution)
        window.destroy()

    ctk.CTkButton(window, text="Apply Resolution", font=("Courier New", 14, "bold"), fg_color="#ff0000", hover_color="#cc0000", command=apply_resolution).pack(pady=10)


def show_debug_console() -> None:
    if app is None:
        return
    window = ctk.CTkToplevel(app.root)
    window.title("Debug Console")
    window.geometry("700x450")
    window.transient(app.root)
    window.grab_set()
    textbox = ctk.CTkTextbox(window, font=("Courier New", 10))
    textbox.pack(fill="both", expand=True, padx=10, pady=10)

    def refresh() -> None:
        textbox.configure(state="normal")
        textbox.delete("1.0", "end")
        parts: list[str] = []
        if LOG_FILE.exists():
            parts.append("=== debug.log ===\n" + LOG_FILE.read_text(encoding="utf-8", errors="replace"))
        if DEBUG_LOG_FILE.exists():
            extra = DEBUG_LOG_FILE.read_text(encoding="utf-8", errors="replace")
            if extra.strip():
                parts.append("=== debug_log.txt ===\n" + extra)
        if parts:
            textbox.insert("1.0", "\n\n".join(parts))
        else:
            textbox.insert("1.0", "No debug logs found.")
        textbox.configure(state="disabled")

    refresh()
    btns = ctk.CTkFrame(window)
    btns.pack(pady=5)
    ctk.CTkButton(btns, text="Refresh", font=("Courier New", 12, "bold"), fg_color="#333333", hover_color="#444444", command=refresh).pack(side="left", padx=5)
    ctk.CTkButton(btns, text="Clear", font=("Courier New", 12, "bold"), fg_color="#ff0000", hover_color="#cc0000", command=clear_debug_logs).pack(side="left", padx=5)


class App:
    def __init__(self, root: ctk.CTk):
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("800x860")
        self.create_menu_bar()
        self.notebook = ctk.CTkTabview(root)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=10)
        for name in ["System Optimizer", "Game Optimizer", "Performance Monitor", "Help"]:
            self.notebook.add(name)
        self.init_system_optimizer_tab()
        self.init_game_optimizer_tab()
        self.init_performance_tab()
        self.init_help_tab()

    def create_menu_bar(self) -> None:
        self.menu_bar = tk.Menu(self.root)
        self.root.config(menu=self.menu_bar)
        self.tools_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.menu_bar.add_cascade(label="Tools", menu=self.tools_menu)
        self.tools_menu.add_command(label="Clear Log", command=self.clear_current_log)
        self.tools_menu.add_command(label="Save Log", command=self.save_current_log)
        self.tools_menu.add_separator()
        self.tools_menu.add_command(label="Advanced System Info", command=show_advanced_system_info)
        self.tools_menu.add_command(label="Set Window Size", command=set_monitor_dimensions)
        self.tools_menu.add_command(label="Debug Console", command=show_debug_console)
        self.tools_menu.add_command(label="Disable Limit Reservable Bandwidth", command=lambda: self.clear_and_run(lambda: apply_limit_reservable_bandwidth(True, 0)))
        self.tools_menu.add_command(label="Revert LRB", command=lambda: self.clear_and_run(lambda: apply_limit_reservable_bandwidth(False, 0)))
        self.tools_menu.add_separator()
        self.tools_menu.add_command(label="Restore Original DNS", command=restore_original_dns)
        self.tools_menu.add_command(label="Optimize Polling Rate", command=optimize_polling_rate)
        self.tools_menu.add_command(label="Revert Polling Rate", command=revert_polling_rate)
        self.tools_menu.add_command(label="Priority Bypasser", command=priority_bypasser_window)
        self.tools_menu.add_command(label="Restore Standard Windows Settings", command=restore_standard_windows_settings)
        self.tools_menu.add_separator()
        self.tools_menu.add_command(label="Trickster", command=unlock_and_configure_trickster)
        self.tools_menu.add_separator()
        self.tools_menu.add_command(label="Exit", command=self.exit_app)

    def clear_current_log(self) -> None:
        current = self.notebook.get()
        if current == "System Optimizer":
            clear_log(self.text_box)
        elif current == "Game Optimizer":
            clear_log(self.game_status_log)
        elif current == "Performance Monitor":
            clear_log(self.performance_text)

    def save_current_log(self) -> None:
        current = self.notebook.get()
        if current == "System Optimizer":
            save_log(self.text_box)
        elif current == "Game Optimizer":
            save_log(self.game_status_log)
        elif current == "Performance Monitor":
            save_log(self.performance_text)

    def init_system_optimizer_tab(self) -> None:
        tab = self.notebook.tab("System Optimizer")
        ctk.CTkLabel(tab, text="System Optimizer", font=("Courier New", 24, "bold"), text_color="#ff0000").pack(pady=20)
        safe_mode_frame = ctk.CTkFrame(tab)
        safe_mode_frame.pack(pady=10)
        self.safe_mode_label = ctk.CTkLabel(safe_mode_frame, text=f"Safe Mode: {'ENABLED' if safe_mode else 'DISABLED'}", font=("Courier New", 14, "bold"), text_color="#00ff00" if safe_mode else "#ff0000")
        self.safe_mode_label.pack(side="left", padx=10)
        ctk.CTkButton(safe_mode_frame, text="Toggle Safe Mode", fg_color="#333333", hover_color="#444444", command=toggle_safe_mode).pack(side="left", padx=10)
        self.system_scrollable_frame = ctk.CTkScrollableFrame(tab, width=760, height=500)
        self.system_scrollable_frame.pack(fill="both", expand=True, padx=20, pady=10)
        button_configs: list[tuple[str, Callable[[], None], bool]] = [
            ("Clean RAM Cache", clean_ram_cache, False),
            ("Clean Windows Temp Folder", clean_windows_temp_folder, False),
            ("Clean Prefetch Folder", clean_prefetch_folder, False),
            ("Clean Recycle Bin", clean_recycle_bin, False),
            ("Clean Windows Update Cache", clean_windows_update_cache, False),
            ("Clean Temporary Internet Files", clean_temporary_internet_files, False),
            ("Clean Thumbnails", clean_thumbnails, False),
            ("Clean Delivery Optimization Files", clean_delivery_optimization_files, False),
            ("Clean Temp Folder", clean_temp_folder, False),
            ("Flush DNS Cache", flush_dns_cache, False),
            ("Set Cloudflare DNS", set_cloudflare_dns, False),
            ("Set Ultimate Power Plan", check_and_set_ultimate_power_plan, False),
            ("Optimize Appearance Setting", optimize_appearance_settings, False),
            ("Clean Windows Update Cleanup", clean_windows_update_cleanup, False),
            ("Clean Microsoft Defender Antivirus", clean_microsoft_defender_antivirus, False),
            ("Clean Windows Upgrade Log Files", clean_windows_upgrade_log_files, False),
            ("Clean System Recovery Log Files", clean_system_recovery_log_files, False),
            ("Disable Telemetry", disable_telemetry, False),
            ("Disable Cortana", disable_cortana, False),
            ("Disable Game Bar", disable_game_bar, False),
            ("Optimize Network Adapter", optimize_network_adapter, False),
        ]
        self.system_checkboxes: dict[str, tk.BooleanVar] = {}
        self.system_function_map: dict[str, Callable[[], None]] = {}
        for text, command, _ in button_configs:
            frame = ctk.CTkFrame(self.system_scrollable_frame)
            frame.pack(fill="x", pady=2)
            var = tk.BooleanVar(value=False)
            ctk.CTkCheckBox(frame, text="", variable=var, width=20).pack(side="left", padx=(10, 5))
            self.system_checkboxes[text] = var
            self.system_function_map[text] = command
            ctk.CTkButton(frame, text=text, command=lambda cmd=command: self.clear_and_run(cmd), fg_color="#333333", hover_color="#444444").pack(side="left", fill="x", expand=True, padx=5)
        ctk.CTkButton(self.system_scrollable_frame, text="Run All", fg_color="#ff0000", hover_color="#cc0000", command=self.run_all).pack(pady=10, fill="x")
        ctk.CTkButton(self.system_scrollable_frame, text="Run Preferred", fg_color="#ff0000", hover_color="#cc0000", command=self.run_preferred).pack(pady=5, fill="x")
        self.text_box = ctk.CTkTextbox(self.system_scrollable_frame, height=120, font=("Courier New", 11), text_color="#ffffff", fg_color="#333333")
        self.text_box.pack(pady=10, fill="x")
        self.text_box.insert("1.0", "Ready for optimization...\n")
        self.text_box.configure(state="disabled")

    def init_game_optimizer_tab(self) -> None:
        tab = self.notebook.tab("Game Optimizer")
        ctk.CTkLabel(tab, text="Game Optimizer", font=("Courier New", 24, "bold"), text_color="#ff0000").pack(pady=20)
        self.game_scrollable_frame = ctk.CTkScrollableFrame(tab, width=760, height=600)
        self.game_scrollable_frame.pack(fill="both", expand=True, padx=20, pady=10)
        ctk.CTkLabel(self.game_scrollable_frame, text="Power Plan Management", font=("Courier New", 18, "bold"), text_color="#ff0000").pack(pady=10)
        plans_frame = ctk.CTkFrame(self.game_scrollable_frame)
        plans_frame.pack(fill="x", pady=5, padx=5)
        ctk.CTkLabel(plans_frame, text="Available Power Plans:", font=("Courier New", 12, "bold")).pack(anchor="w", padx=5, pady=5)
        plans_list_frame = ctk.CTkFrame(plans_frame)
        plans_list_frame.pack(fill="x", padx=5, pady=5)
        self.power_plans_listbox = tk.Listbox(plans_list_frame, height=6, bg="#333333", fg="#ffffff", selectbackground="#ff0000", font=("Courier New", 10))
        self.power_plans_listbox.pack(side="left", fill="x", expand=True, padx=(0, 5))
        scrollbar = ctk.CTkScrollbar(plans_list_frame, command=self.power_plans_listbox.yview)
        scrollbar.pack(side="right", fill="y")
        self.power_plans_listbox.configure(yscrollcommand=scrollbar.set)
        buttons_frame = ctk.CTkFrame(self.game_scrollable_frame)
        buttons_frame.pack(fill="x", pady=5)
        ctk.CTkButton(buttons_frame, text="Refresh Plans", font=("Courier New", 12, "bold"), fg_color="#333333", hover_color="#444444", command=self.refresh_power_plans).pack(side="left", padx=2, pady=2)
        ctk.CTkButton(buttons_frame, text="Set Active", font=("Courier New", 12, "bold"), fg_color="#333333", hover_color="#444444", command=self.activate_selected_power_plan).pack(side="left", padx=2, pady=2)
        ctk.CTkButton(buttons_frame, text="Delete Plan", font=("Courier New", 12, "bold"), fg_color="#ff0000", hover_color="#cc0000", command=self.delete_selected_power_plan).pack(side="left", padx=2, pady=2)
        ctk.CTkButton(buttons_frame, text="Restore Default", font=("Courier New", 12, "bold"), fg_color="#ff0000", hover_color="#cc0000", command=restore_default_power_plans).pack(side="left", padx=2, pady=2)
        create_plan_frame = ctk.CTkFrame(self.game_scrollable_frame)
        create_plan_frame.pack(fill="x", pady=5, padx=5)
        ctk.CTkLabel(create_plan_frame, text="Create New Power Plan:", font=("Courier New", 12, "bold")).pack(anchor="w", padx=5, pady=5)
        create_input_frame = ctk.CTkFrame(create_plan_frame)
        create_input_frame.pack(fill="x", padx=5, pady=5)
        ctk.CTkLabel(create_input_frame, text="Template:", font=("Courier New", 10)).pack(side="left", padx=5)
        self.template_var = ctk.StringVar(value="Balanced")
        self.template_dropdown = ctk.CTkComboBox(create_input_frame, variable=self.template_var, values=["Balanced", "High Performance", "Power Saver", "Ultimate Performance"], width=150, font=("Courier New", 10), fg_color="#333333", button_color="#333333", button_hover_color="#444444", border_color="#555555")
        self.template_dropdown.pack(side="left", padx=5)
        ctk.CTkLabel(create_input_frame, text="Plan Name:", font=("Courier New", 10)).pack(side="left", padx=(20, 5))
        self.new_plan_name = ctk.CTkEntry(create_input_frame, width=200, font=("Courier New", 10), placeholder_text="Enter new plan name")
        self.new_plan_name.pack(side="left", padx=5, fill="x", expand=True)
        ctk.CTkButton(create_input_frame, text="Create Plan", font=("Courier New", 12, "bold"), fg_color="#333333", hover_color="#444444", command=self.create_power_plan).pack(side="left", padx=5)
        ctk.CTkLabel(self.game_scrollable_frame, text="Program Management", font=("Courier New", 18, "bold"), text_color="#ff0000").pack(pady=10)
        entry_frame = ctk.CTkFrame(self.game_scrollable_frame)
        entry_frame.pack(fill="x", pady=5)
        ctk.CTkLabel(entry_frame, text="Program Name:", font=("Courier New", 12, "bold")).pack(side="left", padx=5)
        self.program_entry = ctk.CTkEntry(entry_frame, width=200, font=("Courier New", 12), placeholder_text="e.g., game.exe")
        self.program_entry.pack(side="left", padx=5, fill="x", expand=True)
        program_buttons_frame = ctk.CTkFrame(self.game_scrollable_frame)
        program_buttons_frame.pack(fill="x", pady=5)
        ctk.CTkButton(program_buttons_frame, text="Add Program", font=("Courier New", 12, "bold"), fg_color="#333333", hover_color="#444444", command=lambda: add_program(self.program_entry, self.game_status_log)).pack(side="left", padx=2)
        ctk.CTkButton(program_buttons_frame, text="Add Directory", font=("Courier New", 12, "bold"), fg_color="#333333", hover_color="#444444", command=lambda: add_directory(self.game_status_log)).pack(side="left", padx=2)
        ctk.CTkButton(program_buttons_frame, text="Load List", font=("Courier New", 12, "bold"), fg_color="#333333", hover_color="#444444", command=lambda: load_program_list(self.game_status_log)).pack(side="left", padx=2)
        ctk.CTkButton(program_buttons_frame, text="Save List", font=("Courier New", 12, "bold"), fg_color="#333333", hover_color="#444444", command=save_program_list).pack(side="left", padx=2)
        ctk.CTkLabel(self.game_scrollable_frame, text="Process Monitoring", font=("Courier New", 18, "bold"), text_color="#ff0000").pack(pady=10)
        monitor_buttons = ctk.CTkFrame(self.game_scrollable_frame)
        monitor_buttons.pack(fill="x", pady=5)
        self.game_progress_bar = ctk.CTkProgressBar(monitor_buttons, orientation="horizontal", width=400, progress_color="#ff0000")
        self.game_progress_bar.pack(fill="x", padx=5, pady=5)
        self.game_progress_bar.set(0)
        ctk.CTkButton(monitor_buttons, text="Start Monitoring", font=("Courier New", 12, "bold"), fg_color="#333333", hover_color="#444444", command=lambda: start_monitoring(self.game_status_log, self.game_progress_bar)).pack(side="left", padx=2, pady=5)
        ctk.CTkButton(monitor_buttons, text="Stop Monitoring", font=("Courier New", 12, "bold"), fg_color="#333333", hover_color="#444444", command=lambda: stop_monitoring(self.game_status_log)).pack(side="left", padx=2, pady=5)
        ctk.CTkButton(monitor_buttons, text="Reset Progress", font=("Courier New", 12, "bold"), fg_color="#333333", hover_color="#444444", command=lambda: reset_progress_bar(self.game_progress_bar)).pack(side="left", padx=2, pady=5)
        ctk.CTkLabel(self.game_scrollable_frame, text="Manual Process Optimization", font=("Courier New", 18, "bold"), text_color="#ff0000").pack(pady=10)
        process_frame = ctk.CTkFrame(self.game_scrollable_frame)
        process_frame.pack(fill="x", pady=5, padx=5)
        self.process_var = ctk.StringVar(value="")
        self.process_dropdown = ctk.CTkComboBox(process_frame, variable=self.process_var, values=get_running_processes(), width=200, font=("Courier New", 12), fg_color="#333333", button_color="#333333", button_hover_color="#444444", border_color="#555555", text_color="#ffffff")
        self.process_dropdown.pack(side="left", padx=5, fill="x", expand=True)
        ctk.CTkButton(process_frame, text="Refresh Processes", font=("Courier New", 12, "bold"), fg_color="#333333", hover_color="#444444", command=self.refresh_processes).pack(side="left", padx=5)
        ctk.CTkLabel(process_frame, text="CPU Cores:", font=("Courier New", 12, "bold")).pack(side="left", padx=(10, 5))
        self.affinity_entry = ctk.CTkEntry(process_frame, width=120, placeholder_text="0,1")
        self.affinity_entry.pack(side="left", padx=5)
        ctk.CTkLabel(process_frame, text="Priority:", font=("Courier New", 12, "bold")).pack(side="left", padx=(10, 5))
        self.priority_var = ctk.StringVar(value="HIGH_PRIORITY_CLASS")
        self.priority_dropdown = ctk.CTkComboBox(process_frame, variable=self.priority_var, values=["IDLE_PRIORITY_CLASS", "NORMAL_PRIORITY_CLASS", "HIGH_PRIORITY_CLASS", "REALTIME_PRIORITY_CLASS"], width=180, fg_color="#333333", button_color="#333333", button_hover_color="#444444", border_color="#555555", text_color="#ffffff")
        self.priority_dropdown.pack(side="left", padx=5)
        process_btn_frame = ctk.CTkFrame(self.game_scrollable_frame)
        process_btn_frame.pack(fill="x", pady=5, padx=5)
        ctk.CTkButton(process_btn_frame, text="Apply Process Optimization", font=("Courier New", 14, "bold"), fg_color="#ff0000", hover_color="#cc0000", command=self.apply_process_optimization).pack(side="left", padx=5)
        ctk.CTkButton(process_btn_frame, text="Remove Process Optimization", font=("Courier New", 14, "bold"), fg_color="#333333", hover_color="#444444", command=self.remove_process_optimization).pack(side="left", padx=5)
        self.game_status_log = ctk.CTkTextbox(self.game_scrollable_frame, height=180, font=("Courier New", 11), text_color="#ffffff", fg_color="#333333")
        self.game_status_log.pack(pady=10, fill="x")
        self.game_status_log.insert("1.0", "Ready for game optimization...\n")
        self.game_status_log.configure(state="disabled")
        self.refresh_power_plans()

    def init_performance_tab(self) -> None:
        tab = self.notebook.tab("Performance Monitor")
        ctk.CTkLabel(tab, text="Performance Monitor", font=("Courier New", 24, "bold"), text_color="#ff0000").pack(pady=20)
        controls = ctk.CTkFrame(tab)
        controls.pack(fill="x", padx=20, pady=10)
        self.performance_status_label = ctk.CTkLabel(controls, text="Ready", font=("Courier New", 12, "bold"))
        self.performance_status_label.pack(side="left", padx=10)
        self.performance_text = ctk.CTkTextbox(tab, height=500, font=("Courier New", 11), text_color="#ffffff", fg_color="#333333")
        self.performance_text.pack(fill="both", expand=True, padx=20, pady=10)
        self.performance_text.insert("1.0", "Ready for performance monitoring...\n")
        self.performance_text.configure(state="disabled")
        ctk.CTkButton(controls, text="Start Monitoring", font=("Courier New", 12, "bold"), fg_color="#333333", hover_color="#444444", command=lambda: start_performance_monitoring(self.performance_status_label, self.performance_text)).pack(side="left", padx=5)
        ctk.CTkButton(controls, text="Stop Monitoring", font=("Courier New", 12, "bold"), fg_color="#333333", hover_color="#444444", command=lambda: stop_performance_monitoring(self.performance_status_label)).pack(side="left", padx=5)
        ctk.CTkButton(controls, text="Test Internet Speed", font=("Courier New", 12, "bold"), fg_color="#333333", hover_color="#444444", command=self.run_speed_test).pack(side="left", padx=5)
        ctk.CTkButton(controls, text="NVIDIA Drivers", font=("Courier New", 12, "bold"), fg_color="#333333", hover_color="#444444", command=open_nvidia_drivers).pack(side="left", padx=5)

    def init_help_tab(self) -> None:
        tab = self.notebook.tab("Help")
        ctk.CTkLabel(tab, text="Help", font=("Courier New", 24, "bold"), text_color="#ff0000").pack(pady=20)
        help_box = ctk.CTkTextbox(tab, font=("Courier New", 12), height=560)
        help_box.pack(fill="both", expand=True, padx=20, pady=10)
        help_box.insert(
            "1.0",
            f"{APP_TITLE} v{APP_VERSION}\n\n"
            "Updated features in this build:\n"
            "• Restore Original DNS now clears manual DNS and switches active adapters back to automatic DNS.\n"
            "• Tools menu now includes Optimize Polling Rate and Revert Polling Rate.\n"
            "• Tools menu now includes Priority Bypasser for restricted priority overrides.\n"
            "• Tools menu now includes Restore Standard Windows Settings for backed-up changes without their own dedicated revert path.\n"
            "• System Optimizer now includes Optimize Appearance Setting, which selects Adjust for best performance in Advanced System Settings.\n\n"
            "Notes:\n"
            "• Game Optimizer tab behavior is unchanged aside from integration stability work.\n"
            "• Performance Monitor tab behavior is unchanged aside from integration stability work.\n"
            "• Some changes may require a reboot or sign-out to fully apply or revert.\n\n"
            "Support:\n"
            "PayPal: https://www.paypal.com/paypalme/robbybarnedt\n",
        )
        help_box.configure(state="disabled")
        btn_frame = ctk.CTkFrame(tab)
        btn_frame.pack(fill="x", padx=20, pady=10)
        ctk.CTkButton(btn_frame, text="Support Developer", font=("Courier New", 12, "bold"), fg_color="#333333", hover_color="#444444", command=open_support_page).pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="Advanced System Info", font=("Courier New", 12, "bold"), fg_color="#ff0000", hover_color="#cc0000", command=show_advanced_system_info).pack(side="left", padx=5)

    def refresh_power_plans(self) -> None:
        self.power_plans_listbox.delete(0, tk.END)
        for plan in get_power_plans():
            display = f"{plan.name} {'ACTIVE' if plan.active else ''}".strip()
            self.power_plans_listbox.insert(tk.END, display)

    def activate_selected_power_plan(self) -> None:
        selection = self.power_plans_listbox.curselection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a power plan first.")
            return
        plans = get_power_plans()
        plan = plans[selection[0]]
        if set_active_power_plan_by_guid(plan.guid):
            self.refresh_power_plans()
            self.game_status_log.configure(state="normal")
            self.game_status_log.insert("end", f"Activated power plan: {plan.name}\n")
            self.game_status_log.configure(state="disabled")
        else:
            messagebox.showerror("Error", f"Failed to activate {plan.name}")

    def delete_selected_power_plan(self) -> None:
        selection = self.power_plans_listbox.curselection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a power plan first.")
            return
        plans = get_power_plans()
        plan = plans[selection[0]]
        if plan.active:
            messagebox.showerror("Error", "Cannot delete the active power plan.")
            return
        if messagebox.askyesno("Confirm Delete", f"Delete power plan '{plan.name}'?"):
            if delete_power_plan_by_guid(plan.guid):
                self.refresh_power_plans()

    def create_power_plan(self) -> None:
        template_name = self.template_var.get()
        new_name = self.new_plan_name.get().strip()
        if not new_name:
            messagebox.showwarning("Warning", "Please enter a name for the new power plan.")
            return
        template_guids = {
            "Balanced": "381b4222-f694-41f0-9685-ff5bb260df2e",
            "High Performance": "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c",
            "Power Saver": "a1841308-3541-4fab-bc81-f71556f20b4a",
            "Ultimate Performance": "e9a42b02-d5df-448d-aa00-03f14749eb61",
        }
        guid = create_power_plan_from_template(template_guids[template_name], new_name)
        if guid:
            self.new_plan_name.delete(0, tk.END)
            self.refresh_power_plans()
        else:
            messagebox.showerror("Error", f"Failed to create power plan: {new_name}")

    def refresh_processes(self) -> None:
        processes = get_running_processes()
        self.process_dropdown.configure(values=processes)
        if processes:
            self.process_var.set(processes[0])

    def apply_process_optimization(self) -> None:
        process_name = self.process_var.get()
        affinity_text = self.affinity_entry.get().strip()
        priority_text = self.priority_var.get()
        if not process_name:
            messagebox.showerror("Error", "Please select a process!")
            return
        cores: list[int] = []
        if affinity_text:
            try:
                cores = [int(v.strip()) for v in affinity_text.split(",") if v.strip()]
            except ValueError:
                messagebox.showerror("Error", "Invalid CPU affinity format. Use comma-separated numbers.")
                return
        priority_map = {
            "IDLE_PRIORITY_CLASS": psutil.IDLE_PRIORITY_CLASS,
            "NORMAL_PRIORITY_CLASS": psutil.NORMAL_PRIORITY_CLASS,
            "HIGH_PRIORITY_CLASS": psutil.HIGH_PRIORITY_CLASS,
            "REALTIME_PRIORITY_CLASS": psutil.REALTIME_PRIORITY_CLASS,
        }
        success_affinity = True if not cores else set_cpu_affinity(process_name, cores)
        success_priority = set_process_priority(process_name, priority_map.get(priority_text, psutil.NORMAL_PRIORITY_CLASS))
        self.game_status_log.configure(state="normal")
        if success_affinity or success_priority:
            self.game_status_log.insert("end", f"Applied optimizations to {process_name}.\n")
        else:
            self.game_status_log.insert("end", f"Failed to apply optimizations to {process_name}.\n")
        self.game_status_log.configure(state="disabled")

    def remove_process_optimization(self) -> None:
        process_name = self.process_var.get()
        if not process_name:
            messagebox.showerror("Error", "Please select a process!")
            return
        cpu_count = os.cpu_count() or 2
        set_cpu_affinity(process_name, list(range(cpu_count)))
        set_process_priority(process_name, psutil.NORMAL_PRIORITY_CLASS)
        self.game_status_log.configure(state="normal")
        self.game_status_log.insert("end", f"Removed optimizations from {process_name}.\n")
        self.game_status_log.configure(state="disabled")

    def clear_and_run(self, command: Callable[[], None]) -> None:
        self.text_box.configure(state="normal")
        self.text_box.delete("1.0", "end")
        self.text_box.configure(state="disabled")
        threading.Thread(target=command, daemon=True).start()

    def run_all(self) -> None:
        functions = list(self.system_function_map.values())
        def worker() -> None:
            for fn in functions:
                try:
                    fn()
                except Exception as exc:
                    update_text_box(f"Error running {fn.__name__}: {exc}")
            update_text_box("All optimizations complete!")
        threading.Thread(target=worker, daemon=True).start()

    def run_preferred(self) -> None:
        selected = [self.system_function_map[text] for text, var in self.system_checkboxes.items() if var.get() and text in self.system_function_map]
        if not selected:
            messagebox.showinfo("Info", "No optimizations selected.")
            return
        def worker() -> None:
            for fn in selected:
                try:
                    fn()
                except Exception as exc:
                    update_text_box(f"Error running {fn.__name__}: {exc}")
            update_text_box("Selected optimizations complete!")
        threading.Thread(target=worker, daemon=True).start()

    def run_speed_test(self) -> None:
        def worker() -> None:
            result = test_internet_speed()
            if result:
                text = "=== Internet Speed Test ===\n\n" + f"Download: {result['download']} Mbps\n" + f"Upload: {result['upload']} Mbps\n" + f"Ping: {result['ping']} ms\n"
            else:
                text = "Internet speed test failed."
            update_performance_text(self.performance_text, text)
            self.performance_status_label.configure(text="Speed test complete")
        self.performance_status_label.configure(text="Running speed test...")
        threading.Thread(target=worker, daemon=True).start()

    def show_debug_message(self, message: str) -> None:
        update_text_box(message)

    def exit_app(self) -> None:
        global performance_monitoring
        performance_monitoring = False
        self.root.destroy()


def main() -> None:
    global app
    root = ctk.CTk()
    try:
        elevate_privileges()
    except SystemExit:
        root.destroy()
        raise
    except Exception as exc:
        logger.error("Startup elevation warning: %s", exc)
    app = App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
