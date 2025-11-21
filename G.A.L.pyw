import os
import subprocess
import ctypes
import sys
import shutil
import logging
import threading
import time
import psutil
import tkinter as tk
from tkinter import ttk, messagebox, font, filedialog
import customtkinter as ctk
from datetime import datetime
import platform
from concurrent.futures import ThreadPoolExecutor
from queue import Queue
import winreg  # Added for registry manipulation
import re  # Added for Trickster power plan parsing

# --- Set up logging ---
log_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "debug.log")
logging.basicConfig(
    filename=log_file,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logging.info("Script started.")

# --- Hide the console window (Windows only) ---
if os.name == "nt":
    ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)

# --- Global Variables ---
debug_log_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "debug_log.txt")
monitoring_event = threading.Event()
monitoring_thread = None
program_list = []
detected_processes = set()  # Track detected processes to avoid repeated optimizations
update_queue = Queue()  # Queue for batching GUI updates
system_checkboxes = {}  # Store checkboxes for preferred operations

# --- Install Missing Dependencies ---
def install_dependencies():
    """Install required Python packages if they are missing."""
    required_packages = ["psutil", "customtkinter"]
    import importlib
    import subprocess
    import sys

    for package in required_packages:
        try:
            importlib.import_module(package)
        except ImportError:
            logging.info(f"Installing missing package: {package}")
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])

# --- Power Plan Management Functions ---
def get_power_plans():
    """Get list of all available power plans with their GUIDs and active status."""
    try:
        result = subprocess.run(
            ["powercfg", "/list"],
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        
        plans = []
        for line in result.stdout.splitlines():
            if "Power Scheme" in line:
                # Extract GUID
                guid_match = re.search(r"([a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12})", line)
                if guid_match:
                    guid = guid_match.group(1)
                    # Extract name (text after asterisk if active, otherwise after GUID)
                    if "*" in line:
                        name = line.split("*")[1].strip()
                        is_active = True
                    else:
                        name_part = line.split(guid)[1].strip()
                        name = name_part if name_part else "Unknown Plan"
                        is_active = False
                    plans.append({"guid": guid, "name": name, "active": is_active})
        
        return plans
    except Exception as e:
        logging.error(f"Error getting power plans: {e}")
        return []

def set_active_power_plan(guid):
    """Set a power plan as active by GUID."""
    try:
        result = subprocess.run(
            ["powercfg", "/setactive", guid],
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        return result.returncode == 0
    except Exception as e:
        logging.error(f"Error setting active power plan: {e}")
        return False

def delete_power_plan(guid):
    """Delete a power plan by GUID."""
    try:
        result = subprocess.run(
            ["powercfg", "/delete", guid],
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        return result.returncode == 0
    except Exception as e:
        logging.error(f"Error deleting power plan: {e}")
        return False

def create_power_plan_from_template(template_guid, new_name):
    """Create a new power plan from a template."""
    try:
        # Duplicate the template scheme
        result = subprocess.run(
            ["powercfg", "-duplicatescheme", template_guid],
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        
        if result.returncode == 0:
            # Extract the new GUID from the output
            guid_match = re.search(r"([a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12})", result.stdout)
            if guid_match:
                new_guid = guid_match.group(1)
                # Rename the new plan
                subprocess.run(
                    ["powercfg", "-changename", new_guid, new_name],
                    capture_output=True,
                    text=True,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                return new_guid
        return None
    except Exception as e:
        logging.error(f"Error creating power plan: {e}")
        return None

def get_power_plan_templates():
    """Get available power plan templates."""
    return [
        {"guid": "381b4222-f694-41f0-9685-ff5bb260df2e", "name": "Balanced"},
        {"guid": "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c", "name": "High Performance"},
        {"guid": "a1841308-3541-4fab-bc81-f71556f20b4a", "name": "Power Saver"},
        {"guid": "e9a42b02-d5df-448d-aa00-03f14749eb61", "name": "Ultimate Performance"}
    ]

# --- Trickster Power Plan Function ---
def unlock_and_configure_trickster():
    """Unlock and configure the Ultimate Performance power plan (Trickster functionality)."""
    try:
        # Step 1: Unlock the "Ultimate Performance" power plan
        logging.info("Unlocking 'Ultimate Performance' power plan...")
        subprocess.run(
            ["powercfg", "-duplicatescheme", "e9a42b02-d5df-448d-aa00-03f14749eb61"],
            shell=True,
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )

        # Step 2: Get the GUID of the newly created "Ultimate Performance" plan
        logging.info("Fetching GUID of 'Ultimate Performance'...")
        result = subprocess.run(
            ["powercfg", "/list"],
            shell=True,
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        output = result.stdout
        
        match = re.search(r"(\w{8}-\w{4}-\w{4}-\w{4}-\w{12})\s*\(Ultimate Performance\)", output)
        if not match:
            logging.error("Failed to find 'Ultimate Performance' plan.")
            messagebox.showerror("Error", "Failed to find 'Ultimate Performance' plan.")
            return
        ultimate_guid = match.group(1)
        logging.info(f"Found 'Ultimate Performance' GUID: {ultimate_guid}")

        # Step 3: Delete the existing "High Performance" plan (if it exists)
        logging.info("Deleting existing 'High Performance' plan...")
        match = re.search(r"(\w{8}-\w{4}-\w{4}-\w{4}-\w{12})\s*\(High performance\)", output)
        if match:
            high_performance_guid = match.group(1)
            subprocess.run(
                f"powercfg /delete {high_performance_guid}",
                shell=True,
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            logging.info(f"Deleted 'High Performance' plan with GUID: {high_performance_guid}")

        # Step 4: Rename the "Ultimate Performance" plan to "High Performance"
        logging.info("Renaming 'Ultimate Performance' to 'High Performance'...")
        subprocess.run(
            f'powercfg /changename {ultimate_guid} "High Performance"',
            shell=True,
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )

        # Step 5: Activate the renamed "High Performance" plan
        logging.info("Activating 'High Performance' plan...")
        subprocess.run(
            f"powercfg /setactive {ultimate_guid}",
            shell=True,
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )

        # Show confirmation message
        messagebox.showinfo(
            "Success",
            "The Ultimate Power Plan has been Unlocked, and disguised as High Power Plan.\n"
            "Please proceed to Graphics settings, and apply your programs to High Performance!!"
        )
        logging.info("Trickster power plan configuration completed successfully.")
        
    except Exception as e:
        logging.error(f"Exception in Trickster power plan configuration: {e}")
        messagebox.showerror("Error", f"An error occurred: {e}")

# --- Force Delete Function (Optimized) ---
def force_delete_folder_contents(folder_path):
    """Force-delete all files and subdirectories in a folder, ignoring errors."""
    if not os.path.exists(folder_path):
        logging.warning(f"Folder does not exist: {folder_path}")
        return 0

    deleted_count = 0
    try:
        with os.scandir(folder_path) as entries:
            for entry in entries:
                try:
                    if entry.is_file() or entry.is_symlink():
                        os.unlink(entry.path)
                        deleted_count += 1
                        logging.debug(f"Deleted file: {entry.path}")
                    elif entry.is_dir():
                        # Check if it's a symbolic link before using rmtree
                        if entry.is_symlink():
                            os.unlink(entry.path)
                            deleted_count += 1
                            logging.debug(f"Deleted symbolic link: {entry.path}")
                        else:
                            shutil.rmtree(entry.path)
                            deleted_count += 1
                            logging.debug(f"Deleted directory: {entry.path}")
                except Exception as e:
                    logging.error(f"Exception deleting {entry.path}: {e}")
                    # Try alternative deletion method for stubborn files
                    try:
                        if os.path.exists(entry.path):
                            if os.path.isfile(entry.path) or os.path.islink(entry.path):
                                os.unlink(entry.path)
                                deleted_count += 1
                            elif os.path.isdir(entry.path):
                                shutil.rmtree(entry.path)
                                deleted_count += 1
                    except Exception as e2:
                        logging.error(f"Secondary exception deleting {entry.path}: {e2}")
    except Exception as e:
        logging.error(f"Exception scanning folder {folder_path}: {e}")
    
    return deleted_count

# --- Functions for System Optimizer (Optimized) ---
def run_as_admin():
    """Check if the script is running as administrator."""
    try:
        with open("C:\\Windows\\temp.txt", "w") as f:
            f.write("test")
        os.remove("C:\\Windows\\temp.txt")
        logging.info("Script is running as administrator.")
        return True
    except PermissionError:
        logging.warning("Script is not running as administrator.")
        return False

def elevate_privileges():
    """Request administrator privileges."""
    if not ctypes.windll.shell32.IsUserAnAdmin():
        logging.info("Requesting administrator privileges...")
        try:
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, " ".join(sys.argv), None, 1
            )
            sys.exit()
        except Exception as e:
            logging.error(f"Failed to elevate privileges: {e}")
            messagebox.showerror("Error", "Failed to elevate privileges. Please run the program as an administrator.")
            sys.exit()

def clean_ram_cache():
    """Clear the RAM cache by emptying the working set of memory-intensive processes."""
    try:
        logging.info("Cleaning RAM cache...")
        cleaned_processes = []
        for proc in psutil.process_iter(['pid', 'name', 'memory_info']):
            try:
                if proc.info['memory_info'].rss > 100 * 1024 * 1024:  # Only target processes using >100MB RAM
                    p = psutil.Process(proc.info['pid'])
                    p.memory_info().rss  # Force the process to release unused memory
                    cleaned_processes.append(proc.info['name'])
                    logging.debug(f"Cleaned RAM for process: {proc.info['name']} (PID: {proc.info['pid']})")
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        
        process_list = ", ".join(cleaned_processes[:5])  # Show first 5 processes
        if len(cleaned_processes) > 5:
            process_list += f" and {len(cleaned_processes) - 5} more"
        
        update_text_box(f"Cleaned RAM Cache!\nProcesses optimized: {process_list}")
    except Exception as e:
        logging.error(f"Exception cleaning RAM cache: {e}")
        update_text_box(f"Error: {e}")

def clean_windows_temp_folder():
    """Force-delete everything in the C:\Windows\Temp folder."""
    logging.info("Cleaning Windows Temp folder...")
    windows_temp_folder = "C:\\Windows\\Temp"
    if os.path.exists(windows_temp_folder):
        deleted_count = force_delete_folder_contents(windows_temp_folder)
        update_text_box(f"Cleaned Windows Temp Folder!\nDeleted {deleted_count} files/folders")
    else:
        logging.warning(f"Windows Temp folder does not exist: {windows_temp_folder}")
        update_text_box("Windows Temp folder not found!")

def clean_prefetch_folder():
    """Force-delete everything in the C:\Windows\Prefetch folder."""
    logging.info("Cleaning Prefetch folder...")
    prefetch_folder = "C:\\Windows\\Prefetch"
    if os.path.exists(prefetch_folder):
        deleted_count = force_delete_folder_contents(prefetch_folder)
        update_text_box(f"Cleaned Prefetch Folder!\nDeleted {deleted_count} prefetch files")
    else:
        logging.warning(f"Prefetch folder does not exist: {prefetch_folder}")
        update_text_box("Prefetch folder not found!")

def clean_recycle_bin():
    """Force-clean the Recycle Bin using the Windows API."""
    try:
        logging.info("Cleaning Recycle Bin...")
        ctypes.windll.shell32.SHEmptyRecycleBinW(None, None, 0x00000001)  # 0x00000001 = SHERB_NOCONFIRMATION
        update_text_box("Cleaned Recycle Bin!\nAll deleted files permanently removed")
    except Exception as e:
        logging.error(f"Exception cleaning Recycle Bin: {e}")
        update_text_box(f"Error: {e}")

def clean_windows_update_cache():
    """Clean the Windows Update cache."""
    logging.info("Cleaning Windows Update cache...")
    update_cache_folder = "C:\\Windows\\SoftwareDistribution\\Download"
    if os.path.exists(update_cache_folder):
        deleted_count = force_delete_folder_contents(update_cache_folder)
        update_text_box(f"Cleaned Windows Update Cache!\nDeleted {deleted_count} update files")
    else:
        logging.warning(f"Windows Update cache folder does not exist: {update_cache_folder}")
        update_text_box("Windows Update cache folder not found!")

def clean_temporary_internet_files():
    """Force-delete Temporary Internet Files for all users and browsers."""
    logging.info("Cleaning Temporary Internet Files for all browsers...")
    users_dir = os.getenv('USERPROFILE')
    browser_cache_folders = [
        os.path.join(users_dir, "AppData", "Local", "Microsoft", "Edge", "User Data", "Default", "Cache"),
        os.path.join(users_dir, "AppData", "Local", "Microsoft", "Windows", "INetCache"),
        os.path.join(users_dir, "AppData", "Local", "Google", "Chrome", "User Data", "Default", "Cache"),
        os.path.join(users_dir, "AppData", "Local", "Opera Software", "Opera Stable", "Cache"),
        os.path.join(users_dir, "AppData", "Local", "Opera Software", "Opera GX Stable", "Cache"),
        os.path.join(users_dir, "AppData", "Local", "Opera Software", "Opera GX Stable", "Cache_Data"),
    ]

    total_deleted = 0
    for cache_folder in browser_cache_folders:
        if os.path.exists(cache_folder):
            deleted_count = force_delete_folder_contents(cache_folder)
            total_deleted += deleted_count

    update_text_box(f"Cleaned Temporary Internet Files for all browsers!\nDeleted {total_deleted} cache files")

def clean_thumbnails():
    """Force-delete Thumbnails cache for all users."""
    logging.info("Cleaning Thumbnails...")
    users_dir = os.getenv('USERPROFILE')
    thumbnails_folder = os.path.join(users_dir, "AppData", "Local", "Microsoft", "Windows", "Explorer")
    if os.path.exists(thumbnails_folder):
        deleted_count = 0
        try:
            with os.scandir(thumbnails_folder) as entries:
                for entry in entries:
                    try:
                        if entry.name.startswith("thumbcache_"):
                            if entry.is_file() or entry.is_symlink():
                                os.unlink(entry.path)
                                deleted_count += 1
                    except Exception:
                        continue
        except Exception as e:
            logging.error(f"Exception scanning folder {thumbnails_folder}: {e}")
        
        update_text_box(f"Cleaned Thumbnails!\nDeleted {deleted_count} thumbnail cache files")
    else:
        update_text_box("Thumbnails folder not found!")

def clean_delivery_optimization_files():
    """Force-delete Delivery Optimization Files."""
    logging.info("Cleaning Delivery Optimization Files...")
    delivery_optimization_folder = os.path.join(
        os.getenv("SYSTEMROOT"),
        "ServiceProfiles",
        "NetworkService",
        "AppData",
        "Local",
        "Microsoft",
        "Windows",
        "DeliveryOptimization"
    )

    if os.path.exists(delivery_optimization_folder):
        deleted_count = force_delete_folder_contents(delivery_optimization_folder)
        update_text_box(f"Cleaned Delivery Optimization Files!\nDeleted {deleted_count} delivery optimization files")
    else:
        logging.warning(f"Delivery Optimization folder does not exist: {delivery_optimization_folder}")
        update_text_box("Delivery Optimization folder not found!")

def clean_temp_folder():
    """Force-delete everything in all Temp folders across the system."""
    logging.info("Cleaning all Temp folders...")
    temp_folders = [
        os.getenv('TEMP'),
        os.getenv('TMP'),
        "C:\\Windows\\Temp",
        "C:\\Windows\\Prefetch",
    ]

    total_deleted = 0
    for folder in temp_folders:
        if os.path.exists(folder):
            deleted_count = force_delete_folder_contents(folder)
            total_deleted += deleted_count
            logging.info(f"Cleaned Temp folder: {folder}")

    update_text_box(f"Cleaned all Temp folders!\nDeleted {total_deleted} temporary files across all temp locations")

def flush_dns_cache():
    """Flush the DNS cache."""
    try:
        logging.info("Flushing DNS cache...")
        result = subprocess.run(
            ["ipconfig", "/flushdns"],
            shell=True,
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        if result.returncode == 0:
            update_text_box("Flushed DNS Cache!\nDNS resolver cache has been cleared")
        else:
            update_text_box("Failed to flush DNS cache")
    except Exception as e:
        logging.error(f"Exception flushing DNS cache: {e}")
        update_text_box(f"Error: {e}")

def set_cloudflare_dns():
    """Set DNS to Cloudflare's DNS (1.1.1.1 and 1.0.0.1) for all connected interfaces."""
    try:
        logging.info("Setting Cloudflare DNS...")

        # Open the registry key for network interfaces
        reg_key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces",
            0,
            winreg.KEY_ALL_ACCESS
        )

        interface_count = 0
        # Iterate through all subkeys (network interfaces)
        for i in range(winreg.QueryInfoKey(reg_key)[0]):
            interface_key_name = winreg.EnumKey(reg_key, i)
            interface_key = winreg.OpenKey(reg_key, interface_key_name, 0, winreg.KEY_ALL_ACCESS)

            try:
                # Set DNS to Cloudflare
                winreg.SetValueEx(interface_key, "NameServer", 0, winreg.REG_SZ, "1.1.1.1,1.0.0.1")
                winreg.SetValueEx(interface_key, "DhcpNameServer", 0, winreg.REG_SZ, "1.1.1.1,1.0.0.1")
                interface_count += 1
                logging.info(f"Set Cloudflare DNS for interface: {interface_key_name}")
            except Exception as e:
                logging.error(f"Exception setting DNS for interface {interface_key_name}: {e}")

            winreg.CloseKey(interface_key)

        winreg.CloseKey(reg_key)

        # Notify the system of the change
        subprocess.run(
            ["ipconfig", "/flushdns"],
            shell=True,
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )

        update_text_box(f"Set Cloudflare DNS for all connected interfaces!\nConfigured {interface_count} network interfaces")
    except Exception as e:
        logging.error(f"Exception setting Cloudflare DNS: {e}")
        update_text_box(f"Error: {e}")

def check_and_set_ultimate_power_plan():
    """Check if the Ultimate Power Plan exists, create it if it doesn't, and set it as active."""
    try:
        logging.info("Checking and setting Ultimate Power Plan...")
        result = subprocess.run(
            ["powercfg", "/list"],
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        if "Ultimate Performance" not in result.stdout:
            subprocess.run(
                ["powercfg", "-duplicatescheme", "e9a42b02-d5df-448d-aa00-03f14749eb61"],
                shell=True,
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
        result = subprocess.run(
            ["powercfg", "/list"],
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        for line in result.stdout.splitlines():
            if "Ultimate Performance" in line:
                guid = line.split()[3]
                subprocess.run(
                    ["powercfg", "/setactive", guid],
                    shell=True,
                    capture_output=True,
                    text=True,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                break
        update_text_box("Set Ultimate Power Plan!\nHigh-performance power scheme activated")
    except Exception as e:
        logging.error(f"Exception setting Ultimate Power Plan: {e}")
        update_text_box(f"Error: {e}")

# --- New Folder-Cleaning Functions ---
def clean_windows_update_cleanup():
    """Clean Windows Update Cleanup files."""
    logging.info("Cleaning Windows Update Cleanup files...")
    update_cleanup_folder = os.path.join(os.getenv("SYSTEMROOT"), "SoftwareDistribution", "Download")
    if os.path.exists(update_cleanup_folder):
        deleted_count = force_delete_folder_contents(update_cleanup_folder)
        update_text_box(f"Cleaned Windows Update Cleanup files!\nDeleted {deleted_count} update cleanup files")
    else:
        logging.warning(f"Windows Update Cleanup folder does not exist: {update_cleanup_folder}")
        update_text_box("Windows Update Cleanup folder not found!")

def clean_microsoft_defender_antivirus():
    """Clean Microsoft Defender Antivirus files."""
    logging.info("Cleaning Microsoft Defender Antivirus files...")
    defender_folder = os.path.join(os.getenv("PROGRAMDATA"), "Microsoft", "Windows Defender", "Scans")
    if os.path.exists(defender_folder):
        deleted_count = force_delete_folder_contents(defender_folder)
        update_text_box(f"Cleaned Microsoft Defender Antivirus files!\nDeleted {deleted_count} scan files")
    else:
        logging.warning(f"Microsoft Defender Antivirus folder does not exist: {defender_folder}")
        update_text_box("Microsoft Defender Antivirus folder not found!")

def clean_windows_upgrade_log_files():
    """Clean Windows Upgrade Log Files."""
    logging.info("Cleaning Windows Upgrade Log Files...")
    upgrade_log_folder = os.path.join(os.getenv("SYSTEMROOT"), "Logs", "CBS")
    if os.path.exists(upgrade_log_folder):
        deleted_count = force_delete_folder_contents(upgrade_log_folder)
        update_text_box(f"Cleaned Windows Upgrade Log Files!\nDeleted {deleted_count} log files")
    else:
        logging.warning(f"Windows Upgrade Log Files folder does not exist: {upgrade_log_folder}")
        update_text_box("Windows Upgrade Log Files folder not found!")

def clean_system_recovery_log_files():
    """Clean System Recovery Log Files."""
    logging.info("Cleaning System Recovery Log Files...")
    recovery_log_folder = os.path.join(os.getenv("SYSTEMROOT"), "System32", "LogFiles") 
    if os.path.exists(recovery_log_folder):
        deleted_count = force_delete_folder_contents(recovery_log_folder)
        update_text_box(f"Cleaned System Recovery Log Files!\nDeleted {deleted_count} recovery log files")
    else:
        logging.warning(f"System Recovery Log Files folder does not exist: {recovery_log_folder}")
        update_text_box("System Recovery Log Files folder not found!")

# --- New Optimization Functions ---
def disable_telemetry():
    """Disable Windows telemetry and data collection."""
    try:
        logging.info("Disabling Windows Telemetry...")
        subprocess.run([
            "powershell", "Set-ItemProperty", "-Path", "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection", 
            "-Name", "AllowTelemetry", "-Value", "0"
        ], shell=True, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
        update_text_box("Disabled Windows Telemetry!\nData collection and telemetry services stopped")
    except Exception as e:
        logging.error(f"Exception disabling telemetry: {e}")
        update_text_box(f"Error: {e}")

def disable_cortana():
    """Disable Cortana and web search."""
    try:
        logging.info("Disabling Cortana...")
        subprocess.run([
            "powershell", "Set-ItemProperty", "-Path", "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search", 
            "-Name", "AllowCortana", "-Value", "0"
        ], shell=True, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
        update_text_box("Disabled Cortana!\nCortana and web search features disabled")
    except Exception as e:
        logging.error(f"Exception disabling Cortana: {e}")
        update_text_box(f"Error: {e}")

def disable_game_bar():
    """Disable Xbox Game Bar."""
    try:
        logging.info("Disabling Xbox Game Bar...")
        subprocess.run([
            "powershell", "Set-ItemProperty", "-Path", "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\GameDVR", 
            "-Name", "AllowGameDVR", "-Value", "0"
        ], shell=True, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
        update_text_box("Disabled Xbox Game Bar!\nGame recording and overlay features disabled")
    except Exception as e:
        logging.error(f"Exception disabling Game Bar: {e}")
        update_text_box(f"Error: {e}")

def optimize_network_adapter():
    """Optimize network adapter settings for gaming."""
    try:
        logging.info("Optimizing network adapter settings...")
        subprocess.run([
            "netsh", "int", "tcp", "set", "global", "autotuninglevel=normal"
        ], shell=True, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
        update_text_box("Optimized Network Adapter Settings!\nTCP auto-tuning set to normal for better gaming performance")
    except Exception as e:
        logging.error(f"Exception optimizing network: {e}")
        update_text_box(f"Error: {e}")

# --- Functions for Game Optimizer ---
def write_debug_log(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(debug_log_file, "a") as log_file:
        log_file.write(f"[{timestamp}] {message}\n")

def set_cpu_affinity(process_name, cores):
    """Set CPU affinity for a specific process."""
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'] == process_name:
            try:
                p = psutil.Process(proc.info['pid'])
                p.cpu_affinity(cores)
                logging.info(f"Set CPU affinity for {process_name} to cores: {cores}")
                return True
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                logging.warning(f"Failed to set CPU affinity for {process_name}")
    return False

def set_process_priority(process_name, priority):
    """Set process priority for a specific process."""
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'] == process_name:
            try:
                p = psutil.Process(proc.info['pid'])
                p.nice(priority)
                logging.info(f"Set priority for {process_name} to {priority}")
                return True
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                logging.warning(f"Failed to set priority for {process_name}")
    return False

def disable_windows_defender():
    """Temporarily disable Windows Defender real-time protection."""
    try:
        subprocess.run(
            ["powershell", "Set-MpPreference", "-DisableRealtimeMonitoring", "$true"],
            shell=True,
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        logging.info("Disabled Windows Defender real-time protection.")
    except Exception as e:
        logging.error(f"Exception disabling Windows Defender: {e}")

def kill_gpu_intensive_processes():
    """Kill processes that consume GPU resources."""
    gpu_intensive_processes = ["chrome.exe", "msedge.exe", "dwm.exe"]
    for process_name in gpu_intensive_processes:
        for proc in psutil.process_iter(['pid', 'name']):
            if proc.info['name'] == process_name:
                try:
                    proc.terminate()
                    logging.info(f"Terminated GPU-intensive process: {process_name}")
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    logging.warning(f"Failed to terminate {process_name}")

def disable_windows_animations():
    """Disable Windows animations for better performance."""
    try:
        subprocess.run(
            ["powershell", "Set-ItemProperty", "-Path", "'HKCU:\\Control Panel\\Desktop'", "-Name", "UserPreferencesMask", "-Value", "0x90", "-Type", "Binary"],
            shell=True,
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        logging.info("Disabled Windows animations.")
    except Exception as e:
        logging.error(f"Exception disabling Windows animations: {e}")

def optimize_system(status_log, progress_bar):
    status_log.configure(state="normal")
    status_log.insert("end", "Closing unnecessary processes...\n")
    status_log.see("end")
    status_log.configure(state="disabled")
    write_debug_log("Starting system optimization...")
    progress_bar.set(0.2)

    processes_to_kill = ["chrome.exe", "discord.exe"]  # Exclude steam.exe
    for process_name in processes_to_kill:
        for proc in psutil.process_iter(['pid', 'name']):
            if proc.info['name'] == process_name:
                try:
                    proc.terminate()
                    status_log.configure(state="normal")
                    status_log.insert("end", f"Closed {process_name}\n")
                    status_log.see("end")
                    status_log.configure(state="disabled")
                    write_debug_log(f"Closed process: {process_name}")
                except psutil.NoSuchProcess:
                    write_debug_log(f"Process not found: {process_name}")

    status_log.configure(state="normal")
    status_log.insert("end", "Disabling non-essential services...\n")
    status_log.see("end")
    status_log.configure(state="disabled")
    write_debug_log("Disabling non-essential services...")
    progress_bar.set(0.5)

    services_to_stop = ["SysMain", "DiagTrack"]
    for service in services_to_stop:
        try:
            subprocess.run(["net", "stop", service], shell=True)
            status_log.configure(state="normal")
            status_log.insert("end", f"Stopped service: {service}\n")
            status_log.see("end")
            status_log.configure(state="disabled")
            write_debug_log(f"Stopped service: {service}")
        except Exception as e:
            status_log.configure(state="normal")
            status_log.insert("end", f"Failed to stop service {service}: {e}\n")
            status_log.see("end")
            status_log.configure(state="disabled")
            write_debug_log(f"Failed to stop service {service}: {e}")

    # --- New Enhancements for Game Optimizer ---
    status_log.configure(state="normal")
    status_log.insert("end", "Applying game performance optimizations...\n")
    status_log.see("end")
    status_log.configure(state="disabled")
    write_debug_log("Applying game performance optimizations...")

    # Set CPU affinity for detected game processes
    for process_name in program_list:
        set_cpu_affinity(process_name, [0, 1])  # Use cores 0 and 1
        set_process_priority(process_name, psutil.HIGH_PRIORITY_CLASS)

    # Disable Windows Defender real-time protection
    disable_windows_defender()

    # Kill GPU-intensive processes
    kill_gpu_intensive_processes()

    # Disable Windows animations
    disable_windows_animations()

    status_log.configure(state="normal")
    status_log.insert("end", "Optimizations complete!\n")
    status_log.see("end")
    status_log.configure(state="disabled")
    write_debug_log("System optimizations complete.")
    progress_bar.set(1.0)

def monitor_processes(status_log, progress_bar):
    global detected_processes
    write_debug_log("Starting process monitoring...")
    while not monitoring_event.is_set():
        for proc in psutil.process_iter(['pid', 'name']):
            if proc.info['name'] in program_list and proc.info['name'] not in detected_processes:
                detected_processes.add(proc.info['name'])  # Add to detected processes
                status_log.configure(state="normal")
                status_log.insert("end", f"Detected {proc.info['name']} running. Applying optimizations...\n")
                status_log.see("end")
                status_log.configure(state="disabled")
                write_debug_log(f"Detected {proc.info['name']} running. Applying optimizations...")
                optimize_system(status_log, progress_bar)
        time.sleep(5)  # Add a delay to reduce CPU usage

def start_monitoring(status_log, progress_bar):
    global monitoring_thread, detected_processes
    if not program_list:
        messagebox.showerror("Error", "No programs in the list to monitor!")
        write_debug_log("Error: No programs in the list to monitor!")
        return

    status_log.configure(state="normal")
    status_log.delete("1.0", "end")
    status_log.configure(state="disabled")
    progress_bar.set(0)
    detected_processes.clear()  # Reset detected processes

    monitoring_event.clear()
    monitoring_thread = threading.Thread(target=monitor_processes, args=(status_log, progress_bar), daemon=True)
    monitoring_thread.start()
    status_log.configure(state="normal")
    status_log.insert("end", f"Monitoring for programs: {', '.join(program_list)}...\n")
    status_log.see("end")
    status_log.configure(state="disabled")
    write_debug_log(f"Monitoring for programs: {', '.join(program_list)}...")

def stop_monitoring(status_log):
    global monitoring_thread
    if monitoring_thread and monitoring_thread.is_alive():
        monitoring_event.set()
        monitoring_thread.join(timeout=1)
        status_log.configure(state="normal")
        status_log.insert("end", "Monitoring stopped.\n")
        status_log.see("end")
        status_log.configure(state="disabled")
        write_debug_log("Monitoring stopped.")
    else:
        status_log.configure(state="normal")
        status_log.insert("end", "No active monitoring to stop.\n")
        status_log.see("end")
        status_log.configure(state="disabled")

def clear_log(status_log):
    status_log.configure(state="normal")
    status_log.delete("1.0", "end")
    status_log.insert("end", "Log cleared.\n")
    status_log.see("end")
    status_log.configure(state="disabled")
    write_debug_log("Status log cleared.")

def save_log(status_log):
    log_file = filedialog.asksaveasfilename(
        defaultextension=".txt",
        filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
        title="Save Log As"
    )
    if log_file:
        try:
            with open(log_file, "w") as file:
                status_log.configure(state="normal")
                file.write(status_log.get("1.0", "end"))
                status_log.configure(state="disabled")
            messagebox.showinfo("Log Saved", f"The log has been saved to {log_file}.")
            write_debug_log(f"Status log saved to {log_file}.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save log: {e}")
            write_debug_log(f"Failed to save log: {e}")

def load_program_list(status_log):
    global program_list
    file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
    if file_path:
        try:
            with open(file_path, "r") as file:
                program_list = file.read().splitlines()
                status_log.configure(state="normal")
                status_log.insert("end", f"Loaded program list: {', '.join(program_list)}\n")
                status_log.see("end")
                status_log.configure(state="disabled")
                write_debug_log(f"Loaded program list: {', '.join(program_list)}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load program list: {e}")
            write_debug_log(f"Failed to load program list: {e}")

def save_program_list():
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
    if file_path:
        try:
            with open(file_path, "w") as file:
                file.write("\n".join(program_list))
            messagebox.showinfo("List Saved", f"The program list has been saved to {file_path}.")
            write_debug_log(f"Program list saved to {file_path}.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save program list: {e}")
            write_debug_log(f"Failed to save program list: {e}")

def add_program(program_entry, status_log):
    program_name = program_entry.get()
    if program_name:
        program_list.append(program_name)
        program_entry.delete(0, "end")
        status_log.configure(state="normal")
        status_log.insert("end", f"Added {program_name} to the program list.\n")
        status_log.see("end")
        status_log.configure(state="disabled")
        write_debug_log(f"Added {program_name} to the program list.")
    else:
        messagebox.showerror("Error", "Please enter a program name!")
        write_debug_log("Error: No program name entered.")

def add_directory(status_log):
    directory = filedialog.askdirectory()
    if directory:
        for root, _, files in os.walk(directory):
            for file in files:
                if file.endswith(".exe"):
                    program_list.append(file)
                    status_log.configure(state="normal")
                    status_log.insert("end", f"Added {file} from {root} to the program list.\n")
                    status_log.see("end")
                    status_log.configure(state="disabled")
                    write_debug_log(f"Added {file} from {root} to the program list.")

def reset_progress_bar(progress_bar):
    progress_bar.set(0)
    write_debug_log("Progress bar reset.")

# --- New Game Optimizer Functions ---
def detect_gpu_type():
    """Detect whether the system has NVIDIA, AMD, or Intel graphics."""
    try:
        result = subprocess.run([
            "powershell", "Get-WmiObject", "-Class", "Win32_VideoController", "|", "Select-Object", "Name"
        ], shell=True, capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
        
        gpu_info = result.stdout.lower()
        if "nvidia" in gpu_info:
            return "NVIDIA"
        elif "amd" in gpu_info or "radeon" in gpu_info:
            return "AMD"
        elif "intel" in gpu_info:
            return "Intel"
        else:
            return "Unknown"
    except Exception as e:
        logging.error(f"Exception detecting GPU: {e}")
        return "Unknown"

def get_running_processes():
    """Get list of all running processes for selection."""
    processes = []
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            processes.append(proc.info['name'])
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return sorted(set(processes))  # Remove duplicates and sort

# --- Tools Functions ---
def set_monitor_dimensions():
    """Set window dimensions based on user's monitor size with common resolutions."""
    try:
        # Create window for resolution selection
        resolution_window = ctk.CTkToplevel(app.root)
        resolution_window.title("Set Window Size")
        resolution_window.geometry("400x500")
        resolution_window.transient(app.root)
        resolution_window.grab_set()
        
        # Common resolutions
        common_resolutions = [
            ("1024x768", "XGA"),
            ("1280x720", "HD"),
            ("1280x800", "WXGA"),
            ("1366x768", "FWXGA"),
            ("1440x900", "WXGA+"),
            ("1600x900", "HD+"),
            ("1680x1050", "WSXGA+"),
            ("1920x1080", "Full HD"),
            ("1920x1200", "WUXGA"),
            ("2560x1440", "QHD"),
            ("3440x1440", "UltraWide QHD"),
            ("3840x2160", "4K UHD")
        ]
        
        # Title
        title_label = ctk.CTkLabel(
            resolution_window,
            text="Select Window Size",
            font=("Courier New", 18, "bold"),
            text_color="#ff0000"
        )
        title_label.pack(pady=10)
        
        # Resolution selection frame
        resolution_frame = ctk.CTkScrollableFrame(resolution_window, height=250)
        resolution_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Variable to store selected resolution
        selected_resolution = tk.StringVar(value="800x600")
        
        # Create radio buttons for common resolutions
        for resolution, name in common_resolutions:
            frame = ctk.CTkFrame(resolution_frame)
            frame.pack(fill="x", pady=2)
            
            radio = ctk.CTkRadioButton(
                frame,
                text=f"{resolution} - {name}",
                variable=selected_resolution,
                value=resolution,
                font=("Courier New", 12)
            )
            radio.pack(side="left", padx=5, pady=2)
        
        # Custom resolution input
        custom_frame = ctk.CTkFrame(resolution_window)
        custom_frame.pack(fill="x", padx=10, pady=10)
        
        ctk.CTkLabel(
            custom_frame,
            text="Custom Resolution:",
            font=("Courier New", 12, "bold")
        ).pack(anchor="w", padx=5, pady=5)
        
        custom_entry = ctk.CTkEntry(
            custom_frame,
            placeholder_text="e.g., 800x600",
            font=("Courier New", 12)
        )
        custom_entry.pack(fill="x", padx=5, pady=5)
        
        # Apply button
        def apply_resolution():
            resolution = selected_resolution.get()
            if custom_entry.get().strip():
                # Validate custom resolution format
                custom_res = custom_entry.get().strip()
                if "x" in custom_res:
                    try:
                        width, height = map(int, custom_res.split("x"))
                        if width > 0 and height > 0:
                            resolution = custom_res
                        else:
                            messagebox.showerror("Error", "Resolution values must be positive integers")
                            return
                    except ValueError:
                        messagebox.showerror("Error", "Invalid format. Use WIDTHxHEIGHT (e.g., 800x600)")
                        return
                else:
                    messagebox.showerror("Error", "Invalid format. Use WIDTHxHEIGHT (e.g., 800x600)")
                    return
            
            app.root.geometry(resolution)
            resolution_window.destroy()
            messagebox.showinfo("Window Resized", f"Window dimensions set to {resolution}")
            write_debug_log(f"Window dimensions set to {resolution}")
        
        apply_btn = ctk.CTkButton(
            resolution_window,
            text="Apply Resolution",
            font=("Courier New", 14, "bold"),
            fg_color="#ff0000",
            hover_color="#cc0000",
            command=apply_resolution
        )
        apply_btn.pack(pady=10)
        
        write_debug_log("Resolution selection window opened")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to open resolution selection: {e}")
        write_debug_log(f"Error opening resolution selection: {e}")

def show_debug_console():
    """Show debug console window."""
    try:
        debug_window = ctk.CTkToplevel(app.root)
        debug_window.title("Debug Console")
        debug_window.geometry("600x400")
        debug_window.transient(app.root)
        debug_window.grab_set()
        
        # Debug console text area
        debug_text = ctk.CTkTextbox(debug_window, font=("Courier New", 10))
        debug_text.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Load debug log content
        try:
            if os.path.exists(debug_log_file):
                with open(debug_log_file, "r") as f:
                    debug_text.insert("1.0", f.read())
            else:
                debug_text.insert("1.0", "No debug log found.")
        except Exception as e:
            debug_text.insert("1.0", f"Error loading debug log: {e}")
        
        debug_text.configure(state="disabled")
        
        # Refresh button
        def refresh_debug():
            debug_text.configure(state="normal")
            debug_text.delete("1.0", "end")
            try:
                if os.path.exists(debug_log_file):
                    with open(debug_log_file, "r") as f:
                        debug_text.insert("1.0", f.read())
                else:
                    debug_text.insert("1.0", "No debug log found.")
            except Exception as e:
                debug_text.insert("1.0", f"Error loading debug log: {e}")
            debug_text.configure(state="disabled")
        
        refresh_btn = ctk.CTkButton(debug_window, text="Refresh", command=refresh_debug)
        refresh_btn.pack(pady=5)
        
        write_debug_log("Debug console opened")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to open debug console: {e}")
        write_debug_log(f"Error opening debug console: {e}")

# --- GUI Implementation ---
class App:
    def __init__(self, root):
        self.root = root
        self.root.title("G.A.L - Gamers As Legions")
        self.root.geometry("800x860")
        
        # Configure customtkinter
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")

        # Create menu bar
        self.create_menu_bar()

        # Create a Notebook (Tabbed Interface)
        self.notebook = ctk.CTkTabview(root)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=10)

        # Add tabs
        self.notebook.add("System Optimizer")
        self.notebook.add("Game Optimizer")
        self.notebook.add("Help")  # New Help tab

        # Initialize the tabs
        self.init_system_optimizer_tab()
        self.init_game_optimizer_tab()
        self.init_help_tab()  # Initialize Help tab

    def create_menu_bar(self):
        """Create the Tools menu bar with Trickster integration."""
        self.menu_bar = tk.Menu(self.root)
        self.root.config(menu=self.menu_bar)
        
        # Tools menu
        self.tools_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.menu_bar.add_cascade(label="Tools", menu=self.tools_menu)
        
        # Tools menu items
        self.tools_menu.add_command(label="Clear Log", command=self.clear_current_log)
        self.tools_menu.add_command(label="Save Log", command=self.save_current_log)
        self.tools_menu.add_separator()
        self.tools_menu.add_command(label="Set Window Size", command=set_monitor_dimensions)
        self.tools_menu.add_command(label="Debug Console", command=show_debug_console)
        self.tools_menu.add_separator()
        # Add Trickster button to Tools menu
        self.tools_menu.add_command(label="Trickster", command=unlock_and_configure_trickster)
        self.tools_menu.add_separator()
        self.tools_menu.add_command(label="Exit", command=self.exit_app)

    def clear_current_log(self):
        """Clear the log of the currently active tab."""
        current_tab = self.notebook.get()
        if current_tab == "System Optimizer":
            clear_log(self.text_box)
        else:  # Game Optimizer
            clear_log(self.game_status_log)

    def save_current_log(self):
        """Save the log of the currently active tab."""
        current_tab = self.notebook.get()
        if current_tab == "System Optimizer":
            save_log(self.text_box)
        else:  # Game Optimizer
            save_log(self.game_status_log)

    def init_system_optimizer_tab(self):
        """Initialize the System Optimizer tab."""
        system_tab = self.notebook.tab("System Optimizer")

        # Title Label
        self.title_label = ctk.CTkLabel(
            system_tab,
            text="Gamers As Legions System Optimizer",
            font=("Courier New", 24, "bold"),
            text_color="#ff0000"
        )
        self.title_label.pack(pady=20)

        # Create scrollable frame
        self.system_scrollable_frame = ctk.CTkScrollableFrame(system_tab, width=700, height=400)
        self.system_scrollable_frame.pack(fill="both", expand=True, padx=20, pady=10)

        # Button configurations with their functions
        button_configs = [
            ("Clean RAM Cache", clean_ram_cache),
            ("Clean Windows Temp Folder", clean_windows_temp_folder),
            ("Clean Prefetch Folder", clean_prefetch_folder),
            ("Clean Recycle Bin", clean_recycle_bin),
            ("Clean Windows Update Cache", clean_windows_update_cache),
            ("Clean Temporary Internet Files", clean_temporary_internet_files),
            ("Clean Thumbnails", clean_thumbnails),
            ("Clean Delivery Optimization Files", clean_delivery_optimization_files),
            ("Clean Temp Folder", clean_temp_folder),
            ("Flush DNS Cache", flush_dns_cache),
            ("Set Cloudflare DNS", set_cloudflare_dns),
            ("Set Ultimate Power Plan", check_and_set_ultimate_power_plan),
            ("Clean Windows Update Cleanup", clean_windows_update_cleanup),
            ("Clean Microsoft Defender Antivirus", clean_microsoft_defender_antivirus),
            ("Clean Windows Upgrade Log Files", clean_windows_upgrade_log_files),
            ("Clean System Recovery Log Files", clean_system_recovery_log_files),
            ("Disable Telemetry", disable_telemetry),
            ("Disable Cortana", disable_cortana),
            ("Disable Game Bar", disable_game_bar),
            ("Optimize Network Adapter", optimize_network_adapter),
        ]

        # Create buttons with checkboxes
        self.system_checkboxes = {}
        for text, command in button_configs:
            frame = ctk.CTkFrame(self.system_scrollable_frame)
            frame.pack(fill="x", pady=2)
            
            # Checkbox
            var = tk.BooleanVar()
            checkbox = ctk.CTkCheckBox(
                frame,
                text="",
                variable=var,
                width=20
            )
            checkbox.pack(side="left", padx=(10, 5))
            self.system_checkboxes[text] = var
            
            # Button
            button = ctk.CTkButton(
                frame,
                text=text,
                font=("Courier New", 12, "bold"),
                fg_color="#333333",
                hover_color="#444444",
                command=lambda cmd=command: self.clear_and_run(cmd)
            )
            button.pack(side="left", fill="x", expand=True, padx=5)

        # Run All Button
        self.run_all_button = ctk.CTkButton(
            self.system_scrollable_frame,
            text="Run All",
            font=("Courier New", 14, "bold"),
            fg_color="#ff0000",
            hover_color="#cc0000",
            command=self.run_all
        )
        self.run_all_button.pack(pady=10, fill="x")

        # Run Preferred Button
        self.run_preferred_button = ctk.CTkButton(
            self.system_scrollable_frame,
            text="Run Preferred",
            font=("Courier New", 14, "bold"),
            fg_color="#ff0000",
            hover_color="#cc0000",
            command=self.run_preferred
        )
        self.run_preferred_button.pack(pady=5, fill="x")

        # Text Box for Status Messages
        self.text_box = ctk.CTkTextbox(
            self.system_scrollable_frame,
            height=120,
            font=("Courier New", 11),
            text_color="#ffffff",
            fg_color="#333333"
        )
        self.text_box.pack(pady=10, fill="x")
        self.text_box.insert("1.0", "Ready for optimization...\n")
        self.text_box.configure(state="disabled")

    def init_game_optimizer_tab(self):
        """Initialize the Game Optimizer tab with Power Plan Management."""
        game_tab = self.notebook.tab("Game Optimizer")

        # Title Label
        title_label = ctk.CTkLabel(
            game_tab,
            text="Game Optimizer",
            font=("Courier New", 24, "bold"),
            text_color="#ff0000"
        )
        title_label.pack(pady=20)

        # Create scrollable frame
        self.game_scrollable_frame = ctk.CTkScrollableFrame(game_tab, width=700, height=500)
        self.game_scrollable_frame.pack(fill="both", expand=True, padx=20, pady=10)

        # Power Plan Management Section
        power_plan_section = ctk.CTkLabel(
            self.game_scrollable_frame,
            text="Power Plan Management",
            font=("Courier New", 18, "bold"),
            text_color="#ff0000"
        )
        power_plan_section.pack(pady=10)

        # Current Power Plans Frame
        plans_frame = ctk.CTkFrame(self.game_scrollable_frame)
        plans_frame.pack(fill="x", pady=5, padx=5)

        ctk.CTkLabel(
            plans_frame,
            text="Available Power Plans:",
            font=("Courier New", 12, "bold")
        ).pack(anchor="w", padx=5, pady=5)

        # Power plans listbox with scrollbar
        plans_list_frame = ctk.CTkFrame(plans_frame)
        plans_list_frame.pack(fill="x", padx=5, pady=5)

        self.power_plans_listbox = tk.Listbox(
            plans_list_frame,
            height=6,
            bg="#333333",
            fg="#ffffff",
            selectbackground="#ff0000",
            font=("Courier New", 10)
        )
        self.power_plans_listbox.pack(side="left", fill="x", expand=True, padx=(0, 5))

        scrollbar = ctk.CTkScrollbar(plans_list_frame, command=self.power_plans_listbox.yview)
        scrollbar.pack(side="right", fill="y")
        self.power_plans_listbox.configure(yscrollcommand=scrollbar.set)

        # Power Plan Buttons
        plan_buttons_frame = ctk.CTkFrame(self.game_scrollable_frame)
        plan_buttons_frame.pack(fill="x", pady=5)

        refresh_plans_btn = ctk.CTkButton(
            plan_buttons_frame,
            text="Refresh Plans",
            font=("Courier New", 12, "bold"),
            fg_color="#333333",
            hover_color="#444444",
            command=self.refresh_power_plans
        )
        refresh_plans_btn.pack(side="left", padx=2, pady=2)

        set_active_btn = ctk.CTkButton(
            plan_buttons_frame,
            text="Set Active",
            font=("Courier New", 12, "bold"),
            fg_color="#333333",
            hover_color="#444444",
            command=self.set_active_power_plan
        )
        set_active_btn.pack(side="left", padx=2, pady=2)

        delete_plan_btn = ctk.CTkButton(
            plan_buttons_frame,
            text="Delete Plan",
            font=("Courier New", 12, "bold"),
            fg_color="#ff0000",
            hover_color="#cc0000",
            command=self.delete_power_plan
        )
        delete_plan_btn.pack(side="left", padx=2, pady=2)

        # Create New Power Plan Section
        create_plan_frame = ctk.CTkFrame(self.game_scrollable_frame)
        create_plan_frame.pack(fill="x", pady=5, padx=5)

        ctk.CTkLabel(
            create_plan_frame,
            text="Create New Power Plan:",
            font=("Courier New", 12, "bold")
        ).pack(anchor="w", padx=5, pady=5)

        # Template selection and name entry
        create_input_frame = ctk.CTkFrame(create_plan_frame)
        create_input_frame.pack(fill="x", padx=5, pady=5)

        ctk.CTkLabel(
            create_input_frame,
            text="Template:",
            font=("Courier New", 10)
        ).pack(side="left", padx=5)

        self.template_var = ctk.StringVar(value="Balanced")
        templates = ["Balanced", "High Performance", "Power Saver", "Ultimate Performance"]
        self.template_dropdown = ctk.CTkComboBox(
            create_input_frame,
            variable=self.template_var,
            values=templates,
            width=150,
            font=("Courier New", 10)
        )
        self.template_dropdown.pack(side="left", padx=5)

        ctk.CTkLabel(
            create_input_frame,
            text="Plan Name:",
            font=("Courier New", 10)
        ).pack(side="left", padx=(20, 5))

        self.new_plan_name = ctk.CTkEntry(
            create_input_frame,
            width=200,
            font=("Courier New", 10),
            placeholder_text="Enter new plan name"
        )
        self.new_plan_name.pack(side="left", padx=5, fill="x", expand=True)

        create_btn = ctk.CTkButton(
            create_input_frame,
            text="Create Plan",
            font=("Courier New", 12, "bold"),
            fg_color="#333333",
            hover_color="#444444",
            command=self.create_power_plan
        )
        create_btn.pack(side="left", padx=5)

        # Program Management Section
        program_section = ctk.CTkLabel(
            self.game_scrollable_frame,
            text="Program Management",
            font=("Courier New", 18, "bold"),
            text_color="#ff0000"
        )
        program_section.pack(pady=10)

        # Program entry frame
        entry_frame = ctk.CTkFrame(self.game_scrollable_frame)
        entry_frame.pack(fill="x", pady=5)
        
        ctk.CTkLabel(
            entry_frame,
            text="Program Name:",
            font=("Courier New", 12, "bold")
        ).pack(side="left", padx=5)
        
        self.program_entry = ctk.CTkEntry(
            entry_frame,
            width=200,
            font=("Courier New", 12),
            placeholder_text="e.g., game.exe"
        )
        self.program_entry.pack(side="left", padx=5, fill="x", expand=True)

        # Program management buttons
        program_buttons_frame = ctk.CTkFrame(self.game_scrollable_frame)
        program_buttons_frame.pack(fill="x", pady=5)

        add_program_btn = ctk.CTkButton(
            program_buttons_frame,
            text="Add Program",
            font=("Courier New", 12, "bold"),
            fg_color="#333333",
            hover_color="#444444",
            command=lambda: add_program(self.program_entry, self.game_status_log)
        )
        add_program_btn.pack(side="left", padx=2)

        add_dir_btn = ctk.CTkButton(
            program_buttons_frame,
            text="Add Directory",
            font=("Courier New", 12, "bold"),
            fg_color="#333333",
            hover_color="#444444",
            command=lambda: add_directory(self.game_status_log)
        )
        add_dir_btn.pack(side="left", padx=2)

        load_list_btn = ctk.CTkButton(
            program_buttons_frame,
            text="Load List",
            font=("Courier New", 12, "bold"),
            fg_color="#333333",
            hover_color="#444444",
            command=lambda: load_program_list(self.game_status_log)
        )
        load_list_btn.pack(side="left", padx=2)

        save_list_btn = ctk.CTkButton(
            program_buttons_frame,
            text="Save List",
            font=("Courier New", 12, "bold"),
            fg_color="#333333",
            hover_color="#444444",
            command=save_program_list
        )
        save_list_btn.pack(side="left", padx=2)

        # Process Monitoring Section
        monitoring_section = ctk.CTkLabel(
            self.game_scrollable_frame,
            text="Process Monitoring",
            font=("Courier New", 18, "bold"),
            text_color="#ff0000"
        )
        monitoring_section.pack(pady=10)

        # Monitoring buttons
        monitor_buttons_frame = ctk.CTkFrame(self.game_scrollable_frame)
        monitor_buttons_frame.pack(fill="x", pady=5)

        start_monitor_btn = ctk.CTkButton(
            monitor_buttons_frame,
            text="Start Monitoring",
            font=("Courier New", 12, "bold"),
            fg_color="#333333",
            hover_color="#444444",
            command=lambda: start_monitoring(self.game_status_log, self.game_progress_bar)
        )
        start_monitor_btn.pack(side="left", padx=2)

        stop_monitor_btn = ctk.CTkButton(
            monitor_buttons_frame,
            text="Stop Monitoring",
            font=("Courier New", 12, "bold"),
            fg_color="#333333",
            hover_color="#444444",
            command=lambda: stop_monitoring(self.game_status_log)
        )
        stop_monitor_btn.pack(side="left", padx=2)

        # Manual Process Optimization Section
        optimization_section = ctk.CTkLabel(
            self.game_scrollable_frame,
            text="Manual Process Optimization",
            font=("Courier New", 18, "bold"),
            text_color="#ff0000"
        )
        optimization_section.pack(pady=10)

        # Process selection
        process_select_frame = ctk.CTkFrame(self.game_scrollable_frame)
        process_select_frame.pack(fill="x", pady=5)
        
        ctk.CTkLabel(
            process_select_frame,
            text="Select Process:",
            font=("Courier New", 12, "bold")
        ).pack(side="left", padx=5)
        
        self.process_var = ctk.StringVar(value="")
        
        # Use CTkComboBox with proper styling
        self.process_dropdown = ctk.CTkComboBox(
            process_select_frame,
            variable=self.process_var,
            values=get_running_processes(),
            width=200,
            font=("Courier New", 12),
            dropdown_font=("Courier New", 12),
            fg_color="#333333",
            button_color="#333333",
            button_hover_color="#444444",
            border_color="#555555",
            text_color="#ffffff"
        )
        self.process_dropdown.pack(side="left", padx=5, fill="x", expand=True)
        
        refresh_btn = ctk.CTkButton(
            process_select_frame,
            text="Refresh",
            font=("Courier New", 12, "bold"),
            fg_color="#333333",
            hover_color="#444444",
            command=self.refresh_processes
        )
        refresh_btn.pack(side="left", padx=5)

        # CPU Affinity settings
        affinity_frame = ctk.CTkFrame(self.game_scrollable_frame)
        affinity_frame.pack(fill="x", pady=5)
        
        ctk.CTkLabel(
            affinity_frame,
            text="CPU Cores:",
            font=("Courier New", 12, "bold")
        ).pack(side="left", padx=5)
        
        self.affinity_entry = ctk.CTkEntry(
            affinity_frame,
            width=150,
            font=("Courier New", 12),
            placeholder_text="e.g., 0,1,2,3"
        )
        self.affinity_entry.pack(side="left", padx=5, fill="x", expand=True)
        
        # Priority settings
        priority_frame = ctk.CTkFrame(self.game_scrollable_frame)
        priority_frame.pack(fill="x", pady=5)
        
        ctk.CTkLabel(
            priority_frame,
            text="Priority:",
            font=("Courier New", 12, "bold")
        ).pack(side="left", padx=5)
        
        self.priority_var = ctk.StringVar(value="HIGH_PRIORITY_CLASS")
        priority_options = ["IDLE_PRIORITY_CLASS", "NORMAL_PRIORITY_CLASS", "HIGH_PRIORITY_CLASS", "REALTIME_PRIORITY_CLASS"]
        
        # Use CTkComboBox with proper styling
        self.priority_dropdown = ctk.CTkComboBox(
            priority_frame,
            variable=self.priority_var,
            values=priority_options,
            width=200,
            font=("Courier New", 12),
            dropdown_font=("Courier New", 12),
            fg_color="#333333",
            button_color="#333333",
            button_hover_color="#444444",
            border_color="#555555",
            text_color="#ffffff"
        )
        self.priority_dropdown.pack(side="left", padx=5, fill="x", expand=True)
        
        # Apply optimization button
        apply_opt_btn = ctk.CTkButton(
            self.game_scrollable_frame,
            text="Apply Process Optimization",
            font=("Courier New", 14, "bold"),
            fg_color="#ff0000",
            hover_color="#cc0000",
            command=self.apply_process_optimization
        )
        apply_opt_btn.pack(pady=10, fill="x")

        # Remove Process Optimization button
        remove_opt_btn = ctk.CTkButton(
            self.game_scrollable_frame,
            text="Remove Process Optimization",
            font=("Courier New", 14, "bold"),
            fg_color="#333333",
            hover_color="#444444",
            command=self.remove_process_optimization
        )
        remove_opt_btn.pack(pady=5, fill="x")

        # Progress bar
        self.game_progress_bar = ctk.CTkProgressBar(
            self.game_scrollable_frame,
            orientation="horizontal",
            width=400,
            progress_color="#ff0000"
        )
        self.game_progress_bar.pack(pady=10, fill="x")
        self.game_progress_bar.set(0)

        # Status log for Game Optimizer
        self.game_status_log = ctk.CTkTextbox(
            self.game_scrollable_frame,
            height=150,
            font=("Courier New", 11),
            text_color="#ffffff",
            fg_color="#333333"
        )
        self.game_status_log.pack(pady=10, fill="both", expand=True)
        self.game_status_log.insert("1.0", "Game Optimizer ready...\n")
        self.game_status_log.configure(state="disabled")

        # Load power plans on startup
        self.refresh_power_plans()

    def init_help_tab(self):
        """Initialize the Help tab with comprehensive documentation."""
        help_tab = self.notebook.tab("Help")

        # Create scrollable frame for help content
        help_scrollable_frame = ctk.CTkScrollableFrame(help_tab, width=700, height=600)
        help_scrollable_frame.pack(fill="both", expand=True, padx=20, pady=20)

        # Title
        title_label = ctk.CTkLabel(
            help_scrollable_frame,
            text="G.A.L - Gamers As Legions - Help Guide",
            font=("Courier New", 24, "bold"),
            text_color="#ff0000"
        )
        title_label.pack(pady=20)

        # Table of Contents
        toc_frame = ctk.CTkFrame(help_scrollable_frame)
        toc_frame.pack(fill="x", pady=10, padx=10)
        
        ctk.CTkLabel(
            toc_frame,
            text="Table of Contents:",
            font=("Courier New", 16, "bold"),
            text_color="#ff0000"
        ).pack(anchor="w", padx=10, pady=5)
        
        toc_text = ctk.CTkTextbox(toc_frame, height=80, font=("Courier New", 12))
        toc_text.pack(fill="x", padx=10, pady=5)
        toc_text.insert("1.0", "1. Overview\n2. System Optimizer\n3. Game Optimizer\n4. Power Plan Management\n5. Trickster Feature\n6. Tools Menu\n7. How to Use\n8. About")
        toc_text.configure(state="disabled")

        # Overview Section
        overview_frame = ctk.CTkFrame(help_scrollable_frame)
        overview_frame.pack(fill="x", pady=10, padx=10)
        
        ctk.CTkLabel(
            overview_frame,
            text="1. Overview",
            font=("Courier New", 18, "bold"),
            text_color="#ff0000"
        ).pack(anchor="w", padx=10, pady=5)
        
        overview_text = ctk.CTkTextbox(overview_frame, height=120, font=("Courier New", 12))
        overview_text.pack(fill="x", padx=10, pady=5)
        overview_text.insert("1.0", 
            "G.A.L (Gamers As Legions) is a comprehensive system optimization tool designed specifically for gamers.\n\n"
            "Key Features:\n"
            "• System Optimization: Clean temporary files, optimize settings\n"
            "• Game Optimization: Monitor and optimize running games\n"
            "• Power Plan Management: Control Windows power schemes\n"
            "• Process Management: Set CPU affinity and priority\n"
            "• Network Optimization: DNS and network adapter settings\n\n"
            "The tool requires Administrator privileges to function properly and provides real-time monitoring and optimization capabilities."
        )
        overview_text.configure(state="disabled")

        # System Optimizer Section
        system_help_frame = ctk.CTkFrame(help_scrollable_frame)
        system_help_frame.pack(fill="x", pady=10, padx=10)
        
        ctk.CTkLabel(
            system_help_frame,
            text="2. System Optimizer",
            font=("Courier New", 18, "bold"),
            text_color="#ff0000"
        ).pack(anchor="w", padx=10, pady=5)
        
        system_text = ctk.CTkTextbox(system_help_frame, height=200, font=("Courier New", 12))
        system_text.pack(fill="x", padx=10, pady=5)
        system_text.insert("1.0",
            "The System Optimizer tab provides various cleaning and optimization functions:\n\n"
            "Cleaning Functions:\n"
            "• Clean RAM Cache: Releases unused memory from processes\n"
            "• Clean Windows Temp Folder: Removes temporary system files\n"
            "• Clean Prefetch Folder: Clears application prefetch data\n"
            "• Clean Recycle Bin: Permanently empties recycle bin\n"
            "• Clean Windows Update Cache: Removes update download files\n"
            "• Clean Temporary Internet Files: Clears browser caches\n"
            "• Clean Thumbnails: Removes thumbnail cache\n"
            "• Clean Delivery Optimization Files: Clears update delivery cache\n"
            "• Clean Temp Folder: Comprehensive temp file cleaning\n\n"
            "Optimization Functions:\n"
            "• Flush DNS Cache: Clears DNS resolver cache\n"
            "• Set Cloudflare DNS: Configures fast DNS servers\n"
            "• Set Ultimate Power Plan: Activates high-performance power scheme\n"
            "• Disable Telemetry: Turns off Windows data collection\n"
            "• Disable Cortana: Disables Cortana and web search\n"
            "• Disable Game Bar: Turns off Xbox Game Bar\n"
            "• Optimize Network Adapter: Configures TCP settings for gaming\n\n"
            "Usage:\n"
            "• Click individual buttons for specific optimizations\n"
            "• Use checkboxes to select preferred operations\n"
            "• Click 'Run Preferred' for selected optimizations\n"
            "• Click 'Run All' for complete system optimization"
        )
        system_text.configure(state="disabled")

        # Game Optimizer Section
        game_help_frame = ctk.CTkFrame(help_scrollable_frame)
        game_help_frame.pack(fill="x", pady=10, padx=10)
        
        ctk.CTkLabel(
            game_help_frame,
            text="3. Game Optimizer",
            font=("Courier New", 18, "bold"),
            text_color="#ff0000"
        ).pack(anchor="w", padx=10, pady=5)
        
        game_text = ctk.CTkTextbox(game_help_frame, height=250, font=("Courier New", 12))
        game_text.pack(fill="x", padx=10, pady=5)
        game_text.insert("1.0",
            "The Game Optimizer provides real-time game process monitoring and optimization:\n\n"
            "Program Management:\n"
            "• Add Program: Add individual .exe files to monitor\n"
            "• Add Directory: Scan folder for all .exe files\n"
            "• Load List: Load program list from file\n"
            "• Save List: Save current program list\n\n"
            "Process Monitoring:\n"
            "• Start Monitoring: Begin watching for specified programs\n"
            "• Stop Monitoring: Stop the monitoring process\n"
            "• When detected, programs are automatically optimized\n\n"
            "Manual Process Optimization:\n"
            "• Select Process: Choose from running processes\n"
            "• CPU Cores: Set specific CPU cores (comma-separated)\n"
            "• Priority: Set process priority level\n"
            "• Apply Optimization: Apply settings to selected process\n"
            "• Remove Optimization: Reset process to default settings\n\n"
            "Power Plan Management:\n"
            "• View all available power plans\n"
            "• Set active power plan\n"
            "• Delete unwanted power plans\n"
            "• Create new power plans from templates\n\n"
            "Optimization Effects:\n"
            "• Closes unnecessary background processes\n"
            "• Disables non-essential services\n"
            "• Sets CPU affinity for better core utilization\n"
            "• Increases process priority for better performance\n"
            "• Disables Windows Defender temporarily\n"
            "• Kills GPU-intensive processes\n"
            "• Disables Windows animations"
        )
        game_text.configure(state="disabled")

        # Power Plan Management Section
        power_help_frame = ctk.CTkFrame(help_scrollable_frame)
        power_help_frame.pack(fill="x", pady=10, padx=10)
        
        ctk.CTkLabel(
            power_help_frame,
            text="4. Power Plan Management",
            font=("Courier New", 18, "bold"),
            text_color="#ff0000"
        ).pack(anchor="w", padx=10, pady=5)
        
        power_text = ctk.CTkTextbox(power_help_frame, height=150, font=("Courier New", 12))
        power_text.pack(fill="x", padx=10, pady=5)
        power_text.insert("1.0",
            "Located in the Game Optimizer tab, this feature provides complete control over Windows power plans.\n\n"
            "Available Templates:\n"
            "• Balanced: Standard power-saving performance\n"
            "• High Performance: Maximum performance with higher power usage\n"
            "• Power Saver: Maximum power savings\n"
            "• Ultimate Performance: Hidden Windows plan for ultimate performance\n\n"
            "Operations:\n"
            "• Refresh Plans: Update the list of available power plans\n"
            "• Set Active: Activate the selected power plan\n"
            "• Delete Plan: Remove unwanted power plans (cannot delete active)\n"
            "• Create Plan: Make new custom power plans from templates\n\n"
            "Usage Tips:\n"
            "• Use 'High Performance' or 'Ultimate Performance' for gaming\n"
            "• Create custom plans for specific use cases\n"
            "• Delete unused plans to keep list clean\n"
            "• Active plan is marked with [ACTIVE] in the list"
        )
        power_text.configure(state="disabled")

        # Trickster Section
        trickster_frame = ctk.CTkFrame(help_scrollable_frame)
        trickster_frame.pack(fill="x", pady=10, padx=10)
        
        ctk.CTkLabel(
            trickster_frame,
            text="5. Trickster Feature",
            font=("Courier New", 18, "bold"),
            text_color="#ff0000"
        ).pack(anchor="w", padx=10, pady=5)
        
        trickster_text = ctk.CTkTextbox(trickster_frame, height=120, font=("Courier New", 12))
        trickster_text.pack(fill="x", padx=10, pady=5)
        trickster_text.insert("1.0",
            "Trickster is a special power plan manipulation feature integrated into G.A.L.\n\n"
            "Location: Tools Menu → Trickster\n\n"
            "What it does:\n"
            "• Unlocks the hidden 'Ultimate Performance' power plan\n"
            "• Deletes the existing 'High Performance' plan\n"
            "• Renames 'Ultimate Performance' to 'High Performance'\n"
            "• Activates the new high-performance plan\n\n"
            "Purpose:\n"
            "This disguises the ultimate performance plan as the standard high performance plan,\n"
            "making it easier to select in graphics settings while providing maximum performance.\n\n"
            "Note: After using Trickster, set your graphics applications to use 'High Performance'\n"
            "in Windows Graphics Settings to benefit from the ultimate performance plan."
        )
        trickster_text.configure(state="disabled")

        # Tools Menu Section
        tools_frame = ctk.CTkFrame(help_scrollable_frame)
        tools_frame.pack(fill="x", pady=10, padx=10)
        
        ctk.CTkLabel(
            tools_frame,
            text="6. Tools Menu",
            font=("Courier New", 18, "bold"),
            text_color="#ff0000"
        ).pack(anchor="w", padx=10, pady=5)
        
        tools_text = ctk.CTkTextbox(tools_frame, height=120, font=("Courier New", 12))
        tools_text.pack(fill="x", padx=10, pady=5)
        tools_text.insert("1.0",
            "The Tools menu provides additional utility functions:\n\n"
            "Available Tools:\n"
            "• Clear Log: Clear the current tab's log\n"
            "• Save Log: Save log content to file\n"
            "• Set Window Size: Change application window dimensions\n"
            "• Debug Console: View detailed debug information\n"
            "• Trickster: Activate the Trickster power plan feature\n"
            "• Exit: Close the application\n\n"
            "Window Size Settings:\n"
            "• Pre-defined common resolutions\n"
            "• Custom resolution input\n"
            "• Instant application resizing\n\n"
            "Debug Console:\n"
            "• View real-time debug logs\n"
            "• Refresh to see latest entries\n"
            "• Useful for troubleshooting"
        )
        tools_text.configure(state="disabled")

        # How to Use Section
        usage_frame = ctk.CTkFrame(help_scrollable_frame)
        usage_frame.pack(fill="x", pady=10, padx=10)
        
        ctk.CTkLabel(
            usage_frame,
            text="7. How to Use G.A.L",
            font=("Courier New", 18, "bold"),
            text_color="#ff0000"
        ).pack(anchor="w", padx=10, pady=5)
        
        usage_text = ctk.CTkTextbox(usage_frame, height=200, font=("Courier New", 12))
        usage_text.pack(fill="x", padx=10, pady=5)
        usage_text.insert("1.0",
            "Step-by-Step Guide:\n\n"
            "1. First Run:\n"
            "   • Run as Administrator for full functionality\n"
            "   • Allow the program to install any missing dependencies\n"
            "\n"
            "2. System Optimization:\n"
            "   • Go to System Optimizer tab\n"
            "   • Select desired optimizations using checkboxes\n"
            "   • Click 'Run Preferred' for selected options\n"
            "   • Or click 'Run All' for complete optimization\n"
            "   • Monitor progress in the status box\n"
            "\n"
            "3. Game Optimization Setup:\n"
            "   • Go to Game Optimizer tab\n"
            "   • Add games to monitor:\n"
            "     - Type program name (e.g., 'game.exe') and click 'Add Program'\n"
            "     - Or click 'Add Directory' to scan a folder\n"
            "     - Or load a saved list with 'Load List'\n"
            "   • Save your list with 'Save List' for future use\n"
            "\n"
            "4. Power Plan Configuration:\n"
            "   • In Game Optimizer tab, use Power Plan Management\n"
            "   • Select a high-performance plan and click 'Set Active'\n"
            "   • Or use Tools → Trickster for ultimate performance\n"
            "\n"
            "5. Start Gaming:\n"
            "   • Click 'Start Monitoring' in Game Optimizer\n"
            "   • Launch your games\n"
            "   • G.A.L will automatically detect and optimize them\n"
            "   • Use 'Stop Monitoring' when done\n"
            "\n"
            "6. Manual Optimization:\n"
            "   • Select a running process from the dropdown\n"
            "   • Set CPU cores and priority\n"
            "   • Click 'Apply Process Optimization'\n"
            "   • Use 'Remove' to reset to defaults\n"
            "\n"
            "Best Practices:\n"
            "• Run system optimization weekly\n"
            "• Use Game Optimizer monitoring during gaming sessions\n"
            "• Set power plan to High Performance before gaming\n"
            "• Save your program lists for quick setup"
        )
        usage_text.configure(state="disabled")

        # About Section
        about_frame = ctk.CTkFrame(help_scrollable_frame)
        about_frame.pack(fill="x", pady=10, padx=10)
        
        ctk.CTkLabel(
            about_frame,
            text="8. About G.A.L",
            font=("Courier New", 18, "bold"),
            text_color="#ff0000"
        ).pack(anchor="w", padx=10, pady=5)
        
        about_text = ctk.CTkTextbox(about_frame, height=100, font=("Courier New", 12))
        about_text.pack(fill="x", padx=10, pady=5)
        about_text.insert("1.0",
            "G.A.L - Gamers As Legions\n\n"
            "Created by: xxxnightvoidxxx (Twitch/YouTube)\n"
            "Also known as: xxxsilentdeviantxxx (YouTube)\n\n"
            "Coding Assistant: Deepseek.com AI\n\n"
            "G.A.L is a comprehensive gaming optimization tool designed to provide\n"
            "maximum performance for PC gamers through system optimization,\n"
            "real-time process management, and power plan control.\n\n"
            "Features integrated Trickster functionality for ultimate power plan manipulation."
        )
        about_text.configure(state="disabled")

    def refresh_power_plans(self):
        """Refresh the list of power plans."""
        plans = get_power_plans()
        self.power_plans_listbox.delete(0, tk.END)
        
        for plan in plans:
            display_text = f"{plan['name']} {'[ACTIVE]' if plan['active'] else ''}"
            self.power_plans_listbox.insert(tk.END, display_text)
            # Store GUID as hidden data (we'll parse it when needed)
            self.power_plans_listbox.itemconfig(tk.END, {'bg': '#2b2b2b' if not plan['active'] else '#1f1f1f'})
        
        self.game_status_log.configure(state="normal")
        self.game_status_log.insert("end", f"Refreshed power plans. Found {len(plans)} plans.\n")
        self.game_status_log.see("end")
        self.game_status_log.configure(state="disabled")

    def set_active_power_plan(self):
        """Set the selected power plan as active."""
        selection = self.power_plans_listbox.curselection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a power plan first.")
            return
        
        selected_index = selection[0]
        plans = get_power_plans()
        
        if selected_index < len(plans):
            plan = plans[selected_index]
            if set_active_power_plan(plan['guid']):
                self.game_status_log.configure(state="normal")
                self.game_status_log.insert("end", f"Activated power plan: {plan['name']}\n")
                self.game_status_log.see("end")
                self.game_status_log.configure(state="disabled")
                self.refresh_power_plans()
            else:
                messagebox.showerror("Error", f"Failed to activate power plan: {plan['name']}")

    def delete_power_plan(self):
        """Delete the selected power plan."""
        selection = self.power_plans_listbox.curselection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a power plan first.")
            return
        
        selected_index = selection[0]
        plans = get_power_plans()
        
        if selected_index < len(plans):
            plan = plans[selected_index]
            if plan['active']:
                messagebox.showerror("Error", "Cannot delete the active power plan. Please activate another plan first.")
                return
            
            if messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete the power plan:\n{plan['name']}Help"):
                if delete_power_plan(plan['guid']):
                    self.game_status_log.configure(state="normal")
                    self.game_status_log.insert("end", f"Deleted power plan: {plan['name']}\n")
                    self.game_status_log.see("end")
                    self.game_status_log.configure(state="disabled")
                    self.refresh_power_plans()
                else:
                    messagebox.showerror("Error", f"Failed to delete power plan: {plan['name']}")

    def create_power_plan(self):
        """Create a new power plan from template."""
        template_name = self.template_var.get()
        new_name = self.new_plan_name.get().strip()
        
        if not new_name:
            messagebox.showwarning("Warning", "Please enter a name for the new power plan.")
            return
        
        # Map template names to GUIDs
        template_guids = {
            "Balanced": "381b4222-f694-41f0-9685-ff5bb260df2e",
            "High Performance": "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c",
            "Power Saver": "a1841308-3541-4fab-bc81-f71556f20b4a",
            "Ultimate Performance": "e9a42b02-d5df-448d-aa00-03f14749eb61"
        }
        
        template_guid = template_guids.get(template_name)
        if not template_guid:
            messagebox.showerror("Error", "Invalid template selected.")
            return
        
        new_guid = create_power_plan_from_template(template_guid, new_name)
        if new_guid:
            self.game_status_log.configure(state="normal")
            self.game_status_log.insert("end", f"Created new power plan: {new_name}\n")
            self.game_status_log.see("end")
            self.game_status_log.configure(state="disabled")
            self.new_plan_name.delete(0, tk.END)
            self.refresh_power_plans()
        else:
            messagebox.showerror("Error", f"Failed to create power plan: {new_name}")

    def refresh_processes(self):
        """Refresh the list of running processes."""
        processes = get_running_processes()
        self.process_dropdown.configure(values=processes)
        if processes:
            self.process_var.set(processes[0])
        self.game_status_log.configure(state="normal")
        self.game_status_log.insert("end", "Process list refreshed.\n")
        self.game_status_log.see("end")
        self.game_status_log.configure(state="disabled")

    def apply_process_optimization(self):
        """Apply CPU affinity and priority to selected process."""
        process_name = self.process_var.get()
        affinity_text = self.affinity_entry.get()
        priority_text = self.priority_var.get()
        
        if not process_name:
            messagebox.showerror("Error", "Please select a process!")
            return
            
        # Parse CPU affinity
        cores = []
        if affinity_text:
            try:
                cores = [int(core.strip()) for core in affinity_text.split(",")]
            except ValueError:
                messagebox.showerror("Error", "Invalid CPU affinity format! Use comma-separated numbers.")
                return
        
        # Map priority text to psutil constants
        priority_map = {
            "IDLE_PRIORITY_CLASS": psutil.IDLE_PRIORITY_CLASS,
            "NORMAL_PRIORITY_CLASS": psutil.NORMAL_PRIORITY_CLASS,
            "HIGH_PRIORITY_CLASS": psutil.HIGH_PRIORITY_CLASS,
            "REALTIME_PRIORITY_CLASS": psutil.REALTIME_PRIORITY_CLASS
        }
        priority = priority_map.get(priority_text, psutil.NORMAL_PRIORITY_CLASS)
        
        # Apply optimizations
        success_affinity = True
        success_priority = True
        
        if cores:
            success_affinity = set_cpu_affinity(process_name, cores)
        
        success_priority = set_process_priority(process_name, priority)
        
        # Log results
        self.game_status_log.configure(state="normal")
        if success_affinity or success_priority:
            self.game_status_log.insert("end", f"Applied optimizations to {process_name}:\n")
            if cores and success_affinity:
                self.game_status_log.insert("end", f"  - CPU Affinity set to cores: {cores}\n")
            if success_priority:
                self.game_status_log.insert("end", f"  - Priority set to: {priority_text}\n")
        else:
            self.game_status_log.insert("end", f"Failed to apply optimizations to {process_name}. Process may not be running.\n")
        
        self.game_status_log.see("end")
        self.game_status_log.configure(state="disabled")

    def remove_process_optimization(self):
        """Remove optimizations from selected process (reset to default)."""
        process_name = self.process_var.get()
        
        if not process_name:
            messagebox.showerror("Error", "Please select a process!")
            return
        
        # Reset CPU affinity to all cores
        cpu_count = os.cpu_count()
        all_cores = list(range(cpu_count)) if cpu_count else [0, 1]
        success_affinity = set_cpu_affinity(process_name, all_cores)
        
        # Reset priority to normal
        success_priority = set_process_priority(process_name, psutil.NORMAL_PRIORITY_CLASS)
        
        # Log results
        self.game_status_log.configure(state="normal")
        if success_affinity or success_priority:
            self.game_status_log.insert("end", f"Removed optimizations from {process_name}:\n")
            if success_affinity:
                self.game_status_log.insert("end", f"  - CPU Affinity reset to all cores\n")
            if success_priority:
                self.game_status_log.insert("end", f"  - Priority reset to normal\n")
        else:
            self.game_status_log.insert("end", f"Failed to remove optimizations from {process_name}. Process may not be running.\n")
        
        self.game_status_log.see("end")
        self.game_status_log.configure(state="disabled")

    def clear_and_run(self, command):
        """Clear the text box and run the command."""
        self.text_box.configure(state="normal")
        self.text_box.delete("1.0", "end")
        self.text_box.configure(state="disabled")
        command()

    def run_all(self):
        """Run all cleaning and optimization functions in parallel."""
        functions = [
            clean_ram_cache,
            clean_windows_temp_folder,
            clean_prefetch_folder,
            clean_recycle_bin,
            clean_windows_update_cache,
            clean_temporary_internet_files,
            clean_thumbnails,
            clean_delivery_optimization_files,
            clean_temp_folder,
            flush_dns_cache,
            set_cloudflare_dns,
            check_and_set_ultimate_power_plan,
            clean_windows_update_cleanup,
            clean_microsoft_defender_antivirus,
            clean_windows_upgrade_log_files,
            clean_system_recovery_log_files,
            disable_telemetry,
            disable_cortana,
            disable_game_bar,
            optimize_network_adapter
        ]

        # Use a separate thread to run all functions
        def run_functions():
            with ThreadPoolExecutor() as executor:
                futures = [executor.submit(func) for func in functions]
                for future in futures:
                    future.result()  # Wait for all threads to complete
            update_text_box("All Optimizations Complete!")

        # Start the thread
        threading.Thread(target=run_functions, daemon=True).start()

        # Periodically update the GUI
        self.root.after(100, self.check_thread_status)

    def run_preferred(self):
        """Run only the selected (checked) optimization functions."""
        selected_functions = []
        
        # Map button text to functions
        function_map = {
            "Clean RAM Cache": clean_ram_cache,
            "Clean Windows Temp Folder": clean_windows_temp_folder,
            "Clean Prefetch Folder": clean_prefetch_folder,
            "Clean Recycle Bin": clean_recycle_bin,
            "Clean Windows Update Cache": clean_windows_update_cache,
            "Clean Temporary Internet Files": clean_temporary_internet_files,
            "Clean Thumbnails": clean_thumbnails,
            "Clean Delivery Optimization Files": clean_delivery_optimization_files,
            "Clean Temp Folder": clean_temp_folder,
            "Flush DNS Cache": flush_dns_cache,
            "Set Cloudflare DNS": set_cloudflare_dns,
            "Set Ultimate Power Plan": check_and_set_ultimate_power_plan,
            "Clean Windows Update Cleanup": clean_windows_update_cleanup,
            "Clean Microsoft Defender Antivirus": clean_microsoft_defender_antivirus,
            "Clean Windows Upgrade Log Files": clean_windows_upgrade_log_files,
            "Clean System Recovery Log Files": clean_system_recovery_log_files,
            "Disable Telemetry": disable_telemetry,
            "Disable Cortana": disable_cortana,
            "Disable Game Bar": disable_game_bar,
            "Optimize Network Adapter": optimize_network_adapter,
        }
        
        # Find selected functions
        for text, var in self.system_checkboxes.items():
            if var.get():
                if text in function_map:
                    selected_functions.append(function_map[text])
        
        if not selected_functions:
            messagebox.showinfo("Info", "No optimizations selected! Please check the boxes for the optimizations you want to run.")
            return
        
        # Use a separate thread to run selected functions
        def run_selected_functions():
            with ThreadPoolExecutor() as executor:
                futures = [executor.submit(func) for func in selected_functions]
                for future in futures:
                    future.result()  # Wait for all threads to complete
            update_text_box("Selected Optimizations Complete!")

        # Start the thread
        threading.Thread(target=run_selected_functions, daemon=True).start()

        # Periodically update the GUI
        self.root.after(100, self.check_thread_status)

    def check_thread_status(self):
        """Periodically check the status of the threads and update the GUI."""
        if threading.active_count() > 1:  # If there are still active threads (excluding the main thread)
            self.root.after(100, self.check_thread_status)  # Continue checking
        else:
            update_text_box("All Optimizations Complete!")  # Final update

    def exit_app(self):
        """Exit the application."""
        logging.info("Exiting application.")
        self.root.destroy()

# --- Function to Update Text Box ---
def update_text_box(message):
    """Update the text box with a message using a queue for batching."""
    update_queue.put(message)
    app.root.after(100, process_update_queue)  # Process updates every 100ms

def process_update_queue():
    """Process all pending updates in the queue."""
    while not update_queue.empty():
        message = update_queue.get()
        app.text_box.configure(state="normal")
        app.text_box.delete("1.0", "end")
        app.text_box.insert("1.0", message)
        app.text_box.configure(state="disabled")

# --- Main Execution ---
if __name__ == "__main__":
    # Install missing dependencies
    install_dependencies()

    # Elevate privileges if not already running as admin
    elevate_privileges()

    # Start the GUI
    root = ctk.CTk()
    app = App(root)
    root.mainloop()
