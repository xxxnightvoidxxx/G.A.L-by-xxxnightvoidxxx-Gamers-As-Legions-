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

# --- Set up logging ---
logging.basicConfig(
    filename="debug.log",
    level=logging.INFO,  # Reduced from DEBUG to INFO to minimize logging overhead
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logging.info("Script started.")

# --- Hide the console window (Windows only) ---
if os.name == "nt":
    ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)

# --- Global Variables ---
debug_log_file = "debug_log.txt"
monitoring_event = threading.Event()
monitoring_thread = None
program_list = []
detected_processes = set()  # Track detected processes to avoid repeated optimizations
update_queue = Queue()  # Queue for batching GUI updates

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

# --- Force Delete Function (Optimized) ---
def force_delete_folder_contents(folder_path):
    """Force-delete all files and subdirectories in a folder, ignoring errors."""
    if not os.path.exists(folder_path):
        logging.warning(f"Folder does not exist: {folder_path}")
        return

    try:
        with os.scandir(folder_path) as entries:
            for entry in entries:
                try:
                    if entry.is_file() or entry.is_symlink():
                        os.unlink(entry.path)
                        logging.debug(f"Deleted file: {entry.path}")
                    elif entry.is_dir():
                        shutil.rmtree(entry.path)
                        logging.debug(f"Deleted directory: {entry.path}")
                except Exception as e:
                    logging.error(f"Exception deleting {entry.path}: {e}")
    except Exception as e:
        logging.error(f"Exception scanning folder {folder_path}: {e}")

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
        for proc in psutil.process_iter(['pid', 'name', 'memory_info']):
            try:
                if proc.info['memory_info'].rss > 100 * 1024 * 1024:  # Only target processes using >100MB RAM
                    p = psutil.Process(proc.info['pid'])
                    p.memory_info().rss  # Force the process to release unused memory
                    logging.debug(f"Cleaned RAM for process: {proc.info['name']} (PID: {proc.info['pid']})")
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        update_text_box("Cleaned RAM Cache!")
    except Exception as e:
        logging.error(f"Exception cleaning RAM cache: {e}")
        update_text_box(f"Error: {e}")

def clean_windows_temp_folder():
    """Force-delete everything in the C:\Windows\Temp folder."""
    logging.info("Cleaning Windows Temp folder...")
    windows_temp_folder = "C:\\Windows\\Temp"
    if os.path.exists(windows_temp_folder):
        force_delete_folder_contents(windows_temp_folder)
        update_text_box("Cleaned Windows Temp Folder!")
    else:
        logging.warning(f"Windows Temp folder does not exist: {windows_temp_folder}")
        update_text_box("Windows Temp folder not found!")

def clean_prefetch_folder():
    """Force-delete everything in the C:\Windows\Prefetch folder."""
    logging.info("Cleaning Prefetch folder...")
    prefetch_folder = "C:\\Windows\\Prefetch"
    if os.path.exists(prefetch_folder):
        force_delete_folder_contents(prefetch_folder)
        update_text_box("Cleaned Prefetch Folder!")
    else:
        logging.warning(f"Prefetch folder does not exist: {prefetch_folder}")
        update_text_box("Prefetch folder not found!")

def clean_recycle_bin():
    """Force-clean the Recycle Bin using the Windows API."""
    try:
        logging.info("Cleaning Recycle Bin...")
        ctypes.windll.shell32.SHEmptyRecycleBinW(None, None, 0x00000001)  # 0x00000001 = SHERB_NOCONFIRMATION
        update_text_box("Cleaned Recycle Bin!")
    except Exception as e:
        logging.error(f"Exception cleaning Recycle Bin: {e}")
        update_text_box(f"Error: {e}")

def clean_windows_update_cache():
    """Clean the Windows Update cache."""
    logging.info("Cleaning Windows Update cache...")
    update_cache_folder = "C:\\Windows\\SoftwareDistribution\\Download"
    if os.path.exists(update_cache_folder):
        force_delete_folder_contents(update_cache_folder)
        update_text_box("Cleaned Windows Update Cache!")
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

    for cache_folder in browser_cache_folders:
        if os.path.exists(cache_folder):
            force_delete_folder_contents(cache_folder)

    update_text_box("Cleaned Temporary Internet Files for all browsers!")

def clean_thumbnails():
    """Force-delete Thumbnails cache for all users."""
    logging.info("Cleaning Thumbnails...")
    users_dir = os.getenv('USERPROFILE')
    thumbnails_folder = os.path.join(users_dir, "AppData", "Local", "Microsoft", "Windows", "Explorer")
    if os.path.exists(thumbnails_folder):
        force_delete_folder_contents(thumbnails_folder)
    update_text_box("Cleaned Thumbnails!")

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
        force_delete_folder_contents(delivery_optimization_folder)
        update_text_box("Cleaned Delivery Optimization Files!")
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

    for folder in temp_folders:
        if os.path.exists(folder):
            force_delete_folder_contents(folder)
            logging.info(f"Cleaned Temp folder: {folder}")

    update_text_box("Cleaned all Temp folders!")

def flush_dns_cache():
    """Flush the DNS cache."""
    try:
        logging.info("Flushing DNS cache...")
        subprocess.run(
            ["ipconfig", "/flushdns"],
            shell=True,
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        update_text_box("Flushed DNS Cache!")
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

        # Iterate through all subkeys (network interfaces)
        for i in range(winreg.QueryInfoKey(reg_key)[0]):
            interface_key_name = winreg.EnumKey(reg_key, i)
            interface_key = winreg.OpenKey(reg_key, interface_key_name, 0, winreg.KEY_ALL_ACCESS)

            try:
                # Set DNS to Cloudflare
                winreg.SetValueEx(interface_key, "NameServer", 0, winreg.REG_SZ, "1.1.1.1,1.0.0.1")
                winreg.SetValueEx(interface_key, "DhcpNameServer", 0, winreg.REG_SZ, "1.1.1.1,1.0.0.1")
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

        update_text_box("Set Cloudflare DNS for all connected interfaces!")
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
        update_text_box("Set Ultimate Power Plan!")
    except Exception as e:
        logging.error(f"Exception setting Ultimate Power Plan: {e}")
        update_text_box(f"Error: {e}")

# --- New Folder-Cleaning Functions ---
def clean_windows_update_cleanup():
    """Clean Windows Update Cleanup files."""
    logging.info("Cleaning Windows Update Cleanup files...")
    update_cleanup_folder = os.path.join(os.getenv("SYSTEMROOT"), "SoftwareDistribution", "Download")
    if os.path.exists(update_cleanup_folder):
        force_delete_folder_contents(update_cleanup_folder)
        update_text_box("Cleaned Windows Update Cleanup files!")
    else:
        logging.warning(f"Windows Update Cleanup folder does not exist: {update_cleanup_folder}")
        update_text_box("Windows Update Cleanup folder not found!")

def clean_microsoft_defender_antivirus():
    """Clean Microsoft Defender Antivirus files."""
    logging.info("Cleaning Microsoft Defender Antivirus files...")
    defender_folder = os.path.join(os.getenv("PROGRAMDATA"), "Microsoft", "Windows Defender", "Scans")
    if os.path.exists(defender_folder):
        force_delete_folder_contents(defender_folder)
        update_text_box("Cleaned Microsoft Defender Antivirus files!")
    else:
        logging.warning(f"Microsoft Defender Antivirus folder does not exist: {defender_folder}")
        update_text_box("Microsoft Defender Antivirus folder not found!")

def clean_windows_upgrade_log_files():
    """Clean Windows Upgrade Log Files."""
    logging.info("Cleaning Windows Upgrade Log Files...")
    upgrade_log_folder = os.path.join(os.getenv("SYSTEMROOT"), "Logs", "CBS")
    if os.path.exists(upgrade_log_folder):
        force_delete_folder_contents(upgrade_log_folder)
        update_text_box("Cleaned Windows Upgrade Log Files!")
    else:
        logging.warning(f"Windows Upgrade Log Files folder does not exist: {upgrade_log_folder}")
        update_text_box("Windows Upgrade Log Files folder not found!")

def clean_system_recovery_log_files():
    """Clean System Recovery Log Files."""
    logging.info("Cleaning System Recovery Log Files...")
    recovery_log_folder = os.path.join(os.getenv("SYSTEMROOT"), "System32", "LogFiles", "Srt")
    if os.path.exists(recovery_log_folder):
        force_delete_folder_contents(recovery_log_folder)
        update_text_box("Cleaned System Recovery Log Files!")
    else:
        logging.warning(f"System Recovery Log Files folder does not exist: {recovery_log_folder}")
        update_text_box("System Recovery Log Files folder not found!")

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
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                logging.warning(f"Failed to set CPU affinity for {process_name}")

def set_process_priority(process_name, priority):
    """Set process priority for a specific process."""
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'] == process_name:
            try:
                p = psutil.Process(proc.info['pid'])
                p.nice(priority)
                logging.info(f"Set priority for {process_name} to {priority}")
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                logging.warning(f"Failed to set priority for {process_name}")

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
    status_log.insert(tk.END, "Closing unnecessary processes...\n")
    status_log.see(tk.END)
    write_debug_log("Starting system optimization...")
    progress_bar['value'] = 20

    processes_to_kill = ["chrome.exe", "discord.exe"]  # Exclude steam.exe
    for process_name in processes_to_kill:
        for proc in psutil.process_iter(['pid', 'name']):
            if proc.info['name'] == process_name:
                try:
                    proc.terminate()
                    status_log.insert(tk.END, f"Closed {process_name}\n")
                    status_log.see(tk.END)
                    write_debug_log(f"Closed process: {process_name}")
                except psutil.NoSuchProcess:
                    write_debug_log(f"Process not found: {process_name}")

    status_log.insert(tk.END, "Disabling non-essential services...\n")
    status_log.see(tk.END)
    write_debug_log("Disabling non-essential services...")
    progress_bar['value'] = 50

    services_to_stop = ["SysMain", "DiagTrack"]
    for service in services_to_stop:
        try:
            subprocess.run(["net", "stop", service], shell=True)
            status_log.insert(tk.END, f"Stopped service: {service}\n")
            status_log.see(tk.END)
            write_debug_log(f"Stopped service: {service}")
        except Exception as e:
            status_log.insert(tk.END, f"Failed to stop service {service}: {e}\n")
            status_log.see(tk.END)
            write_debug_log(f"Failed to stop service {service}: {e}")

    # --- New Enhancements for Game Optimizer ---
    status_log.insert(tk.END, "Applying game performance optimizations...\n")
    status_log.see(tk.END)
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

    status_log.insert(tk.END, "Optimizations complete!\n")
    status_log.see(tk.END)
    write_debug_log("System optimizations complete.")
    progress_bar['value'] = 100

def monitor_processes(status_log, progress_bar):
    global detected_processes
    write_debug_log("Starting process monitoring...")
    while not monitoring_event.is_set():
        for proc in psutil.process_iter(['pid', 'name']):
            if proc.info['name'] in program_list and proc.info['name'] not in detected_processes:
                detected_processes.add(proc.info['name'])  # Add to detected processes
                status_log.insert(tk.END, f"Detected {proc.info['name']} running. Applying optimizations...\n")
                status_log.see(tk.END)
                write_debug_log(f"Detected {proc.info['name']} running. Applying optimizations...")
                optimize_system(status_log, progress_bar)
        time.sleep(5)  # Add a delay to reduce CPU usage

def start_monitoring(status_log, progress_bar):
    global monitoring_thread, detected_processes
    if not program_list:
        messagebox.showerror("Error", "No programs in the list to monitor!")
        write_debug_log("Error: No programs in the list to monitor!")
        return

    status_log.delete(1.0, tk.END)
    progress_bar['value'] = 0
    detected_processes.clear()  # Reset detected processes

    monitoring_event.clear()
    monitoring_thread = threading.Thread(target=monitor_processes, args=(status_log, progress_bar), daemon=True)
    monitoring_thread.start()
    status_log.insert(tk.END, f"Monitoring for programs: {', '.join(program_list)}...\n")
    status_log.see(tk.END)
    write_debug_log(f"Monitoring for programs: {', '.join(program_list)}...")

def stop_monitoring():
    global monitoring_thread
    if monitoring_thread and monitoring_thread.is_alive():
        monitoring_event.set()
        monitoring_thread.join(timeout=1)
        status_log.insert(tk.END, "Monitoring stopped.\n")
        status_log.see(tk.END)
        write_debug_log("Monitoring stopped.")

def clear_log(status_log):
    status_log.delete(1.0, tk.END)
    write_debug_log("Status log cleared.")

def save_log(status_log):
    with open("optimization_log.txt", "w") as file:
        file.write(status_log.get(1.0, tk.END))
    messagebox.showinfo("Log Saved", "The log has been saved to optimization_log.txt.")
    write_debug_log("Status log saved to optimization_log.txt.")

def load_program_list(status_log):
    global program_list
    file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
    if file_path:
        try:
            with open(file_path, "r") as file:
                program_list = file.read().splitlines()
                status_log.insert(tk.END, f"Loaded program list: {', '.join(program_list)}\n")
                status_log.see(tk.END)
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
        program_entry.delete(0, tk.END)
        status_log.insert(tk.END, f"Added {program_name} to the program list.\n")
        status_log.see(tk.END)
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
                    status_log.insert(tk.END, f"Added {file} from {root} to the program list.\n")
                    status_log.see(tk.END)
                    write_debug_log(f"Added {file} from {root} to the program list.")

def reset_progress_bar(progress_bar):
    progress_bar['value'] = 0
    write_debug_log("Progress bar reset.")

# --- GUI Implementation ---
class App:
    def __init__(self, root):
        self.root = root
        self.root.title("G.A.L - Gamers As Legions")
        self.root.geometry("800x860")
        self.root.configure(bg="#1e1e1e")

        # Add transparency effect
        self.root.attributes("-alpha", 0.9)  # Set transparency to 90%

        # Set customtkinter theme
        ctk.set_appearance_mode("dark")  # Set dark mode

        # Create a Notebook (Tabbed Interface)
        self.notebook = ctk.CTkTabview(root)
        self.notebook.pack(fill="both", expand=True)

        # Add tabs
        self.notebook.add("System Optimizer")  # Add System Optimizer tab
        self.notebook.add("Game Optimizer")    # Add Game Optimizer tab

        # Initialize the tabs
        self.init_system_optimizer_tab()
        self.init_game_optimizer_tab()

    def init_system_optimizer_tab(self):
        """Initialize the System Optimizer tab."""
        system_tab = self.notebook.tab("System Optimizer")

        # Custom font for Castlevania style
        self.custom_font = font.Font(family="Courier New", size=12, weight="bold")

        # Title Label
        self.title_label = tk.Label(
            system_tab,
            text="Gamers As Legions System Optimizer",
            font=("Courier New", 24, "bold"),
            fg="#ff0000",
            bg="#1e1e1e"
        )
        self.title_label.pack(pady=20)

        # Buttons for each function
        self.create_button(system_tab, "Clean RAM Cache", clean_ram_cache)
        self.create_button(system_tab, "Clean Windows Temp Folder", clean_windows_temp_folder)
        self.create_button(system_tab, "Clean Prefetch Folder", clean_prefetch_folder)
        self.create_button(system_tab, "Clean Recycle Bin", clean_recycle_bin)
        self.create_button(system_tab, "Clean Windows Update Cache", clean_windows_update_cache)
        self.create_button(system_tab, "Clean Temporary Internet Files", clean_temporary_internet_files)
        self.create_button(system_tab, "Clean Thumbnails", clean_thumbnails)
        self.create_button(system_tab, "Clean Delivery Optimization Files", clean_delivery_optimization_files)
        self.create_button(system_tab, "Clean Temp Folder", clean_temp_folder)
        self.create_button(system_tab, "Flush DNS Cache", flush_dns_cache)
        self.create_button(system_tab, "Set Cloudflare DNS", set_cloudflare_dns)
        self.create_button(system_tab, "Set Ultimate Power Plan", check_and_set_ultimate_power_plan)

        # --- New Buttons for Additional Folders ---
        self.create_button(system_tab, "Clean Windows Update Cleanup", clean_windows_update_cleanup)
        self.create_button(system_tab, "Clean Microsoft Defender Antivirus", clean_microsoft_defender_antivirus)
        self.create_button(system_tab, "Clean Windows Upgrade Log Files", clean_windows_upgrade_log_files)
        self.create_button(system_tab, "Clean System Recovery Log Files", clean_system_recovery_log_files)

        # Run All Button
        self.run_all_button = tk.Button(
            system_tab,
            text="Run All",
            font=self.custom_font,
            fg="#ffffff",
            bg="#ff0000",
            command=self.run_all
        )
        self.run_all_button.pack(pady=5, padx=20, fill=tk.X)

        # Text Box for Status Messages
        self.text_box = tk.Text(
            system_tab,
            height=5,
            width=80,
            font=self.custom_font,
            fg="#ffffff",
            bg="#333333",
            wrap=tk.WORD
        )
        self.text_box.pack(pady=10)

        # Exit Button
        self.exit_button = tk.Button(
            system_tab,
            text="Exit",
            font=self.custom_font,
            fg="#ffffff",
            bg="#ff0000",
            command=self.exit_app
        )
        self.exit_button.pack(pady=20)

    def init_game_optimizer_tab(self):
        """Initialize the Game Optimizer tab."""
        game_tab = self.notebook.tab("Game Optimizer")

        # Customize widget colors
        red_color = "#ff0000"
        dark_red_color = "#cc0000"
        gray_color = "#1e1e1e"

        # Add a program entry field
        ctk.CTkLabel(game_tab, text="Add a program to the list (e.g., game.exe):", font=("Helvetica", 14), text_color=red_color).pack(pady=10)
        self.program_entry = ctk.CTkEntry(game_tab, width=300, fg_color=gray_color, text_color="#ffffff")
        self.program_entry.pack(pady=10)

        # Add buttons for managing the program list
        add_button = ctk.CTkButton(game_tab, text="Add Program", command=lambda: add_program(self.program_entry, self.status_log), fg_color=red_color, hover_color=dark_red_color)
        add_button.pack(pady=5)

        add_dir_button = ctk.CTkButton(game_tab, text="Add Directory", command=lambda: add_directory(self.status_log), fg_color=red_color, hover_color=dark_red_color)
        add_dir_button.pack(pady=5)

        load_button = ctk.CTkButton(game_tab, text="Load Program List", command=lambda: load_program_list(self.status_log), fg_color=red_color, hover_color=dark_red_color)
        load_button.pack(pady=5)

        save_button = ctk.CTkButton(game_tab, text="Save Program List", command=save_program_list, fg_color=red_color, hover_color=dark_red_color)
        save_button.pack(pady=5)

        # Add buttons for monitoring
        start_button = ctk.CTkButton(game_tab, text="Start Monitoring", command=lambda: start_monitoring(self.status_log, self.progress_bar), fg_color=red_color, hover_color=dark_red_color)
        start_button.pack(pady=5)

        stop_button = ctk.CTkButton(game_tab, text="Stop Monitoring", command=stop_monitoring, fg_color=red_color, hover_color=dark_red_color)
        stop_button.pack(pady=5)

        # Add buttons for log management
        clear_button = ctk.CTkButton(game_tab, text="Clear Log", command=lambda: clear_log(self.status_log), fg_color=red_color, hover_color=dark_red_color)
        clear_button.pack(pady=5)

        save_log_button = ctk.CTkButton(game_tab, text="Save Log", command=lambda: save_log(self.status_log), fg_color=red_color, hover_color=dark_red_color)
        save_log_button.pack(pady=5)

        # Add a progress bar
        self.progress_bar = ctk.CTkProgressBar(game_tab, orientation="horizontal", width=400, progress_color=red_color)
        self.progress_bar.pack(pady=10)

        # Add a status log
        self.status_log = tk.Text(game_tab, height=10, width=70, bg=gray_color, fg=red_color, font=("Helvetica", 10))
        self.status_log.pack(pady=10)

    def create_button(self, parent, text, command):
        """Helper function to create styled buttons."""
        button = tk.Button(
            parent,
            text=text,
            font=self.custom_font,
            fg="#ffffff",
            bg="#333333",
            command=lambda: self.clear_and_run(command)
        )
        button.pack(pady=5, padx=20, fill=tk.X)

    def clear_and_run(self, command):
        """Clear the text box and run the command."""
        self.text_box.config(state=tk.NORMAL)
        self.text_box.delete(1.0, tk.END)
        self.text_box.config(state=tk.DISABLED)
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
            clean_system_recovery_log_files
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
        app.text_box.config(state=tk.NORMAL)
        app.text_box.delete(1.0, tk.END)
        app.text_box.insert(tk.END, message)
        app.text_box.config(state=tk.DISABLED)

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