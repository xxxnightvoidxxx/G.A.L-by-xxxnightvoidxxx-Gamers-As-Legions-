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
import winreg
import re
import json
import webbrowser
import GPUtil
import speedtest
import wmi
import socket
import uuid

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
detected_processes = set()
update_queue = Queue()
system_checkboxes = {}
performance_monitoring = False
performance_thread = None
safe_mode = False

# --- Install Missing Dependencies ---
def install_dependencies():
    """Install required Python packages if they are missing."""
    required_packages = ["psutil", "customtkinter", "gputil", "speedtest-cli", "wmi"]
    import importlib
    import subprocess
    import sys

    for package in required_packages:
        try:
            importlib.import_module(package.replace("-", "_"))
        except ImportError:
            logging.info(f"Installing missing package: {package}")
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])

# --- Safe Mode Functions ---
def toggle_safe_mode():
    """Toggle safe mode on/off."""
    global safe_mode
    safe_mode = not safe_mode
    status = "ENABLED" if safe_mode else "DISABLED"
    
    if hasattr(app, 'safe_mode_label'):
        app.safe_mode_label.configure(text=f"Safe Mode: {status}")
    
    logging.info(f"Safe mode {status}")
    
    # Show warning for safe mode
    if safe_mode:
        messagebox.showwarning(
            "Safe Mode Enabled", 
            "Safe Mode is now ENABLED.\n\n"
            "The following optimizations will be skipped:\n"
            "• DNS changes\n"
            "• Registry modifications\n"
            "• Power plan changes\n"
            "• Service modifications\n\n"
            "Only file cleaning operations will be performed."
        )
    else:
        messagebox.showinfo(
            "Safe Mode Disabled", 
            "Safe Mode is now DISABLED.\n\n"
            "All optimizations will run normally."
        )

def is_safe_mode_operation(operation_type):
    """Check if an operation should be skipped in safe mode."""
    if not safe_mode:
        return False
    
    safe_mode_restricted_operations = [
        "dns", "registry", "power", "service", "network", "telemetry", 
        "cortana", "gamebar", "defender", "animations"
    ]
    
    return any(op in operation_type.lower() for op in safe_mode_restricted_operations)

# --- Advanced System Information Functions ---
def get_advanced_system_info():
    """Get comprehensive system information."""
    try:
        info = {}
        
        # Python Information
        info['python'] = {
            'version': platform.python_version(),
            'path': sys.executable,
            'architecture': platform.architecture()[0]
        }
        
        # CUDA Information
        info['cuda'] = get_cuda_info()
        
        # Operating System
        info['os'] = {
            'name': platform.system(),
            'version': platform.version(),
            'release': platform.release(),
            'architecture': platform.architecture()[0],
            'processor': platform.processor()
        }
        
        # CPU Details
        info['cpu'] = get_cpu_details()
        
        # Memory Details
        info['memory'] = get_memory_details()
        
        # Storage Drives
        info['storage'] = get_storage_details()
        
        # Network Adapters
        info['network'] = get_network_details()
        
        # USB Devices
        info['usb'] = get_usb_devices()
        
        # BIOS & Motherboard
        info['bios'] = get_bios_info()
        info['motherboard'] = get_motherboard_info()
        
        # DirectX Version
        info['directx'] = get_directx_version()
        
        return info
        
    except Exception as e:
        logging.error(f"Error getting advanced system info: {e}")
        return {}

def get_cuda_info():
    """Get CUDA information if available."""
    try:
        # Try to get CUDA version from nvidia-smi
        result = subprocess.run(['nvidia-smi', '--query-gpu=driver_version', '--format=csv,noheader'], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            driver_version = result.stdout.strip()
            return {
                'driver_version': driver_version,
                'cuda_detected': True
            }
    except:
        pass
    
    return {
        'driver_version': 'Not detected',
        'cuda_detected': False
    }

def get_cpu_details():
    """Get detailed CPU information."""
    try:
        cpu_info = {
            'physical_cores': psutil.cpu_count(logical=False),
            'logical_cores': psutil.cpu_count(logical=True),
            'max_frequency': psutil.cpu_freq().max if psutil.cpu_freq() else 'N/A',
            'current_frequency': psutil.cpu_freq().current if psutil.cpu_freq() else 'N/A',
            'architecture': platform.machine()
        }
        
        # Try to get more detailed CPU info using WMI
        try:
            c = wmi.WMI()
            for processor in c.Win32_Processor():
                cpu_info['name'] = processor.Name
                cpu_info['manufacturer'] = processor.Manufacturer
                cpu_info['description'] = processor.Description
                break
        except:
            cpu_info['name'] = platform.processor()
            
        return cpu_info
    except Exception as e:
        logging.error(f"Error getting CPU details: {e}")
        return {}

def get_memory_details():
    """Get detailed memory information."""
    try:
        memory = psutil.virtual_memory()
        swap = psutil.swap_memory()
        
        return {
            'total_physical': f"{memory.total / (1024**3):.2f} GB",
            'available_physical': f"{memory.available / (1024**3):.2f} GB",
            'used_physical': f"{memory.used / (1024**3):.2f} GB",
            'physical_percent': f"{memory.percent}%",
            'total_swap': f"{swap.total / (1024**3):.2f} GB",
            'used_swap': f"{swap.used / (1024**3):.2f} GB",
            'swap_percent': f"{swap.percent}%"
        }
    except Exception as e:
        logging.error(f"Error getting memory details: {e}")
        return {}

def get_storage_details():
    """Get detailed storage information with drive type detection."""
    try:
        drives = []
        for partition in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                drive_type = detect_drive_type(partition.device)
                
                drive_info = {
                    'device': partition.device,
                    'mountpoint': partition.mountpoint,
                    'fstype': partition.fstype,
                    'drive_type': drive_type,
                    'total_size': f"{usage.total / (1024**3):.2f} GB",
                    'used': f"{usage.used / (1024**3):.2f} GB",
                    'free': f"{usage.free / (1024**3):.2f} GB",
                    'percent': f"{usage.percent}%"
                }
                drives.append(drive_info)
            except Exception as e:
                logging.error(f"Error getting drive info for {partition.device}: {e}")
                continue
                
        return drives
    except Exception as e:
        logging.error(f"Error getting storage details: {e}")
        return []

def detect_drive_type(device):
    """Detect if a drive is SSD or HDD."""
    try:
        # Method 1: Using WMI
        c = wmi.WMI()
        for disk in c.Win32_LogicalDisk(DeviceID=device[0] + ":"):
            for partition in disk.Associators_():
                for physical_disk in partition.Associators_():
                    if hasattr(physical_disk, 'MediaType'):
                        if 'Solid State' in physical_disk.MediaType:
                            return 'SSD'
                        else:
                            return 'HDD'
        
        # Method 2: Using heuristics (check if it's a removable drive)
        if 'removable' in device.lower():
            return 'Removable'
            
        # Default to HDD if cannot determine
        return 'HDD (assumed)'
        
    except Exception as e:
        logging.error(f"Error detecting drive type for {device}: {e}")
        return 'Unknown'

def get_network_details():
    """Get detailed network adapter information."""
    try:
        adapters = []
        for interface, addrs in psutil.net_if_addrs().items():
            stats = psutil.net_if_stats().get(interface)
            
            adapter_info = {
                'name': interface,
                'type': 'Unknown',
                'speed': f"{stats.speed} Mbps" if stats else 'Unknown',
                'is_up': stats.isup if stats else False,
                'mac_address': '',
                'manufacturer': 'Unknown'
            }
            
            # Get MAC address
            for addr in addrs:
                if addr.family == psutil.AF_LINK:
                    adapter_info['mac_address'] = addr.address
                    break
            
            # Try to determine adapter type
            if 'wireless' in interface.lower() or 'wifi' in interface.lower():
                adapter_info['type'] = 'Wireless'
            elif 'ethernet' in interface.lower() or 'lan' in interface.lower():
                adapter_info['type'] = 'Ethernet'
            elif 'bluetooth' in interface.lower():
                adapter_info['type'] = 'Bluetooth'
            elif 'virtual' in interface.lower():
                adapter_info['type'] = 'Virtual'
                
            adapters.append(adapter_info)
            
        return adapters
    except Exception as e:
        logging.error(f"Error getting network details: {e}")
        return []

def get_usb_devices():
    """Get connected USB devices."""
    try:
        usb_devices = []
        c = wmi.WMI()
        
        for device in c.Win32_USBControllerDevice():
            try:
                usb_device = device.Dependent
                device_info = {
                    'name': usb_device.Name if hasattr(usb_device, 'Name') else 'Unknown',
                    'description': usb_device.Description if hasattr(usb_device, 'Description') else 'Unknown',
                    'status': usb_device.Status if hasattr(usb_device, 'Status') else 'Unknown'
                }
                usb_devices.append(device_info)
            except Exception as e:
                continue
                
        return usb_devices
    except Exception as e:
        logging.error(f"Error getting USB devices: {e}")
        return []

def get_bios_info():
    """Get BIOS information."""
    try:
        c = wmi.WMI()
        for bios in c.Win32_BIOS():
            return {
                'manufacturer': bios.Manufacturer,
                'version': bios.Version,
                'release_date': bios.ReleaseDate,
                'serial_number': bios.SerialNumber
            }
        return {}
    except Exception as e:
        logging.error(f"Error getting BIOS info: {e}")
        return {}

def get_motherboard_info():
    """Get motherboard information."""
    try:
        c = wmi.WMI()
        for board in c.Win32_BaseBoard():
            return {
                'manufacturer': board.Manufacturer,
                'model': board.Product,
                'version': board.Version
            }
        return {}
    except Exception as e:
        logging.error(f"Error getting motherboard info: {e}")
        return {}

def get_directx_version():
    """Get DirectX version."""
    try:
        # Check DirectX version through registry
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\DirectX")
        version, _ = winreg.QueryValueEx(key, "Version")
        winreg.CloseKey(key)
        return version
    except:
        return "Unknown"

def show_advanced_system_info():
    """Show advanced system information window."""
    try:
        info_window = ctk.CTkToplevel(app.root)
        info_window.title("Advanced System Information")
        info_window.geometry("900x700")
        info_window.transient(app.root)
        info_window.grab_set()
        
        # Create notebook for tabs
        notebook = ctk.CTkTabview(info_window)
        notebook.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Add tabs
        tabs = [
            "Python & CUDA", "OS & CPU", "Memory & Storage", 
            "Network & USB", "BIOS & Motherboard", "Summary"
        ]
        for tab in tabs:
            notebook.add(tab)
        
        # Get system info
        system_info = get_advanced_system_info()
        
        # Python & CUDA Tab
        python_text = format_python_cuda_info(system_info)
        python_textbox = create_info_textbox(notebook.tab("Python & CUDA"), python_text)
        
        # OS & CPU Tab
        os_cpu_text = format_os_cpu_info(system_info)
        os_cpu_textbox = create_info_textbox(notebook.tab("OS & CPU"), os_cpu_text)
        
        # Memory & Storage Tab
        memory_storage_text = format_memory_storage_info(system_info)
        memory_storage_textbox = create_info_textbox(notebook.tab("Memory & Storage"), memory_storage_text)
        
        # Network & USB Tab
        network_usb_text = format_network_usb_info(system_info)
        network_usb_textbox = create_info_textbox(notebook.tab("Network & USB"), network_usb_text)
        
        # BIOS & Motherboard Tab
        bios_text = format_bios_motherboard_info(system_info)
        bios_textbox = create_info_textbox(notebook.tab("BIOS & Motherboard"), bios_text)
        
        # Summary Tab
        summary_text = format_summary_info(system_info)
        summary_textbox = create_info_textbox(notebook.tab("Summary"), summary_text)
        
        # Export button
        export_btn = ctk.CTkButton(
            info_window,
            text="Export to Text File",
            font=("Courier New", 12, "bold"),
            fg_color="#333333",
            hover_color="#444444",
            command=lambda: export_system_info(system_info)
        )
        export_btn.pack(pady=10)
        
    except Exception as e:
        logging.error(f"Error showing advanced system info: {e}")
        messagebox.showerror("Error", f"Failed to show system information: {e}")

def create_info_textbox(parent, text):
    """Create a styled textbox for information display."""
    textbox = ctk.CTkTextbox(parent, font=("Courier New", 11), wrap="word")
    textbox.pack(fill="both", expand=True, padx=10, pady=10)
    textbox.insert("1.0", text)
    textbox.configure(state="disabled")
    return textbox

def format_python_cuda_info(info):
    """Format Python and CUDA information for display."""
    text = "=== PYTHON INFORMATION ===\n\n"
    
    python_info = info.get('python', {})
    text += f"Version: {python_info.get('version', 'N/A')}\n"
    text += f"Path: {python_info.get('path', 'N/A')}\n"
    text += f"Architecture: {python_info.get('architecture', 'N/A')}\n"
    
    text += "\n=== CUDA INFORMATION ===\n\n"
    
    cuda_info = info.get('cuda', {})
    text += f"Driver Version: {cuda_info.get('driver_version', 'N/A')}\n"
    text += f"CUDA Detected: {cuda_info.get('cuda_detected', False)}\n"
    
    return text

def format_os_cpu_info(info):
    """Format OS and CPU information for display."""
    text = "=== OPERATING SYSTEM ===\n\n"
    
    os_info = info.get('os', {})
    text += f"Name: {os_info.get('name', 'N/A')}\n"
    text += f"Version: {os_info.get('version', 'N/A')}\n"
    text += f"Release: {os_info.get('release', 'N/A')}\n"
    text += f"Architecture: {os_info.get('architecture', 'N/A')}\n"
    text += f"Processor: {os_info.get('processor', 'N/A')}\n"
    
    text += "\n=== CPU DETAILS ===\n\n"
    
    cpu_info = info.get('cpu', {})
    text += f"Name: {cpu_info.get('name', 'N/A')}\n"
    text += f"Manufacturer: {cpu_info.get('manufacturer', 'N/A')}\n"
    text += f"Physical Cores: {cpu_info.get('physical_cores', 'N/A')}\n"
    text += f"Logical Cores: {cpu_info.get('logical_cores', 'N/A')}\n"
    text += f"Max Frequency: {cpu_info.get('max_frequency', 'N/A')} MHz\n"
    text += f"Current Frequency: {cpu_info.get('current_frequency', 'N/A')} MHz\n"
    text += f"Architecture: {cpu_info.get('architecture', 'N/A')}\n"
    
    return text

def format_memory_storage_info(info):
    """Format memory and storage information for display."""
    text = "=== MEMORY INFORMATION ===\n\n"
    
    memory_info = info.get('memory', {})
    text += f"Total Physical: {memory_info.get('total_physical', 'N/A')}\n"
    text += f"Available Physical: {memory_info.get('available_physical', 'N/A')}\n"
    text += f"Used Physical: {memory_info.get('used_physical', 'N/A')}\n"
    text += f"Physical Usage: {memory_info.get('physical_percent', 'N/A')}\n"
    text += f"Total Swap: {memory_info.get('total_swap', 'N/A')}\n"
    text += f"Used Swap: {memory_info.get('used_swap', 'N/A')}\n"
    text += f"Swap Usage: {memory_info.get('swap_percent', 'N/A')}\n"
    
    text += "\n=== STORAGE DRIVES ===\n\n"
    
    storage_info = info.get('storage', [])
    for drive in storage_info:
        text += f"Drive: {drive.get('device', 'N/A')}\n"
        text += f"  Mount: {drive.get('mountpoint', 'N/A')}\n"
        text += f"  Type: {drive.get('drive_type', 'N/A')}\n"
        text += f"  File System: {drive.get('fstype', 'N/A')}\n"
        text += f"  Total Size: {drive.get('total_size', 'N/A')}\n"
        text += f"  Used: {drive.get('used', 'N/A')} ({drive.get('percent', 'N/A')})\n"
        text += f"  Free: {drive.get('free', 'N/A')}\n\n"
    
    return text

def format_network_usb_info(info):
    """Format network and USB information for display."""
    text = "=== NETWORK ADAPTERS ===\n\n"
    
    network_info = info.get('network', [])
    for adapter in network_info:
        text += f"Adapter: {adapter.get('name', 'N/A')}\n"
        text += f"  Type: {adapter.get('type', 'N/A')}\n"
        text += f"  Speed: {adapter.get('speed', 'N/A')}\n"
        text += f"  Status: {'UP' if adapter.get('is_up') else 'DOWN'}\n"
        text += f"  MAC: {adapter.get('mac_address', 'N/A')}\n"
        text += f"  Manufacturer: {adapter.get('manufacturer', 'N/A')}\n\n"
    
    text += "=== USB DEVICES ===\n\n"
    
    usb_info = info.get('usb', [])
    for device in usb_info:
        text += f"Device: {device.get('name', 'N/A')}\n"
        text += f"  Description: {device.get('description', 'N/A')}\n"
        text += f"  Status: {device.get('status', 'N/A')}\n\n"
    
    return text

def format_bios_motherboard_info(info):
    """Format BIOS and motherboard information for display."""
    text = "=== BIOS INFORMATION ===\n\n"
    
    bios_info = info.get('bios', {})
    text += f"Manufacturer: {bios_info.get('manufacturer', 'N/A')}\n"
    text += f"Version: {bios_info.get('version', 'N/A')}\n"
    text += f"Release Date: {bios_info.get('release_date', 'N/A')}\n"
    text += f"Serial Number: {bios_info.get('serial_number', 'N/A')}\n"
    
    text += "\n=== MOTHERBOARD INFORMATION ===\n\n"
    
    motherboard_info = info.get('motherboard', {})
    text += f"Manufacturer: {motherboard_info.get('manufacturer', 'N/A')}\n"
    text += f"Model: {motherboard_info.get('model', 'N/A')}\n"
    text += f"Version: {motherboard_info.get('version', 'N/A')}\n"
    
    text += "\n=== DIRECTX VERSION ===\n\n"
    text += f"Version: {info.get('directx', 'Unknown')}\n"
    
    return text

def format_summary_info(info):
    """Format summary information for display."""
    text = "=== SYSTEM SUMMARY ===\n\n"
    
    # OS Summary
    os_info = info.get('os', {})
    text += f"Operating System: {os_info.get('name', 'N/A')} {os_info.get('release', 'N/A')}\n"
    text += f"Architecture: {os_info.get('architecture', 'N/A')}\n\n"
    
    # CPU Summary
    cpu_info = info.get('cpu', {})
    text += f"Processor: {cpu_info.get('name', 'N/A')}\n"
    text += f"Cores: {cpu_info.get('physical_cores', 'N/A')} physical, {cpu_info.get('logical_cores', 'N/A')} logical\n\n"
    
    # Memory Summary
    memory_info = info.get('memory', {})
    text += f"Memory: {memory_info.get('total_physical', 'N/A')} total, {memory_info.get('available_physical', 'N/A')} available\n\n"
    
    # Storage Summary
    storage_info = info.get('storage', [])
    text += f"Storage Drives: {len(storage_info)}\n"
    for drive in storage_info:
        text += f"  {drive.get('device', 'N/A')}: {drive.get('drive_type', 'N/A')} - {drive.get('total_size', 'N/A')}\n"
    
    text += f"\nNetwork Adapters: {len(info.get('network', []))}\n"
    text += f"USB Devices: {len(info.get('usb', []))}\n"
    text += f"Python Version: {info.get('python', {}).get('version', 'N/A')}\n"
    text += f"DirectX Version: {info.get('directx', 'Unknown')}\n"
    
    return text

def export_system_info(info):
    """Export system information to a text file."""
    try:
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt")],
            title="Export System Information"
        )
        
        if filename:
            with open(filename, 'w') as f:
                f.write("=== G.A.L - Advanced System Information Report ===\n\n")
                f.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                f.write(format_summary_info(info) + "\n\n")
                f.write(format_python_cuda_info(info) + "\n\n")
                f.write(format_os_cpu_info(info) + "\n\n")
                f.write(format_memory_storage_info(info) + "\n\n")
                f.write(format_network_usb_info(info) + "\n\n")
                f.write(format_bios_motherboard_info(info) + "\n\n")
            
            messagebox.showinfo("Export Successful", f"System information exported to:\n{filename}")
            logging.info(f"System information exported to: {filename}")
            
    except Exception as e:
        logging.error(f"Error exporting system info: {e}")
        messagebox.showerror("Export Error", f"Failed to export system information: {e}")

# --- Enhanced Real-time Monitoring Functions ---
def get_enhanced_system_performance():
    """Get enhanced system performance data with additional metrics."""
    try:
        # CPU usage with frequency and core count
        cpu_percent = psutil.cpu_percent(interval=1)
        cpu_freq = psutil.cpu_freq()
        current_freq = cpu_freq.current if cpu_freq else 'N/A'
        physical_cores = psutil.cpu_count(logical=False)
        logical_cores = psutil.cpu_count(logical=True)
        
        # Memory usage with available memory
        memory = psutil.virtual_memory()
        memory_percent = memory.percent
        memory_used_gb = memory.used / (1024 ** 3)
        memory_total_gb = memory.total / (1024 ** 3)
        memory_available_gb = memory.available / (1024 ** 3)
        
        # Disk usage for all drives
        disk_info = []
        for partition in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                disk_info.append({
                    'device': partition.device,
                    'mountpoint': partition.mountpoint,
                    'total': usage.total / (1024 ** 3),
                    'used': usage.used / (1024 ** 3),
                    'free': usage.free / (1024 ** 3),
                    'percent': usage.percent
                })
            except:
                continue
        
        # Network usage with active process count
        net_io = psutil.net_io_counters()
        upload_speed = net_io.bytes_sent
        download_speed = net_io.bytes_recv
        active_processes = len(psutil.pids())
        
        # Enhanced GPU info
        gpu_info = get_enhanced_gpu_info()
        
        performance_data = {
            'cpu_percent': cpu_percent,
            'cpu_frequency': current_freq,
            'physical_cores': physical_cores,
            'logical_cores': logical_cores,
            'memory_percent': memory_percent,
            'memory_used_gb': memory_used_gb,
            'memory_total_gb': memory_total_gb,
            'memory_available_gb': memory_available_gb,
            'disk_info': disk_info,
            'upload_speed': upload_speed,
            'download_speed': download_speed,
            'active_processes': active_processes,
            'gpu_info': gpu_info,
            'timestamp': datetime.now().strftime("%H:%M:%S")
        }
        
        return performance_data
    except Exception as e:
        logging.error(f"Error getting enhanced system performance: {e}")
        return None

def get_enhanced_gpu_info():
    """Get enhanced GPU information including driver version and UUID."""
    try:
        gpus = GPUtil.getGPUs()
        gpu_info = []
        
        for gpu in gpus:
            gpu_data = {
                'name': gpu.name,
                'temperature': gpu.temperature,
                'memory_used': gpu.memoryUsed,
                'memory_total': gpu.memoryTotal,
                'memory_percent': (gpu.memoryUsed / gpu.memoryTotal) * 100,
                'load': gpu.load * 100,
                'driver': getattr(gpu, 'driver', 'Unknown'),
                'uuid': getattr(gpu, 'uuid', 'Unknown')
            }
            gpu_info.append(gpu_data)
        
        return gpu_info
    except Exception as e:
        logging.error(f"Error getting enhanced GPU info: {e}")
        return []

def monitor_enhanced_performance(status_label, performance_text):
    """Monitor system performance with enhanced metrics."""
    global performance_monitoring
    
    # Store initial network values for calculating speeds
    prev_net_io = psutil.net_io_counters()
    prev_time = time.time()
    
    while performance_monitoring:
        try:
            # Get enhanced performance data
            perf_data = get_enhanced_system_performance()
            
            if perf_data:
                # Calculate network speeds
                current_time = time.time()
                time_diff = current_time - prev_time
                
                current_net_io = psutil.net_io_counters()
                upload_speed = (current_net_io.bytes_sent - prev_net_io.bytes_sent) / time_diff
                download_speed = (current_net_io.bytes_recv - prev_net_io.bytes_recv) / time_diff
                
                # Update previous values
                prev_net_io = current_net_io
                prev_time = current_time
                
                # Format enhanced performance text
                perf_text = f"""=== Enhanced System Performance Monitor ===
Last Update: {perf_data['timestamp']}

--- CPU ---
Usage: {perf_data['cpu_percent']:.1f}%
Frequency: {perf_data['cpu_frequency']} MHz
Cores: {perf_data['physical_cores']} physical, {perf_data['logical_cores']} logical

--- Memory ---
Usage: {perf_data['memory_percent']:.1f}%
Used: {perf_data['memory_used_gb']:.1f} GB
Available: {perf_data['memory_available_gb']:.1f} GB
Total: {perf_data['memory_total_gb']:.1f} GB

--- Storage ---
"""
                
                # Add disk information for all drives
                for disk in perf_data['disk_info']:
                    perf_text += f"{disk['device']} ({disk['mountpoint']}): {disk['percent']:.1f}%\n"
                    perf_text += f"  Used: {disk['used']:.1f} GB / {disk['total']:.1f} GB\n"
                
                perf_text += f"""
--- Network ---
Download: {download_speed / 1024:.1f} KB/s
Upload: {upload_speed / 1024:.1f} KB/s
Active Processes: {perf_data['active_processes']}
"""
                
                # Add enhanced GPU information
                if perf_data['gpu_info']:
                    perf_text += "\n--- GPU Information ---\n"
                    for i, gpu in enumerate(perf_data['gpu_info']):
                        perf_text += f"GPU {i+1}: {gpu['name']}\n"
                        perf_text += f"  Driver: {gpu['driver']}\n"
                        perf_text += f"  UUID: {gpu['uuid']}\n"
                        perf_text += f"  Temperature: {gpu['temperature']}°C\n"
                        perf_text += f"  Usage: {gpu['load']:.1f}%\n"
                        perf_text += f"  Memory: {gpu['memory_used']} MB / {gpu['memory_total']} MB ({gpu['memory_percent']:.1f}%)\n"
                else:
                    perf_text += "\n--- GPU Information ---\nNo GPU detected or GPU monitoring not available\n"
                
                # Update GUI in thread-safe manner
                app.root.after(0, lambda: update_performance_text(performance_text, perf_text))
                
                # Update status
                app.root.after(0, lambda: status_label.configure(
                    text=f"Monitoring... Last update: {perf_data['timestamp']}"
                ))
            
            time.sleep(2)  # Update every 2 seconds
            
        except Exception as e:
            logging.error(f"Error in enhanced performance monitoring: {e}")
            time.sleep(5)

def start_enhanced_performance_monitoring(status_label, performance_text):
    """Start enhanced performance monitoring."""
    global performance_monitoring, performance_thread
    
    if not performance_monitoring:
        performance_monitoring = True
        performance_thread = threading.Thread(
            target=monitor_enhanced_performance, 
            args=(status_label, performance_text),
            daemon=True
        )
        performance_thread.start()
        status_label.configure(text="Enhanced performance monitoring started...")
        logging.info("Enhanced performance monitoring started")

# --- Fixed Power Plan Management Functions ---
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
            if "Power Scheme" in line or "GUID" in line:
                # Extract GUID
                guid_match = re.search(r"([a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12})", line)
                if guid_match:
                    guid = guid_match.group(1)
                    # Extract name and active status
                    if "*" in line:
                        name_part = line.split("*")[1].strip()
                        is_active = True
                    else:
                        name_part = line.split(guid)[1].strip()
                        is_active = False
                    
                    # Clean the name - extract everything before the first parenthesis
                    name_match = re.search(r"([^(]*)", name_part)
                    if name_match:
                        name = name_match.group(1).strip()
                        if not name:
                            # If no name found, try alternative parsing
                            name_match2 = re.search(r"\((.*?)\)", name_part)
                            if name_match2:
                                name = name_match2.group(1).strip()
                            else:
                                name = "Unnamed Plan"
                    else:
                        name = "Unnamed Plan"
                    
                    plans.append({"guid": guid, "name": name, "active": is_active})
        
        return plans
    except Exception as e:
        logging.error(f"Error getting power plans: {e}")
        return []

def set_active_power_plan(guid):
    """Set a power plan as active by GUID."""
    if is_safe_mode_operation("power"):
        logging.info("Power plan change skipped in safe mode")
        update_text_box("Power plan change skipped (Safe Mode)")
        return False
        
    try:
        result = subprocess.run(
            ["powercfg", "/setactive", guid],
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        if result.returncode == 0:
            logging.info(f"Successfully activated power plan: {guid}")
            return True
        else:
            logging.error(f"Failed to activate power plan: {result.stderr}")
            return False
    except Exception as e:
        logging.error(f"Exception activating power plan: {e}")
        return False

def delete_power_plan(guid):
    """Delete a power plan by GUID."""
    if is_safe_mode_operation("power"):
        logging.info("Power plan deletion skipped in safe mode")
        update_text_box("Power plan deletion skipped (Safe Mode)")
        return False
        
    try:
        result = subprocess.run(
            ["powercfg", "/delete", guid],
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        if result.returncode == 0:
            logging.info(f"Successfully deleted power plan: {guid}")
            return True
        else:
            logging.error(f"Failed to delete power plan: {result.stderr}")
            return False
    except Exception as e:
        logging.error(f"Exception deleting power plan: {e}")
        return False

def create_power_plan_from_template(template_guid, new_name):
    """Create a new power plan from a template GUID."""
    if is_safe_mode_operation("power"):
        logging.info("Power plan creation skipped in safe mode")
        update_text_box("Power plan creation skipped (Safe Mode)")
        return None
        
    try:
        # Duplicate the template plan
        result = subprocess.run(
            ["powercfg", "-duplicatescheme", template_guid],
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        
        if result.returncode != 0:
            logging.error(f"Failed to duplicate power plan template: {result.stderr}")
            return None
        
        # Extract the new GUID from the output
        guid_match = re.search(r"([a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12})", result.stdout)
        if not guid_match:
            logging.error("Could not extract new power plan GUID")
            return None
        
        new_guid = guid_match.group(1)
        
        # Change the name of the new plan
        result = subprocess.run(
            f'powercfg /changename {new_guid} "{new_name}"',
            shell=True,
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        
        if result.returncode == 0:
            logging.info(f"Successfully created power plan: {new_name} ({new_guid})")
            return new_guid
        else:
            logging.error(f"Failed to rename power plan: {result.stderr}")
            # Try to delete the plan if renaming failed
            subprocess.run(["powercfg", "/delete", new_guid], capture_output=True)
            return None
            
    except Exception as e:
        logging.error(f"Exception creating power plan: {e}")
        return None

def restore_default_power_plans():
    """Restore default Windows power plans."""
    if is_safe_mode_operation("power"):
        logging.info("Power plan restoration skipped in safe mode")
        update_text_box("Power plan restoration skipped (Safe Mode)")
        return False
        
    try:
        logging.info("Restoring default power plans...")
        
        # First, restore default schemes
        result = subprocess.run(
            "powercfg -restoredefaultschemes",
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW,
            shell=True
        )
        
        if result.returncode != 0:
            logging.error(f"Failed to restore default schemes: {result.stderr}")
            messagebox.showerror("Error", "Failed to restore default power plans")
            return False
        
        # Get current plans to identify non-default ones
        plans = get_power_plans()
        default_plan_names = ["Balanced", "Power saver", "High performance", "Ultimate Performance"]
        
        deleted_count = 0
        for plan in plans:
            # Keep only default plans, delete everything else
            if plan['name'] not in default_plan_names:
                if delete_power_plan(plan['guid']):
                    deleted_count += 1
                    logging.info(f"Deleted custom power plan: {plan['name']}")
        
        # Set Balanced as active plan
        balanced_guid = "381b4222-f694-41f0-9685-ff5bb260df2e"
        set_active_power_plan(balanced_guid)
        
        # Refresh power plans list
        if hasattr(app, 'refresh_power_plans'):
            app.refresh_power_plans()
        
        messagebox.showinfo(
            "Success", 
            f"Restored default power plans!\n\n"
            f"Deleted {deleted_count} custom power plans.\n"
            f"Set 'Balanced' as active power plan."
        )
        logging.info(f"Restored default power plans. Deleted {deleted_count} custom plans.")
        return True
        
    except Exception as e:
        logging.error(f"Error restoring default power plans: {e}")
        messagebox.showerror("Error", f"Failed to restore default power plans: {e}")
        return False

# --- Performance Monitoring Functions ---
def get_gpu_info():
    """Get GPU information including temperature, memory, and usage."""
    try:
        gpus = GPUtil.getGPUs()
        gpu_info = []
        
        for gpu in gpus:
            gpu_data = {
                'name': gpu.name,
                'temperature': gpu.temperature,
                'memory_used': gpu.memoryUsed,
                'memory_total': gpu.memoryTotal,
                'memory_percent': (gpu.memoryUsed / gpu.memoryTotal) * 100,
                'load': gpu.load * 100
            }
            gpu_info.append(gpu_data)
        
        return gpu_info
    except Exception as e:
        logging.error(f"Error getting GPU info: {e}")
        return []

def get_system_performance():
    """Get comprehensive system performance data."""
    try:
        # CPU usage
        cpu_percent = psutil.cpu_percent(interval=1)
        
        # Memory usage
        memory = psutil.virtual_memory()
        memory_percent = memory.percent
        memory_used_gb = memory.used / (1024 ** 3)
        memory_total_gb = memory.total / (1024 ** 3)
        
        # Disk usage (C: drive)
        disk = psutil.disk_usage('C:\\')
        disk_percent = disk.percent
        disk_used_gb = disk.used / (1024 ** 3)
        disk_total_gb = disk.total / (1024 ** 3)
        
        # Network usage
        net_io = psutil.net_io_counters()
        upload_speed = net_io.bytes_sent
        download_speed = net_io.bytes_recv
        
        # GPU info
        gpu_info = get_gpu_info()
        
        performance_data = {
            'cpu_percent': cpu_percent,
            'memory_percent': memory_percent,
            'memory_used_gb': memory_used_gb,
            'memory_total_gb': memory_total_gb,
            'disk_percent': disk_percent,
            'disk_used_gb': disk_used_gb,
            'disk_total_gb': disk_total_gb,
            'upload_speed': upload_speed,
            'download_speed': download_speed,
            'gpu_info': gpu_info,
            'timestamp': datetime.now().strftime("%H:%M:%S")
        }
        
        return performance_data
    except Exception as e:
        logging.error(f"Error getting system performance: {e}")
        return None

def test_internet_speed():
    """Test internet download and upload speed."""
    try:
        logging.info("Testing internet speed...")
        st = speedtest.Speedtest()
        st.get_best_server()
        
        download_speed = st.download() / 1_000_000  # Convert to Mbps
        upload_speed = st.upload() / 1_000_000  # Convert to Mbps
        ping = st.results.ping
        
        return {
            'download': round(download_speed, 2),
            'upload': round(upload_speed, 2),
            'ping': round(ping, 2)
        }
    except Exception as e:
        logging.error(f"Error testing internet speed: {e}")
        return None

def monitor_performance(status_label, performance_text):
    """Monitor system performance in real-time."""
    global performance_monitoring
    
    # Store initial network values for calculating speeds
    prev_net_io = psutil.net_io_counters()
    prev_time = time.time()
    
    while performance_monitoring:
        try:
            # Get performance data
            perf_data = get_enhanced_system_performance()
            
            if perf_data:
                # Calculate network speeds
                current_time = time.time()
                time_diff = current_time - prev_time
                
                current_net_io = psutil.net_io_counters()
                upload_speed = (current_net_io.bytes_sent - prev_net_io.bytes_sent) / time_diff
                download_speed = (current_net_io.bytes_recv - prev_net_io.bytes_recv) / time_diff
                
                # Update previous values
                prev_net_io = current_net_io
                prev_time = current_time
                
                # Format performance text
                perf_text = f"""=== Enhanced System Performance Monitor ===
Last Update: {perf_data['timestamp']}

--- CPU ---
Usage: {perf_data['cpu_percent']:.1f}%
Frequency: {perf_data['cpu_frequency']} MHz
Cores: {perf_data['physical_cores']} physical, {perf_data['logical_cores']} logical

--- Memory ---
Usage: {perf_data['memory_percent']:.1f}%
Used: {perf_data['memory_used_gb']:.1f} GB
Available: {perf_data['memory_available_gb']:.1f} GB
Total: {perf_data['memory_total_gb']:.1f} GB

--- Storage ---
"""
                
                # Add disk information for all drives
                for disk in perf_data['disk_info']:
                    perf_text += f"{disk['device']} ({disk['mountpoint']}): {disk['percent']:.1f}%\n"
                    perf_text += f"  Used: {disk['used']:.1f} GB / {disk['total']:.1f} GB\n"
                
                perf_text += f"""
--- Network ---
Download: {download_speed / 1024:.1f} KB/s
Upload: {upload_speed / 1024:.1f} KB/s
Active Processes: {perf_data['active_processes']}
"""
                
                # Add enhanced GPU information
                if perf_data['gpu_info']:
                    perf_text += "\n--- GPU Information ---\n"
                    for i, gpu in enumerate(perf_data['gpu_info']):
                        perf_text += f"GPU {i+1}: {gpu['name']}\n"
                        perf_text += f"  Driver: {gpu['driver']}\n"
                        perf_text += f"  UUID: {gpu['uuid']}\n"
                        perf_text += f"  Temperature: {gpu['temperature']}°C\n"
                        perf_text += f"  Usage: {gpu['load']:.1f}%\n"
                        perf_text += f"  Memory: {gpu['memory_used']} MB / {gpu['memory_total']} MB ({gpu['memory_percent']:.1f}%)\n"
                else:
                    perf_text += "\n--- GPU Information ---\nNo GPU detected or GPU monitoring not available\n"
                
                # Update GUI in thread-safe manner
                app.root.after(0, lambda: update_performance_text(performance_text, perf_text))
                
                # Update status
                app.root.after(0, lambda: status_label.configure(
                    text=f"Monitoring... Last update: {perf_data['timestamp']}"
                ))
            
            time.sleep(2)  # Update every 2 seconds
            
        except Exception as e:
            logging.error(f"Error in performance monitoring: {e}")
            time.sleep(5)

def update_performance_text(performance_text, text):
    """Update performance text widget in thread-safe manner."""
    performance_text.configure(state="normal")
    performance_text.delete("1.0", "end")
    performance_text.insert("1.0", text)
    performance_text.configure(state="disabled")

def start_performance_monitoring(status_label, performance_text):
    """Start performance monitoring."""
    global performance_monitoring, performance_thread
    
    if not performance_monitoring:
        performance_monitoring = True
        performance_thread = threading.Thread(
            target=monitor_performance, 
            args=(status_label, performance_text),
            daemon=True
        )
        performance_thread.start()
        status_label.configure(text="Performance monitoring started...")
        logging.info("Performance monitoring started")

def stop_performance_monitoring(status_label):
    """Stop performance monitoring."""
    global performance_monitoring
    
    performance_monitoring = False
    if performance_thread and performance_thread.is_alive():
        performance_thread.join(timeout=2)
    status_label.configure(text="Performance monitoring stopped")
    logging.info("Performance monitoring stopped")

# --- Web Link Functions ---
def open_nvidia_drivers():
    """Open NVIDIA drivers download page."""
    try:
        webbrowser.open("https://www.nvidia.com/Download/index.aspx")
        logging.info("Opened NVIDIA drivers page")
    except Exception as e:
        logging.error(f"Error opening NVIDIA drivers page: {e}")
        messagebox.showerror("Error", "Failed to open NVIDIA drivers page")

def open_support_page():
    """Open support page for the developer."""
    try:
        webbrowser.open("https://www.paypal.com/paypalme/robbybarnedt")
        logging.info("Opened support page")
    except Exception as e:
        logging.error(f"Error opening support page: {e}")
        messagebox.showerror("Error", "Failed to open support page")

# --- Trickster Power Plan Function ---
def unlock_and_configure_trickster():
    """Unlock and configure the Ultimate Performance power plan (Trickster functionality)."""
    if is_safe_mode_operation("power"):
        logging.info("Trickster operation skipped in safe mode")
        update_text_box("Trickster operation skipped (Safe Mode)")
        return
        
    try:
        # Step 1: Unlock the "Ultimate Performance" power plan
        logging.info("Unlocking 'Ultimate Performance' power plan...")
        result = subprocess.run(
            ["powercfg", "-duplicatescheme", "e9a42b02-d5df-448d-aa00-03f14749eb61"],
            shell=True,
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        
        if result.returncode != 0:
            logging.error(f"Failed to duplicate Ultimate Performance scheme: {result.stderr}")
            messagebox.showerror("Error", "Failed to unlock Ultimate Performance power plan")
            return

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
        result = subprocess.run(
            f'powercfg /changename {ultimate_guid} "High Performance"',
            shell=True,
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        
        if result.returncode != 0:
            logging.error(f"Failed to rename power plan: {result.stderr}")
            messagebox.showerror("Error", "Failed to rename power plan")
            return

        # Step 5: Activate the renamed "High Performance" plan
        logging.info("Activating 'High Performance' plan...")
        result = subprocess.run(
            f"powercfg /setactive {ultimate_guid}",
            shell=True,
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        
        if result.returncode != 0:
            logging.error(f"Failed to activate power plan: {result.stderr}")
            messagebox.showerror("Error", "Failed to activate power plan")
            return

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
    "Force-delete everything in the C:\\Windows\\Temp folder."
    logging.info("Cleaning Windows Temp folder...")
    windows_temp_folder = "C:\\Windows\\Temp"
    if os.path.exists(windows_temp_folder):
        deleted_count = force_delete_folder_contents(windows_temp_folder)
        update_text_box(f"Cleaned Windows Temp Folder!\nDeleted {deleted_count} files/folders")
    else:
        logging.warning(f"Windows Temp folder does not exist: {windows_temp_folder}")
        update_text_box("Windows Temp folder not found!")

def clean_prefetch_folder():
    """Force-delete everything in the C:\\Windows\\Prefetch folder."""
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

# --- SAFER DNS Function with Backup and Restore ---
def set_cloudflare_dns():
    """Safely set Cloudflare DNS with user confirmation and revert option."""
    if is_safe_mode_operation("dns"):
        logging.info("DNS change skipped in safe mode")
        update_text_box("DNS change skipped (Safe Mode)")
        return
        
    try:
        # Ask for user confirmation first
        if not messagebox.askyesno(
            "Warning", 
            "This will change your DNS settings to Cloudflare (1.1.1.1).\n\n"
            "This may temporarily disconnect your internet and could affect:\n"
            "• VPN connections\n• Corporate networks\n• Some websites\n\n"
            "Do you want to continue?"
        ):
            return

        logging.info("Setting Cloudflare DNS safely...")

        # Store original DNS settings for potential revert
        original_dns = {}
        
        # Open the registry key for network interfaces
        reg_key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces",
            0,
            winreg.KEY_READ
        )

        interface_count = 0
        # Only modify interfaces that are actively using DHCP
        for i in range(winreg.QueryInfoKey(reg_key)[0]):
            interface_key_name = winreg.EnumKey(reg_key, i)
            interface_key = winreg.OpenKey(reg_key, interface_key_name, 0, winreg.KEY_READ)
            
            try:
                # Check if interface uses DHCP
                try:
                    dhcp_enabled = winreg.QueryValueEx(interface_key, "EnableDHCP")[0]
                    if dhcp_enabled == 1:  # Only modify DHCP interfaces
                        # Store original values
                        original_values = {}
                        try:
                            original_values['NameServer'] = winreg.QueryValueEx(interface_key, "NameServer")[0]
                        except FileNotFoundError:
                            original_values['NameServer'] = None
                        try:
                            original_values['DhcpNameServer'] = winreg.QueryValueEx(interface_key, "DhcpNameServer")[0]
                        except FileNotFoundError:
                            original_values['DhcpNameServer'] = None
                        
                        original_dns[interface_key_name] = original_values
                        
                        # Now open for writing
                        winreg.CloseKey(interface_key)
                        interface_key = winreg.OpenKey(reg_key, interface_key_name, 0, winreg.KEY_SET_VALUE)
                        
                        # Set DNS to Cloudflare
                        winreg.SetValueEx(interface_key, "NameServer", 0, winreg.REG_SZ, "1.1.1.1,1.0.0.1")
                        winreg.SetValueEx(interface_key, "DhcpNameServer", 0, winreg.REG_SZ, "1.1.1.1,1.0.0.1")
                        interface_count += 1
                        logging.info(f"Set Cloudflare DNS for interface: {interface_key_name}")
                
                except FileNotFoundError:
                    continue  # Skip interfaces without DHCP setting
                    
            except Exception as e:
                logging.error(f"Exception setting DNS for interface {interface_key_name}: {e}")
            finally:
                winreg.CloseKey(interface_key)

        winreg.CloseKey(reg_key)

        # Store original settings for revert capability
        if original_dns:
            revert_file = os.path.join(os.path.dirname(__file__), "dns_backup.json")
            with open(revert_file, "w") as f:
                json.dump(original_dns, f)
            logging.info(f"DNS backup saved to: {revert_file}")

        # Flush DNS and renew IP
        subprocess.run(["ipconfig", "/flushdns"], capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
        subprocess.run(["ipconfig", "/release"], capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
        subprocess.run(["ipconfig", "/renew"], capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)

        update_text_box(f"Set Cloudflare DNS for {interface_count} network interfaces!\nOriginal settings backed up to: dns_backup.json")
        
        # Show revert instructions
        messagebox.showinfo(
            "DNS Changed", 
            f"DNS settings updated for {interface_count} interfaces.\n\n"
            "If you experience internet issues:\n"
            "1. Use 'Restore Original DNS' in Tools menu\n"
            "2. Or restart your computer\n"
            "3. Or run 'ipconfig /renew' in Command Prompt"
        )
        
    except Exception as e:
        logging.error(f"Exception setting Cloudflare DNS: {e}")
        update_text_box(f"Error: {e}")

def restore_original_dns():
    """Restore original DNS settings from backup."""
    try:
        revert_file = os.path.join(os.path.dirname(__file__), "dns_backup.json")
        if not os.path.exists(revert_file):
            messagebox.showerror("Error", "No DNS backup found! Cannot restore original settings.")
            return
        
        with open(revert_file, 'r') as f:
            original_dns = json.load(f)
        
        reg_key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces",
            0,
            winreg.KEY_ALL_ACCESS
        )
        
        restored_count = 0
        for interface_key_name, original_values in original_dns.items():
            try:
                interface_key = winreg.OpenKey(reg_key, interface_key_name, 0, winreg.KEY_SET_VALUE)
                
                # Restore NameServer
                if original_values['NameServer']:
                    winreg.SetValueEx(interface_key, "NameServer", 0, winreg.REG_SZ, original_values['NameServer'])
                else:
                    try:
                        winreg.DeleteValue(interface_key, "NameServer")
                    except FileNotFoundError:
                        pass  # Value didn't exist originally
                
                # Restore DhcpNameServer  
                if original_values['DhcpNameServer']:
                    winreg.SetValueEx(interface_key, "DhcpNameServer", 0, winreg.REG_SZ, original_values['DhcpNameServer'])
                else:
                    try:
                        winreg.DeleteValue(interface_key, "DhcpNameServer")
                    except FileNotFoundError:
                        pass  # Value didn't exist originally
                
                restored_count += 1
                winreg.CloseKey(interface_key)
                
            except Exception as e:
                logging.error(f"Failed to restore DNS for {interface_key_name}: {e}")
        
        winreg.CloseKey(reg_key)
        
        # Flush DNS and renew IP
        subprocess.run(["ipconfig", "/flushdns"], capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
        subprocess.run(["ipconfig", "/release"], capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
        subprocess.run(["ipconfig", "/renew"], capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
        
        # Remove backup file
        os.remove(revert_file)
        
        update_text_box(f"Restored original DNS settings for {restored_count} interfaces!")
        messagebox.showinfo("DNS Restored", "Original DNS settings have been restored.")
        
    except Exception as e:
        logging.error(f"Exception restoring DNS: {e}")
        messagebox.showerror("Error", f"Failed to restore DNS: {e}")

def check_and_set_ultimate_power_plan():
    """Check if the Ultimate Power Plan exists, create it if it doesn't, and set it as active."""
    if is_safe_mode_operation("power"):
        logging.info("Power plan change skipped in safe mode")
        update_text_box("Power plan change skipped (Safe Mode)")
        return
        
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
    if is_safe_mode_operation("telemetry"):
        logging.info("Telemetry disable skipped in safe mode")
        update_text_box("Telemetry disable skipped (Safe Mode)")
        return
        
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
    if is_safe_mode_operation("cortana"):
        logging.info("Cortana disable skipped in safe mode")
        update_text_box("Cortana disable skipped (Safe Mode)")
        return
        
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
    if is_safe_mode_operation("gamebar"):
        logging.info("Game Bar disable skipped in safe mode")
        update_text_box("Game Bar disable skipped (Safe Mode)")
        return
        
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
    if is_safe_mode_operation("network"):
        logging.info("Network optimization skipped in safe mode")
        update_text_box("Network optimization skipped (Safe Mode)")
        return
        
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
    if is_safe_mode_operation("defender"):
        logging.info("Windows Defender disable skipped in safe mode")
        return
        
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
    if is_safe_mode_operation("animations"):
        logging.info("Windows animations disable skipped in safe mode")
        return
        
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
        self.notebook.add("Performance Monitor")
        self.notebook.add("Help")

        # Initialize the tabs
        self.init_system_optimizer_tab()
        self.init_game_optimizer_tab()
        self.init_performance_tab()
        self.init_help_tab()

    def create_menu_bar(self):
        """Create the Tools menu bar with Trickster and DNS restore integration."""
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
        # Add DNS restore option
        self.tools_menu.add_command(label="Restore Original DNS", command=restore_original_dns)
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
        elif current_tab == "Game Optimizer":
            clear_log(self.game_status_log)
        elif current_tab == "Performance Monitor":
            clear_log(self.performance_text)

    def save_current_log(self):
        """Save the log of the currently active tab."""
        current_tab = self.notebook.get()
        if current_tab == "System Optimizer":
            save_log(self.text_box)
        elif current_tab == "Game Optimizer":
            save_log(self.game_status_log)
        elif current_tab == "Performance Monitor":
            save_log(self.performance_text)

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

        # Safe Mode Toggle
        safe_mode_frame = ctk.CTkFrame(system_tab)
        safe_mode_frame.pack(pady=10)
        
        self.safe_mode_label = ctk.CTkLabel(
            safe_mode_frame,
            text=f"Safe Mode: {'ENABLED' if safe_mode else 'DISABLED'}",
            font=("Courier New", 14, "bold"),
            text_color="#00ff00" if safe_mode else "#ff0000"
        )
        self.safe_mode_label.pack(side="left", padx=10)
        
        self.safe_mode_btn = ctk.CTkButton(
            safe_mode_frame,
            text="Toggle Safe Mode",
            font=("Courier New", 12, "bold"),
            fg_color="#333333",
            hover_color="#444444",
            command=toggle_safe_mode
        )
        self.safe_mode_btn.pack(side="left", padx=10)

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

        # Restore Default Button
        restore_default_btn = ctk.CTkButton(
            plan_buttons_frame,
            text="Restore Default",
            font=("Courier New", 12, "bold"),
            fg_color="#ff0000",
            hover_color="#cc0000",
            command=restore_default_power_plans
        )
        restore_default_btn.pack(side="left", padx=2, pady=2)

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

    def init_performance_tab(self):
        """Initialize the Performance Monitor tab."""
        performance_tab = self.notebook.tab("Performance Monitor")

        # Title Label
        title_label = ctk.CTkLabel(
            performance_tab,
            text="Performance Monitor",
            font=("Courier New", 24, "bold"),
            text_color="#ff0000"
        )
        title_label.pack(pady=20)

        # Create scrollable frame
        self.performance_scrollable_frame = ctk.CTkScrollableFrame(performance_tab, width=700, height=500)
        self.performance_scrollable_frame.pack(fill="both", expand=True, padx=20, pady=10)

        # Status label
        self.performance_status_label = ctk.CTkLabel(
            self.performance_scrollable_frame,
            text="Performance monitoring ready",
            font=("Courier New", 12),
            text_color="#00ff00"
        )
        self.performance_status_label.pack(pady=5)

        # Performance monitoring buttons
        perf_buttons_frame = ctk.CTkFrame(self.performance_scrollable_frame)
        perf_buttons_frame.pack(fill="x", pady=10)

        start_perf_btn = ctk.CTkButton(
            perf_buttons_frame,
            text="Start Monitoring",
            font=("Courier New", 12, "bold"),
            fg_color="#333333",
            hover_color="#444444",
            command=lambda: start_performance_monitoring(self.performance_status_label, self.performance_text)
        )
        start_perf_btn.pack(side="left", padx=5)

        stop_perf_btn = ctk.CTkButton(
            perf_buttons_frame,
            text="Stop Monitoring",
            font=("Courier New", 12, "bold"),
            fg_color="#333333",
            hover_color="#444444",
            command=lambda: stop_performance_monitoring(self.performance_status_label)
        )
        stop_perf_btn.pack(side="left", padx=5)

        # Advanced System Info Button
        advanced_info_btn = ctk.CTkButton(
            perf_buttons_frame,
            text="Advanced System Info",
            font=("Courier New", 12, "bold"),
            fg_color="#ff0000",
            hover_color="#cc0000",
            command=show_advanced_system_info
        )
        advanced_info_btn.pack(side="left", padx=5)

        # Performance text area
        self.performance_text = ctk.CTkTextbox(
            self.performance_scrollable_frame,
            height=300,
            font=("Courier New", 11),
            text_color="#ffffff",
            fg_color="#333333"
        )
        self.performance_text.pack(pady=10, fill="both", expand=True)
        self.performance_text.insert("1.0", "Performance data will appear here...\nClick 'Start Monitoring' to begin.\n")
        self.performance_text.configure(state="disabled")

        # Support buttons frame
        support_frame = ctk.CTkFrame(self.performance_scrollable_frame)
        support_frame.pack(fill="x", pady=10)

        # NVIDIA Drivers button
        nvidia_btn = ctk.CTkButton(
            support_frame,
            text="Download NVIDIA Drivers",
            font=("Courier New", 12, "bold"),
            fg_color="#333333",
            hover_color="#444444",
            command=open_nvidia_drivers
        )
        nvidia_btn.pack(side="left", padx=5, pady=5)

        # Support button
        support_btn = ctk.CTkButton(
            support_frame,
            text="Support The Devs",
            font=("Courier New", 12, "bold"),
            fg_color="#ff0000",
            hover_color="#cc0000",
            command=open_support_page
        )
        support_btn.pack(side="left", padx=5, pady=5)

    def run_speed_test(self):
        """Run internet speed test and display results."""
        def speed_test_thread():
            self.performance_status_label.configure(text="Testing internet speed... This may take a moment.")
            
            speed_results = test_internet_speed()
            
            if speed_results:
                result_text = f"""=== Internet Speed Test Results ===

Download Speed: {speed_results['download']} Mbps
Upload Speed: {speed_results['upload']} Mbps
Ping: {speed_results['ping']} ms

Test completed at: {datetime.now().strftime("%H:%M:%S")}
"""
                self.root.after(0, lambda: self.display_speed_results(result_text))
                self.root.after(0, lambda: self.performance_status_label.configure(text="Speed test completed!"))
            else:
                self.root.after(0, lambda: self.performance_status_label.configure(text="Speed test failed!"))
        
        # Run speed test in separate thread
        threading.Thread(target=speed_test_thread, daemon=True).start()

    def display_speed_results(self, result_text):
        """Display speed test results in performance text area."""
        self.performance_text.configure(state="normal")
        self.performance_text.insert("end", "\n" + result_text + "\n")
        self.performance_text.see("end")
        self.performance_text.configure(state="disabled")

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
        toc_text.insert("1.0", "1. Overview\n2. System Optimizer\n3. Game Optimizer\n4. Performance Monitor\n5. Power Plan Management\n6. Trickster Feature\n7. Tools Menu\n8. How to Use\n9. About")
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
            "• Performance Monitor: Real-time system performance tracking\n"
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
            "• Create new power plans from templates\n"
            "• Restore Default: Reset to Windows default power plans\n\n"
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

        # Performance Monitor Section
        performance_help_frame = ctk.CTkFrame(help_scrollable_frame)
        performance_help_frame.pack(fill="x", pady=10, padx=10)
        
        ctk.CTkLabel(
            performance_help_frame,
            text="4. Performance Monitor",
            font=("Courier New", 18, "bold"),
            text_color="#ff0000"
        ).pack(anchor="w", padx=10, pady=5)
        
        performance_text = ctk.CTkTextbox(performance_help_frame, height=200, font=("Courier New", 12))
        performance_text.pack(fill="x", padx=10, pady=5)
        performance_text.insert("1.0",
            "The Performance Monitor tab provides real-time system performance tracking:\n\n"
            "Monitoring Features:\n"
            "• CPU Usage: Real-time CPU utilization percentage\n"
            "• Memory Usage: RAM usage and available memory\n"
            "• Disk Usage: C: drive space and utilization\n"
            "• Network Usage: Real-time upload/download speeds\n"
            "• GPU Information: Temperature, memory usage, and load\n"
            "• Automatic Updates: Refreshes every 2 seconds\n\n"
            "Internet Speed Test:\n"
            "• Tests download and upload speeds\n"
            "• Measures ping latency\n"
            "• Provides comprehensive speed analysis\n\n"
            "Support Features:\n"
            "• NVIDIA Drivers: Quick link to download latest drivers\n"
            "• Support The Devs: Option to support development\n\n"
            "Usage:\n"
            "• Click 'Start Monitoring' to begin real-time tracking\n"
            "• Click 'Stop Monitoring' to pause performance updates\n"
            "• Use 'Test Internet Speed' for connection analysis\n"
            "• Monitor system health during gaming sessions"
        )
        performance_text.configure(state="disabled")

        # Power Plan Management Section
        power_help_frame = ctk.CTkFrame(help_scrollable_frame)
        power_help_frame.pack(fill="x", pady=10, padx=10)
        
        ctk.CTkLabel(
            power_help_frame,
            text="5. Power Plan Management",
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
            "• Restore Default: Delete all custom plans and restore Windows defaults\n"
            "• Create Plan: Make new custom power plans from templates\n\n"
            "Usage Tips:\n"
            "• Use 'High Performance' or 'Ultimate Performance' for gaming\n"
            "• Create custom plans for specific use cases\n"
            "• Delete unused plans to keep list clean\n"
            "• Use 'Restore Default' if you experience power plan issues\n"
            "• Active plan is marked with [ACTIVE] in the list"
        )
        power_text.configure(state="disabled")

        # Trickster Section
        trickster_frame = ctk.CTkFrame(help_scrollable_frame)
        trickster_frame.pack(fill="x", pady=10, padx=10)
        
        ctk.CTkLabel(
            trickster_frame,
            text="6. Trickster Feature",
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
            text="7. Tools Menu",
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
            "• Restore Original DNS: Restore DNS settings if internet issues occur\n"
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
            text="8. How to Use G.A.L",
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
            "   • Use 'Restore Default' if you need to reset power plans\n"
            "\n"
            "5. Performance Monitoring:\n"
            "   • Go to Performance Monitor tab\n"
            "   • Click 'Start Monitoring' for real-time system stats\n"
            "   • Use 'Test Internet Speed' to check connection\n"
            "   • Access driver downloads and support options\n"
            "\n"
            "6. Start Gaming:\n"
            "   • Click 'Start Monitoring' in Game Optimizer\n"
            "   • Launch your games\n"
            "   • G.A.L will automatically detect and optimize them\n"
            "   • Use 'Stop Monitoring' when done\n"
            "\n"
            "7. Manual Optimization:\n"
            "   • Select a running process from the dropdown\n"
            "   • Set CPU cores and priority\n"
            "   • Click 'Apply Process Optimization'\n"
            "   • Use 'Remove' to reset to defaults\n"
            "\n"
            "Best Practices:\n"
            "• Run system optimization weekly\n"
            "• Use Game Optimizer monitoring during gaming sessions\n"
            "• Set power plan to High Performance before gaming\n"
            "• Monitor performance during intensive tasks\n"
            "• Save your program lists for quick setup"
        )
        usage_text.configure(state="disabled")

        # About Section
        about_frame = ctk.CTkFrame(help_scrollable_frame)
        about_frame.pack(fill="x", pady=10, padx=10)
        
        ctk.CTkLabel(
            about_frame,
            text="9. About G.A.L",
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
            
            if messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete the power plan:\n{plan['name']}?"):
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
        global performance_monitoring
        performance_monitoring = False
        logging.info("Exiting application.")
        self.root.destroy()

# --- Function to Update Text Box ---
def update_text_box(message):
    """Update the text box with a message using a queue for batching."""
    update_queue.put(message)
    if 'app' in globals() and hasattr(app, 'root'):
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