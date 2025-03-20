import os
import subprocess
import datetime
import sys
import time
import threading
from colorama import Fore, Style, init

init()
loading_finished = False

def get_file_size(file_path):
    if os.path.exists(file_path):
        return os.path.getsize(file_path)
    return 0

def animate_loading(backup_file):
    global loading_finished
    chars = "/—\\|"
    initial_size = 0
    while not loading_finished:
        current_size = get_file_size(backup_file)
        if current_size > initial_size:
            percentage = (current_size / (1024 * 1024))
            if percentage > 100:
                percentage = 100
            for char in chars:
                sys.stdout.write(
                    f"\r{Fore.YELLOW}Backing up... {char} {Fore.CYAN}{current_size / (1024 * 1024):.2f} MB {Fore.GREEN}({percentage:.2f}%){Style.RESET_ALL}"
                )
                sys.stdout.flush()
                time.sleep(0.1)
        else:
            for char in chars:
                sys.stdout.write(f"\r{Fore.YELLOW}Backing up... {char} {Fore.RED}Waiting to start...{Style.RESET_ALL}")
                sys.stdout.flush()
                time.sleep(0.1)
    sys.stdout.write(f"\r{Fore.GREEN}Backup complete!{' ' * 50}{Style.RESET_ALL}\n")  # Clear animation after completion


def list_devices():
    print(f"\n{Fore.CYAN}📱 Detecting connected devices...{Style.RESET_ALL}")
    result = subprocess.run(["adb", "devices"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    devices = []
    for line in result.stdout.splitlines():
        if "device" in line and not line.startswith("List"):
            devices.append(line.split("\t")[0])
    if not devices:
        print(f"{Fore.RED}🚨 No devices found. Please connect your Android device and enable USB debugging.{Style.RESET_ALL}")
        sys.exit(1)
    return devices

def select_device(devices):
    print(f"{Fore.CYAN}🔢 Select a device to backup:{Style.RESET_ALL}")
    for i, device in enumerate(devices):
        print(f"{Fore.YELLOW}[{i + 1}] {device}{Style.RESET_ALL}")
    choice = int(input(f"{Fore.GREEN}👉 Enter device number: {Style.RESET_ALL}")) - 1
    if choice < 0 or choice >= len(devices):
        print(f"{Fore.RED}❌ Invalid selection.{Style.RESET_ALL}")
        sys.exit(1)
    return devices[choice]

def backup_android_device(device):
    global loading_finished
    loading_finished = False

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_file = f"android_backup_{timestamp}.ab"

    adb_command = ["adb", "-s", device, "backup", "-apk", "-shared", "-all", "-f", backup_file]

    loading_thread = threading.Thread(target=animate_loading, args=(backup_file,))
    loading_thread.start()

    print(f"\n{Fore.CYAN}🚀 Starting backup to file: {backup_file}{Style.RESET_ALL}")
    process = subprocess.Popen(adb_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()

    loading_finished = True
    loading_thread.join()
  
    if process.returncode == 0:
        final_size = get_file_size(backup_file) / (1024 * 1024)
        print(f"{Fore.GREEN}✅ Backup successfully saved to: {backup_file} ({final_size:.2f} MB){Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}❌ Backup failed.{Style.RESET_ALL}")
        print(f"{Fore.RED}Error: {stderr.decode('utf-8')}{Style.RESET_ALL}")

if __name__ == "__main__":
    print(f"{Fore.CYAN}🔌 Make sure your Android device is connected and USB debugging is enabled.{Style.RESET_ALL}")
    input(f"{Fore.GREEN}👉 Press Enter to continue...{Style.RESET_ALL}")
    devices = list_devices()
    selected_device = select_device(devices)
    print(f"{Fore.GREEN}📱 Selected device: {selected_device}{Style.RESET_ALL}")
    backup_android_device(selected_device)
