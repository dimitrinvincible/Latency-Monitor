import subprocess
import time
import ctypes
import re
import psutil
from scapy.all import sniff, IP
from datetime import datetime
import pynvml


# ---------------- CONFIGURATION ----------------
TARGET = "8.8.8.8"  # Target IP for testing, using Google DNS for default but can be changed
LATENCY_THRESHOLD_MS = 100 # Change this for your desired latency number
PING_INTERVAL = 3  # in seconds, how often program will ping
PROCESS_TO_MONITOR = "ReadyOrNot-Win64-Shipping.exe"  # Change as needed for program to look for
# Ready or Not was just the program that had latency and made me create this

# I only added this because I was having issues during testing with talking to my GPU, figured I'd leave it
pynvml.nvmlLib = ctypes.CDLL("C:\\Windows\\System32\\nvml.dll")


# Initialize NVML once
pynvml.nvmlInit()

# ---------------- UTILITIES ----------------
# Gather latency information
def get_latency(host):
    try:
        output = subprocess.check_output(["ping", "-n", "1", host], universal_newlines=True)
        match = re.search(r"Average = (\d+)ms", output)
        return int(match.group(1)) if match else None
    except subprocess.CalledProcessError as e:
        print(f"Ping failed: {e}")
        return None

# Recognizing that target process is running
def is_process_running(name):
    for proc in psutil.process_iter(['name']):
        try:
            if name.lower() in proc.info['name'].lower():
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return False

# ---------------- MONITORING ACTIONS ----------------
# Monitoring and taking action for latency increase
def handle_latency_spike(latency):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[!] High latency detected: {latency}ms")
    with open("latency_spikes.log", "a") as f:
        f.write(f"{timestamp} - High latency: {latency}ms\n")
    inspect_traffic()
    log_hardware_stats()
    log_gpu_stats()

def inspect_traffic(duration=10, filter_str="ip", log_file="packet_inspection.log"):
    print(f"[INFO] Sniffing packets for {duration}s...")
    packets = sniff(filter=filter_str, timeout=duration)
    with open(log_file, "a") as f:
        for pkt in packets:
            if IP in pkt:
                src = pkt[IP].src
                dst = pkt[IP].dst
                proto = pkt[IP].proto
                summary = pkt.summary()
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                f.write(f"[{timestamp}] {src} -> {dst} | Proto: {proto} | {summary}\n")
    print(f"[INFO] Packet inspection complete. {len(packets)} packets captured.")

# Log hardware information
def log_hardware_stats(log_file="hardware_usage.log"):
    cpu = psutil.cpu_percent(interval=1)
    ram = psutil.virtual_memory()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(log_file, "a") as f:
        f.write(f"[{timestamp}] CPU: {cpu:.1f}% | RAM: {ram.used/1024**3:.2f} GB / {ram.total/1024**3:.2f} GB ({ram.percent}%)\n")
    print(f"[INFO] CPU: {cpu:.1f}%, RAM: {ram.percent:.1f}%")

# Log GPU information
def log_gpu_stats(log_file="hardware_usage.log"):
    try:
        handle = pynvml.nvmlDeviceGetHandleByIndex(0)
        util = pynvml.nvmlDeviceGetUtilizationRates(handle)
        mem = pynvml.nvmlDeviceGetMemoryInfo(handle)
        temp = pynvml.nvmlDeviceGetTemperature(handle, pynvml.NVML_TEMPERATURE_GPU)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(log_file, "a") as f:
            f.write(f"[{timestamp}] GPU: {util.gpu}% | Mem: {mem.used/1024**2:.0f}MB / {mem.total/1024**2:.0f}MB | Temp: {temp}°C\n")
        print(f"[INFO] GPU: {util.gpu}%, Temp: {temp}°C")
    except Exception as e:
        print(f"[ERROR] GPU logging failed: {e}")

# ---------------- MAIN LOOP ----------------
def monitor_latency():
    print(f"[INFO] Monitoring latency to {TARGET} (threshold: {LATENCY_THRESHOLD_MS}ms)...")
    while True:
        if not is_process_running(PROCESS_TO_MONITOR):
            print(f"[INFO] {PROCESS_TO_MONITOR} not running. Skipping check...")
            time.sleep(5)
            continue

        latency = get_latency(TARGET)
        if latency is not None:
            print(f"[INFO] Latency: {latency}ms")
            if latency > LATENCY_THRESHOLD_MS:
                handle_latency_spike(latency)
        else:
            print("[WARN] No response or latency not found.")
        time.sleep(PING_INTERVAL)

if __name__ == "__main__":
    try:
        monitor_latency()
    finally:
        pynvml.nvmlShutdown()
