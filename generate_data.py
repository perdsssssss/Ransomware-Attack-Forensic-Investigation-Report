import pandas as pd
import random
from datetime import datetime, timedelta

# Set random seed for reproducibility
random.seed(42)

print("Generating ransomware attack simulation data...")

# Configuration
NUM_EVENTS = 600
NUM_WORKSTATIONS = 20
NUM_SERVERS = 2
ATTACK_START = datetime(2025, 9, 27, 14, 15, 0)  # Sept 27, 2:15 PM
ATTACK_END = datetime(2025, 9, 27, 15, 45, 0)    # Sept 27, 3:45 PM
SIMULATION_START = datetime(2025, 9, 26, 8, 0, 0)
SIMULATION_END = datetime(2025, 9, 28, 16, 0, 0)

# Define legitimate and malicious processes
legitimate_processes = [
    "explorer.exe", "chrome.exe", "outlook.exe", "excel.exe", 
    "word.exe", "powerpnt.exe", "teams.exe", "svchost.exe",
    "notepad.exe", "python.exe", "msedge.exe", "firefox.exe"
]

malicious_processes = [
    "update_office365.exe", "svchost32.exe", "encrypt_v2.exe",
    "system_update.exe", "windows_defender_real.exe"
]

# Internal IP ranges
internal_ips = [f"192.168.1.{i}" for i in range(10, 200)]
external_malicious_ip = "45.129.33.197"

# Generate hostnames
workstations = [f"WORKSTATION-{str(i).zfill(3)}" for i in range(1, NUM_WORKSTATIONS + 1)]
servers = [f"SERVER-{str(i).zfill(2)}" for i in range(1, NUM_SERVERS + 1)]
all_hosts = workstations + servers

# Common usernames
usernames = ["jsmith", "mjones", "akumar", "lchen", "rdavis", "spatil", "tgarcia", "SYSTEM"]

# File paths
legitimate_files = [
    "C:\\Users\\{user}\\Documents\\report.docx",
    "C:\\Users\\{user}\\Documents\\presentation.pptx",
    "C:\\Users\\{user}\\Desktop\\data.xlsx",
    "C:\\Users\\{user}\\Downloads\\document.pdf",
    "C:\\Program Files\\Microsoft Office\\templates\\normal.dotm"
]

system_files = [
    "C:\\Windows\\System32\\config\\SAM",
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "C:\\ProgramData\\Microsoft\\Crypto\\RSA\\shadow.key"
]

# Event types
event_types = ["file_access", "file_modification", "process_creation", "network_connection", "registry_change"]

# Generate events
events = []
event_id = 10000

# Patient zero: WORKSTATION-003
patient_zero_host = "WORKSTATION-003"
patient_zero_user = "mjones"

# Phase 1: Normal baseline activity (85% of events before attack)
normal_events_count = int(NUM_EVENTS * 0.70)

for i in range(normal_events_count):
    # Random timestamp before attack or after attack (normal activity continues)
    if random.random() < 0.7:
        timestamp = SIMULATION_START + timedelta(
            seconds=random.randint(0, int((ATTACK_START - SIMULATION_START).total_seconds()))
        )
    else:
        timestamp = ATTACK_END + timedelta(
            seconds=random.randint(0, int((SIMULATION_END - ATTACK_END).total_seconds()))
        )
    
    hostname = random.choice(all_hosts)
    user = random.choice(usernames[:-1])  # Exclude SYSTEM for normal activity
    process = random.choice(legitimate_processes)
    event_type = random.choice(event_types)
    
    file_modified = "NaN"
    network_connection = "NaN"
    
    if event_type == "file_modification":
        file_modified = random.choice(legitimate_files).format(user=user)
    elif event_type == "network_connection":
        network_connection = random.choice(internal_ips)
    
    severity = random.choice(["Low", "Low", "Low", "Medium"])
    
    raw_message = f"Normal activity: {process} on {hostname}"
    
    events.append({
        "event_id": event_id,
        "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "hostname": hostname,
        "user_account": user if random.random() > 0.05 else "NaN",
        "process_name": process,
        "event_type": event_type,
        "file_modified": file_modified,
        "network_connection": network_connection,
        "event_severity": severity,
        "raw_message": raw_message
    })
    event_id += 1

# Phase 2: Attack sequence (15% of events)
attack_events_count = NUM_EVENTS - normal_events_count

# Initial compromise
initial_time = ATTACK_START
events.append({
    "event_id": event_id,
    "timestamp": initial_time.strftime("%Y-%m-%d %H:%M:%S"),
    "hostname": patient_zero_host,
    "user_account": patient_zero_user,
    "process_name": malicious_processes[0],
    "event_type": "process_creation",
    "file_modified": "NaN",
    "network_connection": external_malicious_ip,
    "event_severity": "Critical",
    "raw_message": f"Suspicious process {malicious_processes[0]} created by {patient_zero_user}"
})
event_id += 1

# Reconnaissance phase (2:15 PM - 2:45 PM)
recon_start = ATTACK_START + timedelta(minutes=5)
recon_end = ATTACK_START + timedelta(minutes=30)

for i in range(int(attack_events_count * 0.2)):
    timestamp = recon_start + timedelta(
        seconds=random.randint(0, int((recon_end - recon_start).total_seconds()))
    )
    
    hostname = patient_zero_host if random.random() < 0.6 else random.choice(workstations[:min(10, len(workstations))])
    
    events.append({
        "event_id": event_id,
        "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "hostname": hostname,
        "user_account": patient_zero_user if random.random() > 0.3 else "SYSTEM",
        "process_name": random.choice(malicious_processes),
        "event_type": "network_connection",
        "file_modified": "NaN",
        "network_connection": random.choice(internal_ips) if random.random() > 0.3 else external_malicious_ip,
        "event_severity": "High",
        "raw_message": "Network scanning activity detected"
    })
    event_id += 1

# Lateral movement phase (2:45 PM - 3:15 PM)
lateral_start = ATTACK_START + timedelta(minutes=30)
lateral_end = ATTACK_START + timedelta(minutes=60)

compromised_hosts = [patient_zero_host] + random.sample(workstations, min(10, len(workstations)-1))

for i in range(int(attack_events_count * 0.3)):
    timestamp = lateral_start + timedelta(
        seconds=random.randint(0, int((lateral_end - lateral_start).total_seconds()))
    )
    
    hostname = random.choice(compromised_hosts)
    
    events.append({
        "event_id": event_id,
        "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "hostname": hostname,
        "user_account": "SYSTEM",
        "process_name": malicious_processes[1],
        "event_type": "process_creation",
        "file_modified": random.choice(system_files) if random.random() > 0.5 else "NaN",
        "network_connection": external_malicious_ip if random.random() > 0.7 else "NaN",
        "event_severity": "Critical",
        "raw_message": f"Lateral movement: {malicious_processes[1]} spreading to {hostname}"
    })
    event_id += 1

# Encryption phase (3:15 PM - 3:45 PM)
encrypt_start = ATTACK_START + timedelta(minutes=60)
encrypt_end = ATTACK_END

for i in range(int(attack_events_count * 0.5)):
    timestamp = encrypt_start + timedelta(
        seconds=random.randint(0, int((encrypt_end - encrypt_start).total_seconds()))
    )
    
    hostname = random.choice(compromised_hosts)
    user = random.choice(usernames[:-1])
    
    file_path = random.choice(legitimate_files).format(user=user)
    encrypted_file = file_path.replace(".docx", ".locked").replace(".xlsx", ".locked").replace(".pptx", ".locked")
    
    events.append({
        "event_id": event_id,
        "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "hostname": hostname,
        "user_account": "SYSTEM",
        "process_name": malicious_processes[2],
        "event_type": "file_modification",
        "file_modified": encrypted_file,
        "network_connection": "NaN",
        "event_severity": "Critical",
        "raw_message": f"File encryption: {file_path} encrypted by {malicious_processes[2]}"
    })
    event_id += 1

# Sort events by timestamp
events_df = pd.DataFrame(events)
events_df['timestamp_sort'] = pd.to_datetime(events_df['timestamp'])
events_df = events_df.sort_values('timestamp_sort').drop('timestamp_sort', axis=1)

# Save to CSV
output_file = "final_project_raw_data.csv"
events_df.to_csv(output_file, index=False)

print(f"\n✓ Successfully generated {len(events_df)} system events")
print(f"✓ Saved to: {output_file}")
print(f"\nData Summary:")
print(f"  - Simulation Period: {SIMULATION_START} to {SIMULATION_END}")
print(f"  - Attack Window: {ATTACK_START} to {ATTACK_END}")
print(f"  - Total Hosts: {len(all_hosts)} ({NUM_WORKSTATIONS} workstations, {NUM_SERVERS} servers)")
print(f"  - Compromised Hosts: {len(compromised_hosts)}")
print(f"  - Patient Zero: {patient_zero_host} (User: {patient_zero_user})")
print(f"  - Malicious C&C Server: {external_malicious_ip}")
print(f"\nRaw data generation complete!")
