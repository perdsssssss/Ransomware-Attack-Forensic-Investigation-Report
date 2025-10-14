import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
import matplotlib.pyplot as plt
import seaborn as sns
import re

print("="*60)
print("ACTIVITY 12: RANSOMWARE ATTACK ANALYSIS")
print("="*60)

# ============================================================================
# STEP 1: LOAD DATA
# ============================================================================
print("\n[STEP 1/4] Loading cleaned data...")
try:
    df = pd.read_csv('final_project_cleaned_data.csv')
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    print(f"✓ Loaded {len(df)} events from final_project_cleaned_data.csv")
    print(f"✓ Date Range: {df['timestamp'].min()} to {df['timestamp'].max()}")
except FileNotFoundError:
    print("ERROR: final_project_cleaned_data.csv not found!")
    print("Please run preprocess_data.py first (Activity 11)")
    exit(1)

# ============================================================================
# STEP 2: ENTITY EXTRACTION (NLP-based)
# ============================================================================
print("\n" + "="*60)
print("[STEP 2/4] ENTITY EXTRACTION")
print("="*60)
print("\nExtracting suspicious entities from system logs...")

# Initialize entity lists
malicious_processes = []
external_ips = []
encrypted_files = []

# Extract malicious processes using regex patterns
print("\n• Searching for malicious processes...")
suspicious_patterns = [
    r'update.*\.exe$',      # update_office365.exe
    r'svchost\d+\.exe$',    # svchost32.exe
    r'encrypt.*\.exe$'      # encrypt_v2.exe
]

for process in df['process_name'].unique():
    for pattern in suspicious_patterns:
        if re.search(pattern, str(process), re.IGNORECASE):
            malicious_processes.append(process)
            break

print(f"  ✓ Found {len(malicious_processes)} malicious processes")

# Extract external IPs (not 192.168.x.x)
print("\n• Searching for external IP connections...")
for ip in df['network_connection'].unique():
    if ip != "NONE" and not str(ip).startswith('192.168'):
        external_ips.append(ip)

print(f"  ✓ Found {len(external_ips)} external IPs")

# Extract encrypted files (.locked extension)
print("\n• Searching for encrypted files...")
encrypted_files = df[df['file_modified'].str.contains('.locked', na=False)]['file_modified'].unique().tolist()
print(f"  ✓ Found {len(encrypted_files)} encrypted files")

# Create entity summary DataFrame
print("\n• Creating entity summary...")
entity_data = []

# Add malicious processes
for proc in malicious_processes:
    events = df[df['process_name'] == proc]
    entity_data.append({
        'entity_type': 'malicious_process',
        'entity_value': proc,
        'frequency': len(events),
        'first_seen': events['timestamp'].min(),
        'last_seen': events['timestamp'].max(),
        'hostnames': ', '.join(events['hostname'].unique()[:3])
    })

# Add external IPs
for ip in external_ips:
    events = df[df['network_connection'] == ip]
    entity_data.append({
        'entity_type': 'external_ip',
        'entity_value': ip,
        'frequency': len(events),
        'first_seen': events['timestamp'].min(),
        'last_seen': events['timestamp'].max(),
        'hostnames': ', '.join(events['hostname'].unique()[:3])
    })

# Add encrypted files (limit to 10 for readability)
for file in encrypted_files[:10]:
    events = df[df['file_modified'] == file]
    entity_data.append({
        'entity_type': 'encrypted_file',
        'entity_value': file,
        'frequency': len(events),
        'first_seen': events['timestamp'].min(),
        'last_seen': events['timestamp'].max(),
        'hostnames': ', '.join(events['hostname'].unique()[:3])
    })

entities_df = pd.DataFrame(entity_data)
entities_df = entities_df.sort_values(['entity_type', 'frequency'], ascending=[True, False])

# Save entities
entities_df.to_csv('final_project_entities.csv', index=False)

print("\n✓ Entity Extraction Complete!")
print(f"\nSummary:")
print(f"  • Total Entities: {len(entities_df)}")
print(f"  • Malicious Processes: {len(malicious_processes)}")
print(f"  • External IPs: {len(external_ips)}")
print(f"  • Encrypted Files: {len(encrypted_files)}")
print(f"\n✓ Saved to: final_project_entities.csv")

# Display top entities
print("\nTop 5 Most Frequent Entities:")
for idx, row in entities_df.head(5).iterrows():
    print(f"  • {row['entity_type']}: {row['entity_value']} ({row['frequency']} occurrences)")

# ============================================================================
# STEP 3: ANOMALY DETECTION (Isolation Forest)
# ============================================================================
print("\n" + "="*60)
print("[STEP 3/4] ANOMALY DETECTION")
print("="*60)
print("\nApplying Isolation Forest to detect suspicious events...")

# Prepare features for machine learning
print("\n• Encoding categorical variables...")
le_severity = LabelEncoder()
le_event = LabelEncoder()

df['severity_encoded'] = le_severity.fit_transform(df['event_severity'])
df['event_type_encoded'] = le_event.fit_transform(df['event_type'])

print("  ✓ Encoded event_severity")
print("  ✓ Encoded event_type")

# Create binary features
print("\n• Creating binary features...")
df['is_suspicious_process'] = df['process_name'].isin(malicious_processes).astype(int)
df['is_encrypted'] = df['file_modified'].str.contains('.locked', na=False).astype(int)

print(f"  ✓ Suspicious processes flagged: {df['is_suspicious_process'].sum()}")
print(f"  ✓ Encrypted files flagged: {df['is_encrypted'].sum()}")

# Select features for Isolation Forest
features = [
    'hour_of_day',           # Time-based
    'is_weekend',            # Time-based
    'is_after_hours',        # Time-based
    'severity_encoded',      # Severity level
    'is_external_ip',        # Network-based
    'is_suspicious_process', # Process-based
    'is_encrypted'           # File-based
]

print(f"\n• Selected {len(features)} features for anomaly detection:")
for feat in features:
    print(f"  - {feat}")

X = df[features].fillna(0)

# Train Isolation Forest model
print("\n• Training Isolation Forest model...")
print("  Parameters:")
print("    - contamination: 0.15 (expect 15% anomalies)")
print("    - n_estimators: 100")
print("    - random_state: 42")

iso_forest = IsolationForest(
    contamination=0.15,    # Expect 15% attack events
    n_estimators=100,
    random_state=42,
    n_jobs=-1
)

# Predict anomalies
predictions = iso_forest.fit_predict(X)
df['is_anomaly'] = (predictions == -1).astype(int)
df['anomaly_score'] = iso_forest.score_samples(X)

anomaly_count = df['is_anomaly'].sum()
normal_count = len(df) - anomaly_count
anomaly_percentage = (anomaly_count / len(df)) * 100

print("\n✓ Anomaly Detection Complete!")
print(f"\nResults:")
print(f"  • Total Events: {len(df)}")
print(f"  • Normal Events: {normal_count} ({100-anomaly_percentage:.1f}%)")
print(f"  • Anomalies Detected: {anomaly_count} ({anomaly_percentage:.1f}%)")

# Show top anomalies
print("\n• Top 5 Most Anomalous Events:")
top_anomalies = df[df['is_anomaly'] == 1].sort_values('anomaly_score').head(5)
for i, (idx, row) in enumerate(top_anomalies.iterrows(), 1):
    print(f"  {i}. {row['timestamp']} | {row['hostname']}")
    print(f"     Process: {row['process_name']} | Severity: {row['event_severity']}")
    print(f"     Anomaly Score: {row['anomaly_score']:.4f}")

# Identify patient zero (first anomaly with suspicious activity)
print("\n• Identifying Patient Zero...")
suspicious = df[(df['is_anomaly'] == 1) & (df['is_suspicious_process'] == 1)].sort_values('timestamp')
if len(suspicious) > 0:
    patient_zero = suspicious.iloc[0]
    print(f"  ✓ Patient Zero Identified:")
    print(f"    - Hostname: {patient_zero['hostname']}")
    print(f"    - User: {patient_zero['user_account']}")
    print(f"    - Timestamp: {patient_zero['timestamp']}")
    print(f"    - Process: {patient_zero['process_name']}")
    print(f"    - Network: {patient_zero['network_connection']}")

# Save results with anomaly flags
df.to_csv('final_project_anomalies.csv', index=False)
print(f"\n✓ Saved to: final_project_anomalies.csv")

# ============================================================================
# STEP 4: VISUALIZATION (4-Panel Chart)
# ============================================================================
print("\n" + "="*60)
print("[STEP 4/4] CREATING VISUALIZATIONS")
print("="*60)
print("\nGenerating 4-panel analysis chart...")

# Set visualization style
sns.set_style("whitegrid")
plt.rcParams['figure.figsize'] = (14, 10)

# Create figure with 4 subplots
fig, axes = plt.subplots(2, 2, figsize=(14, 10))
fig.suptitle('Ransomware Attack Analysis - TechCorp Solutions\nSeptember 26-28, 2025', 
             fontsize=14, fontweight='bold', y=0.995)

print("\n• Creating Chart 1: Attack Timeline...")
# Chart 1: Attack Timeline Scatter Plot
ax1 = axes[0, 0]
colors = ['#d62728' if a == 1 else '#1f77b4' for a in df['is_anomaly']]
ax1.scatter(df['timestamp'], df['hostname'], c=colors, alpha=0.5, s=20)
ax1.set_xlabel('Timestamp', fontweight='bold')
ax1.set_ylabel('Hostname', fontweight='bold')
ax1.set_title('Attack Timeline - Event Distribution Across Hosts', fontweight='bold', pad=10)
ax1.tick_params(axis='x', rotation=45)
ax1.grid(True, alpha=0.3)

from matplotlib.patches import Patch
legend_elements = [
    Patch(facecolor='#d62728', label=f'Anomaly ({anomaly_count})'),
    Patch(facecolor='#1f77b4', label=f'Normal ({normal_count})')
]
ax1.legend(handles=legend_elements, loc='upper right', fontsize=8)
print("  ✓ Chart 1 complete")

print("• Creating Chart 2: Entity Frequency...")
# Chart 2: Top 10 Suspicious Entities
ax2 = axes[0, 1]
top_entities = entities_df.nlargest(10, 'frequency')
colors_entity = ['#d62728' if 'malicious' in et or 'external' in et else '#ff7f0e' 
                 for et in top_entities['entity_type']]
ax2.barh(range(len(top_entities)), top_entities['frequency'], color=colors_entity)
ax2.set_yticks(range(len(top_entities)))
ax2.set_yticklabels([f"{row['entity_value'][:25]}..." if len(row['entity_value']) > 25 
                      else row['entity_value'] for _, row in top_entities.iterrows()], 
                     fontsize=8)
ax2.set_xlabel('Frequency (Occurrences)', fontweight='bold')
ax2.set_title('Top 10 Suspicious Entities Detected', fontweight='bold', pad=10)
ax2.invert_yaxis()
ax2.grid(True, axis='x', alpha=0.3)
print("  ✓ Chart 2 complete")

print("• Creating Chart 3: Hourly Heatmap...")
# Chart 3: Hourly Anomaly Heatmap
ax3 = axes[1, 0]
df['date'] = df['timestamp'].dt.date
heatmap_data = df[df['is_anomaly'] == 1].pivot_table(
    values='event_id', index='date', columns='hour_of_day', 
    aggfunc='count', fill_value=0
)
sns.heatmap(heatmap_data, cmap='Reds', annot=True, fmt='g', 
            cbar_kws={'label': 'Anomaly Count'},
            ax=ax3, linewidths=0.5, linecolor='gray')
ax3.set_xlabel('Hour of Day', fontweight='bold')
ax3.set_ylabel('Date', fontweight='bold')
ax3.set_title('Anomalous Events Heatmap - Temporal Distribution', fontweight='bold', pad=10)
print("  ✓ Chart 3 complete")

print("• Creating Chart 4: Severity Distribution...")
# Chart 4: Event Severity Distribution
ax4 = axes[1, 1]
severity_counts = df['event_severity'].value_counts()
colors_severity = {
    'Low': '#2ca02c', 'Medium': '#ff7f0e', 
    'High': '#d62728', 'Critical': '#8b0000'
}
wedges, texts, autotexts = ax4.pie(
    severity_counts.values, labels=severity_counts.index,
    autopct='%1.1f%%',
    colors=[colors_severity.get(x, 'gray') for x in severity_counts.index],
    startangle=90,
    textprops={'fontsize': 9, 'fontweight': 'bold'}
)
ax4.set_title('Event Severity Distribution\n(All Events)', fontweight='bold', pad=10)
print("  ✓ Chart 4 complete")

# Save visualization
plt.tight_layout()
output_file = 'final_project_chart.png'
plt.savefig(output_file, dpi=300, bbox_inches='tight')
print(f"\n✓ All visualizations created successfully!")
print(f"✓ Saved to: {output_file}")
plt.close()

# ============================================================================
# FINAL SUMMARY
# ============================================================================
print("\n" + "="*60)
print("ANALYSIS COMPLETE - FINAL SUMMARY")
print("="*60)

print(f"\n📊 Generated Files:")
print(f"  1. final_project_entities.csv ({len(entities_df)} entities)")
print(f"  2. final_project_anomalies.csv ({len(df)} events with anomaly flags)")
print(f"  3. final_project_chart.png (4-panel visualization)")

print(f"\n🔍 Key Findings:")
print(f"  • Total Events Analyzed: {len(df)}")
print(f"  • Anomalies Detected: {anomaly_count} ({anomaly_percentage:.1f}%)")
print(f"  • Malicious Processes: {len(malicious_processes)}")
print(f"  • External C&C IPs: {len(external_ips)}")
print(f"  • Files Encrypted: {len(encrypted_files)}")

if len(suspicious) > 0:
    print(f"\n🎯 Attack Summary:")
    print(f"  • Attack Start: {suspicious['timestamp'].min()}")
    print(f"  • Attack End: {suspicious['timestamp'].max()}")
    print(f"  • Duration: {(suspicious['timestamp'].max() - suspicious['timestamp'].min())}")
    print(f"  • Compromised Hosts: {suspicious['hostname'].nunique()}")