import pandas as pd

print("="*60)
print("ACTIVITY 11: DATA PREPROCESSING")
print("="*60)

# Load raw data
print("\nLoading raw data...")
try:
    df = pd.read_csv('final_project_raw_data.csv')
    print(f"✓ Loaded {len(df)} events from final_project_raw_data.csv")
except FileNotFoundError:
    print("ERROR: final_project_raw_data.csv not found!")
    print("Please run ACT11.py first to generate raw data.")
    exit(1)

# Clean missing values
print("\nCleaning missing values...")
df['user_account'] = df['user_account'].replace('NaN', 'SYSTEM')
df['network_connection'] = df['network_connection'].replace('NaN', 'NONE')
df['file_modified'] = df['file_modified'].replace('NaN', 'UNKNOWN')
print("✓ Replaced NaN values")

# Convert timestamp
print("\nConverting timestamp to datetime...")
df['timestamp'] = pd.to_datetime(df['timestamp'])
print("✓ Timestamp converted")

# Feature engineering
print("\nEngineering new features...")

# Time-based features
df['hour_of_day'] = df['timestamp'].dt.hour
df['day_of_week'] = df['timestamp'].dt.day_name()
df['is_weekend'] = df['timestamp'].dt.dayofweek.isin([5, 6]).astype(int)
df['is_after_hours'] = ((df['hour_of_day'] < 8) | (df['hour_of_day'] > 18)).astype(int)

# Network-based features
df['is_external_ip'] = df['network_connection'].apply(
    lambda x: 1 if (x != 'NONE' and not str(x).startswith('192.168')) else 0
)

print("✓ Created 5 new features:")
print("  • hour_of_day (0-23)")
print("  • day_of_week (Monday-Sunday)")
print("  • is_weekend (0 or 1)")
print("  • is_after_hours (0 or 1)")
print("  • is_external_ip (0 or 1)")

# Save cleaned data
output = 'final_project_cleaned_data.csv'
df.to_csv(output, index=False)

print("\n" + "="*60)
print("PREPROCESSING COMPLETE")
print("="*60)
print(f"\n✓ Total Events: {len(df)}")
print(f"✓ Total Columns: {len(df.columns)}")
print(f"\nData Quality:")
print(f"  • Missing user_account: 0")
print(f"  • Missing network_connection: 0")
print(f"  • Missing file_modified: 0")
print(f"\nNew Features Summary:")
print(f"  • After-hours events: {df['is_after_hours'].sum()}")
print(f"  • Weekend events: {df['is_weekend'].sum()}")
print(f"  • External IP connections: {df['is_external_ip'].sum()}")
print(f"\n✓ Saved to: {output}")
print("\n✅ Ready for Activity 12 (Analysis)")
print("="*60) 