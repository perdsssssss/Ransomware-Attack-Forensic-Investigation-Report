Final Project Plan
Activity 10: Advanced Report Generation and Final Project Kickoff

Course: Intelligent Systems in Forensics
Student: Ferdinand T. Corbin Jr.

I. Introduction
This project plan outlines my strategy for the final forensic investigation project. It applies everything I've learned from Activities 1-9 to a new scenario: reconstructing the timeline of a ransomware attack through system event log analysis. This demonstrates my ability to perform a complete investigation from data creation to final reporting, applying forensic techniques to cybersecurity incident response.

II. Summary of Activities 1-9
Activity 1 – Python Basics: Learned Python fundamentals through grade computation, building my foundation for data manipulation.
Activities 2-3 – Data Preparation: Learned to clean and organize data properly using CSV files and Pandas.
Activity 4 – Anomaly Detection: Used Isolation Forest to automatically detect unusual events in data—my first machine learning application.
Activity 5 – Entity Extraction: Applied SpaCy for NLP to extract names, organizations, and locations from text evidence.
Activity 6 – Reporting & Visualization: Created forensic reports with Matplotlib charts to communicate findings clearly.
Activities 7-8 – Network Forensics: Used Scapy to analyze network packets and built a simple intrusion detection system.
Activity 9 – Metadata Analysis: Extracted EXIF data from images using Piexif to uncover hidden evidence.
Each activity built my skills progressively, preparing me for this independent final project.

III. New Raw Data Description
Dataset: System Event Logs During Ransomware Attack
I will simulate system event logs from a corporate network during a ransomware incident with these fields:
FieldTypeDescriptionExampleevent_idIntegerUnique event identifier10001timestampStringEvent occurrence time"2025-09-27 14:32:45"hostnameStringComputer name"WORKSTATION-042"user_accountStringUsername associated"jsmith"process_nameStringProcess/application name"explorer.exe"event_typeStringCategory of event"file_access"file_modifiedStringFile path accessed"C:\Users\jsmith\Documents\report.docx"network_connectionStringRemote IP address"192.168.1.50"event_severityStringPriority level"High"raw_messageStringFull log message"Process suspicious.exe created"
Dataset Size: 5,000-8,000 system events covering a 48-hour period (September 26-28, 2025)
Why this data? Ransomware attacks are among the most damaging cybersecurity threats, causing business disruption and data loss. This dataset is perfect for timeline reconstruction and pattern detection to identify:

Initial infection point (patient zero)
Malicious process execution
Lateral movement across network
Mass file encryption events
Command and control communications
Attack progression phases

Real-World Context: On September 28, 2025, TechCorp Solutions experienced a ransomware attack that encrypted files across multiple workstations. Forensic investigators must reconstruct the complete attack timeline to understand how the breach occurred and prevent future incidents.

IV. Preprocessing Strategy
Step 1: Generate Raw Data
Script: generate_data.py
Output: final_project_raw_data.csv

Create 5,000-8,000 simulated system events
Include mostly legitimate activity (85%)
Inject attack indicators (15%) like:

Suspicious process names (update_system32.exe, encrypt_v2.exe)
External IP connections to unknown servers
Mass file modification events
After-hours suspicious activity
Unusual account privileges



Step 2: Clean and Prepare Data
Script: preprocess_data.py
Input: final_project_raw_data.csv
Output: final_project_cleaned_data.csv
Cleaning tasks:

Replace missing user_account values with "SYSTEM"
Replace missing network_connection with "NONE"
Replace missing file_modified with "UNKNOWN"
Convert timestamp to datetime format
Standardize event_type values (lowercase, remove spaces)
Validate data types (event_id as integer)

Feature Engineering:
Create new columns for attack detection:

hour_of_day (0-23) - extracted from timestamp
day_of_week - Monday through Sunday
is_weekend (True/False) - Saturday/Sunday flag
is_after_hours (True/False) - outside 8 AM - 6 PM
is_external_ip (True/False) - non-internal network addresses
file_extension - extracted from file_modified (.exe, .docx, etc.)
is_suspicious_process (True/False) - matches malware patterns
files_modified_per_minute - rolling count per user
unique_hosts_accessed - different machines per user

These new features help identify malicious behavior and attack progression patterns.

V. Analysis Strategy
Primary Technique: Entity Extraction (NLP)
Script: analyze_data.py
Input: final_project_cleaned_data.csv
Output: final_project_entities.csv
Process:

Use SpaCy to extract entities from raw_message and structured columns:

Malicious processes - executables with suspicious names
External IP addresses - potential Command & Control servers
User accounts - compromised credentials
Critical file paths - system directories accessed


Build frequency distribution of all unique entities
Identify patterns in entity co-occurrence
Create timeline of when each suspicious entity first appeared
Save entity analysis with columns: entity_type, entity_value, frequency, first_seen, last_seen, associated_hostnames

Connection to Activity 5: This builds on the NLP entity extraction I learned, now applied to cybersecurity log analysis to identify attack indicators.
Secondary Technique: Isolation Forest (Anomaly Detection)
Process:

Load cleaned system event data
Select features for anomaly detection:

files_modified_per_minute (mass encryption indicator)
hour_of_day (unusual timing)
is_external_ip (encoded as 0/1)
event_severity (encoded numerically)


Train Isolation Forest model with:

contamination=0.15 (expect 15% attack events)
n_estimators=100
random_state=42


Predict anomalies and add is_anomaly column
Calculate anomaly scores
Focus on high-volume file modifications and external connections
Save results to final_project_anomalies.csv

Connection to Activity 4: This applies the Isolation Forest technique to detect unusual system behavior that indicates ransomware activity.
Timeline Reconstruction

Filter events where is_anomaly == 1 OR entity flagged as suspicious
Sort by timestamp chronologically
Group into attack phases:

Phase 1: Initial Compromise (first malicious process)
Phase 2: Reconnaissance (network scanning)
Phase 3: Lateral Movement (spreading to other machines)
Phase 4: Encryption (mass file modification)
Phase 5: Ransom Demand (ransom note creation)




VI. Visualization Plan
Script: analyze_data.py (visualization section)
Output: final_project_chart.png
Four Charts:

Attack Timeline Chart - Gantt-style visualization

X-axis: Time (48-hour period)
Y-axis: Hostnames (workstations and servers)
Color coding: Green (normal), Yellow (suspicious), Red (encrypted)
Shows attack progression across network


Entity Frequency Distribution - Horizontal bar chart

Top 15 suspicious processes and external IPs
Bars colored by severity
Identifies most common attack indicators


Hourly Event Heatmap - Seaborn heatmap

X-axis: Hour of day (0-23)
Y-axis: Date (Sept 26-28)
Color intensity: Number of anomalous events
Shows concentration of attack activity


Network Connection Graph - NetworkX diagram

Nodes: Hostnames and external IPs
Edges: Network connections (thickness = frequency)
Red for external IPs, blue for internal hosts
Visualizes attack propagation pattern



All charts will demonstrate the complete attack narrative from initial infection to full encryption.

VII. Final Report Outline
Document: final_project_report.md
Structure:
1. Executive Summary

Brief overview of ransomware incident at TechCorp Solutions
Main findings (patient zero, attack timeline, impact assessment)
Key recommendations for immediate response and prevention

2. Methodology

How I generated the system event logs
Preprocessing and feature engineering steps
Analysis techniques used (Entity Extraction with SpaCy, Anomaly Detection with Isolation Forest)
Timeline reconstruction approach

3. Key Findings

Patient zero identification
Initial infection vector
Malicious processes discovered
Attack progression timeline
Indicators of Compromise (IOCs)
Impact assessment

4. Visualizations

Include final_project_chart.png (4-panel visualization)
Brief explanation of what each chart reveals about attack progression

5. Conclusion

Summary of investigation findings
Attack attribution analysis
Lessons learned from incident

6. References

Libraries used: Pandas, Scikit-learn, Matplotlib, SpaCy, NetworkX
Course activities referenced (especially Activities 4, 5, and 7)


VIII. Expected Deliverables
Week 11 Files:

generate_data.py - System event log generator
preprocess_data.py - Data cleaning and feature engineering
final_project_raw_data.csv - Raw simulated logs
final_project_cleaned_data.csv - Preprocessed dataset

Week 12 Files:

analyze_data.py - Entity extraction, anomaly detection, and visualization
final_project_entities.csv - Extracted malicious entities
final_project_anomalies.csv - Events with anomaly flags
final_project_chart.png - 4-panel visualization

Week 13 Files:

final_project_report.md - Complete forensic report
All above files packaged together


IX. Success Criteria
✅ Clean dataset with 5,000+ events and no missing critical values
✅ Entity extraction identifies at least 5 key malicious indicators
✅ Isolation Forest detects attack phase events with high accuracy
✅ Timeline reconstruction provides clear chronological narrative
✅ At least 4 effective visualizations created
✅ Professional report with all required sections
✅ Attack progression from infection to encryption is documented
✅ Actionable recommendations for prevention included

X. Contingency Plans
If too few anomalies detected: Increase contamination parameter to 0.20 or add more suspicious events to raw data (more external connections, more mass file modifications)
If too many false positives: Decrease contamination to 0.10 or refine feature selection to focus on strongest attack indicators (file modification rate + external IPs)
If entity extraction yields little: Enhance raw_message content quality, add more specific process names and IP addresses with clear malicious patterns
If visualizations unclear: Simplify charts, add detailed labels and legends, use color coding more effectively, or create separate images instead of subplots
If timeline reconstruction unclear: Add more timestamp granularity, create intermediate phase markers, use annotations to highlight critical events

XI. Personal Reflection
From Activity 1's basic Python to now planning a full ransomware forensic investigation, I've grown significantly. Each activity taught me something essential:

Activity 4 showed me how AI can automate threat detection through anomaly detection
Activity 5 demonstrated how NLP can extract critical entities from unstructured log data
Activity 6 taught me that clear visualizations are crucial for communicating technical findings
Activities 7-8 gave me network forensics skills that directly connect to understanding ransomware propagation
Activity 9 showed me the value of metadata in digital investigations

This final project synthesizes all these skills into a realistic cybersecurity incident response scenario. Ransomware attacks are one of the most serious threats organizations face today, and being able to reconstruct the attack timeline is critical for understanding how the breach occurred, identifying all compromised systems, and preventing future attacks.
I'm excited to apply everything I've learned to create a comprehensive forensic investigation that demonstrates both technical proficiency and investigative thinking. The ability to transform raw system logs into a clear narrative of an attack is a valuable skill in modern cybersecurity.
By completing this project, I will demonstrate mastery of the entire forensic workflow: data acquisition, preprocessing, intelligent analysis, visualization, and professional reporting. This capstone project represents the culmination of my learning journey in digital forensics and intelligent systems.