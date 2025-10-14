# Ransomware Attack Forensic Investigation

A comprehensive forensic analysis project demonstrating the application of machine learning and NLP techniques to detect and reconstruct a simulated ransomware attack on a corporate network.

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Status](https://img.shields.io/badge/status-completed-success.svg)

## 📋 Project Overview

This project simulates a ransomware attack on **TechCorp Solutions** and demonstrates how intelligent systems can be used to:
- Detect anomalous behavior in system logs
- Extract malicious entities using NLP techniques
- Reconstruct attack timelines
- Visualize security incidents
- Generate professional forensic reports

**Course:** Intelligent Systems in Forensics (COM232)  
**Investigator:** Ferdinand T. Corbin Jr.

## 🎯 Key Features

- **Anomaly Detection** using Isolation Forest algorithm
- **Entity Extraction** with regex pattern matching
- **Timeline Reconstruction** of attack progression
- **Multi-panel Visualizations** for comprehensive analysis
- **Automated Report Generation** with actionable insights

## 📊 Results Summary

| Metric | Value |
|--------|-------|
| **Total Events Analyzed** | 300 |
| **Anomalies Detected** | 45 (15%) |
| **Malicious Processes** | 6 distinct executables |
| **External C2 IPs** | 3 unique addresses |
| **Encrypted Files** | 80+ with `.locked` extension |
| **Attack Duration** | 48 hours (Sept 26-28, 2025) |

## 🛠️ Technologies Used

- **Python 3.8+**
- **pandas** - Data manipulation and analysis
- **scikit-learn** - Machine learning (Isolation Forest)
- **matplotlib & seaborn** - Data visualization
- **NumPy** - Numerical computing

## 📁 Project Structure
```
ransomware-forensics/
│
├── generate_data.py              # Raw data generator
├── preprocess_data.py            # Data cleaning and feature engineering
├── analyze_data.py               # Main analysis script (ML + NLP)
│
├── final_project_raw_data.csv    # Simulated system logs (generated)
├── final_project_cleaned_data.csv # Preprocessed dataset
├── final_project_entities.csv    # Extracted malicious entities
├── final_project_anomalies.csv   # Flagged anomalous events
├── final_project_chart.png       # 4-panel visualization
│
├── final_project_report.md       # Complete forensic report
├── project_plan.md               # Project planning document
└── README.md                     # This file
```

## 🚀 Getting Started

### Prerequisites
```bash
pip install pandas numpy scikit-learn matplotlib seaborn
```

### Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/ransomware-forensics.git
cd ransomware-forensics
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

### Usage

Run the analysis pipeline in sequence:
```bash
# Step 1: Generate simulated ransomware attack data
python generate_data.py

# Step 2: Preprocess and engineer features
python preprocess_data.py

# Step 3: Run analysis (Entity Extraction + Anomaly Detection)
python analyze_data.py
```

## 📈 Visualizations

The project generates a comprehensive 4-panel dashboard:

1. **Attack Timeline** - Event distribution across hosts over time
2. **Entity Frequency** - Top 10 suspicious entities detected
3. **Hourly Heatmap** - Temporal distribution of anomalies
4. **Severity Distribution** - Breakdown of event severity levels

![Ransomware Analysis Dashboard](final_project_chart.png)

## 🔍 Methodology

### Phase 1: Data Generation
- Simulated 300 system log events
- 85% benign activity, 15% attack indicators
- Realistic timestamps, hostnames, and process names

### Phase 2: Feature Engineering
Created derived features for better detection:
- `hour_of_day` - Temporal analysis
- `is_weekend` - Non-working day detection
- `is_after_hours` - Late-night activity flagging
- `is_external_ip` - Non-local connection detection
- `is_encrypted` - File encryption indicator

### Phase 3: Entity Extraction
Used regex patterns to identify:
- Malicious executables (`svchost32.exe`, `encrypt_v2.exe`)
- External Command & Control IPs
- Encrypted files with `.locked` extension

### Phase 4: Anomaly Detection
- **Algorithm:** Isolation Forest
- **Contamination:** 0.15 (15% expected anomalies)
- **Features:** 7 behavioral and temporal indicators
- **Output:** Binary anomaly flags + anomaly scores

## 📝 Key Findings

### Attack Progression

1. **Initial Compromise** - Single user account on HOST-01
2. **Lateral Movement** - Spread to HOST-03
3. **Command & Control** - Connections to external IPs
4. **Mass Encryption** - 80+ files encrypted with `.locked` extension
5. **Peak Activity** - Concentration during 10 PM - 3 AM

### Indicators of Compromise (IOCs)

**Malicious Processes:**
- `update_office365.exe`
- `svchost32.exe`
- `encrypt_v2.exe`

**External C2 IPs:**
- `203.0.113.45`
- `198.51.100.77`
- `185.220.101.33`

## 💡 Recommendations

1. **Immediate Actions:**
   - Isolate compromised hosts
   - Block external C2 IP addresses
   - Disable affected user accounts
   - Restore files from backups

2. **Prevention Measures:**
   - Implement continuous anomaly monitoring
   - Enhance user security awareness training
   - Deploy endpoint detection and response (EDR)
   - Enforce strict access controls

3. **Long-term Strategy:**
   - Regular security audits
   - Network segmentation
   - Multi-factor authentication (MFA)
   - Automated threat intelligence integration

## 📚 Learning Outcomes

This project demonstrates proficiency in:
- ✅ Data preprocessing and feature engineering
- ✅ Machine learning for cybersecurity
- ✅ Pattern recognition and entity extraction
- ✅ Data visualization for forensic analysis
- ✅ Professional technical report writing

## 🤝 Contributing

This is an academic project, but suggestions are welcome! Feel free to:
- Open an issue for bugs or improvements
- Submit pull requests for enhancements
- Share your own forensic analysis techniques

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Course: Intelligent Systems in Forensics (COM232)
- Tools: scikit-learn, pandas, matplotlib, seaborn
- Inspiration: Real-world ransomware incident response

## 📧 Contact

**Ferdinand T. Corbin Jr.**  
Student, Intelligent Systems in Forensics  
[Your Email] | [Your LinkedIn]

---

**⚠️ Disclaimer:** This project uses simulated data for educational purposes only. No real systems were compromised or attacked during this investigation.
