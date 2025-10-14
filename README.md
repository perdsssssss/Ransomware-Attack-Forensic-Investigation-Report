# Ransomware Attack Forensic Investigation

A comprehensive forensic analysis project demonstrating the application of machine learning and NLP techniques to detect and reconstruct a simulated ransomware attack on a corporate network.

## 📋 Project Overview

This project simulates a ransomware attack on **TechCorp Solutions** and demonstrates how intelligent systems can be used to:
- Detect anomalous behavior in system logs
- Extract malicious entities using NLP techniques
- Reconstruct attack timelines
- Visualize security incidents
- Generate professional forensic reports

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

- **Python**
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

```

## 🙏 Acknowledgments

- Course: Intelligent Systems in Forensics
- Tools: scikit-learn, pandas, matplotlib, seaborn
- Inspiration: Real-world ransomware incident response
