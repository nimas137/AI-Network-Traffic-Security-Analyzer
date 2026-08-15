# 🛡 AI Network Traffic Security Analyzer

An **AI-assisted real-time network traffic monitoring and security analysis system** built with Python, Flask, Scapy, and Machine Learning.

The system captures network packets, analyzes traffic behavior, detects suspicious activity, identifies anomalies using Machine Learning, calculates a security risk score, and generates an automated PDF security report.

---

## ⭐ Key Highlights

- 🤖 **AI-Based Anomaly Detection** using Isolation Forest
- 🚨 **Real-Time Suspicious Traffic Detection**
- 📊 **Live Network Traffic Dashboard**
- 🧠 **AI Risk Score from 0–100**
- 🟢🟡🔴 **LOW / MEDIUM / HIGH Risk Classification**
- 📄 **Automated PDF Security Reports**
- 🔍 **Packet-Level Network Analysis**
- 💡 **AI-Powered Security Recommendations**
- ⚠️ **High-Risk Port Detection**
- 📦 **Large Packet Detection**
- ❓ **Unknown Protocol Detection**
- 🔄 **Live Dashboard Updates**

---

## 🚀 Features

### 🔴 Real-Time Network Monitoring

- **Live packet capture**
- **Source and destination IP monitoring**
- **Source and destination port monitoring**
- **Protocol identification**
- **Packet size analysis**
- **TCP, UDP and ICMP traffic statistics**

### 🚨 Suspicious Traffic Detection

The system detects potentially suspicious network activity using security rules.

It currently checks:

- **High-risk ports**
- **Large packets**
- **Unknown protocols**
- **Unusual traffic patterns**

### 🤖 AI Security Analysis

The system uses **Isolation Forest**, an unsupervised Machine Learning algorithm, to detect abnormal network traffic.

The AI analyzes features including:

- **Packet size**
- **TCP traffic**
- **UDP traffic**
- **ICMP traffic**
- **High-risk source ports**
- **High-risk destination ports**
- **Large packet indicators**
- **Unknown protocol indicators**

### 🧠 Risk Assessment

The system calculates an **AI security risk score from 0 to 100**.

| Risk Score | Risk Level |
|------------|------------|
| **0–34** | 🟢 LOW |
| **35–69** | 🟡 MEDIUM |
| **70–100** | 🔴 HIGH |

The final score combines:

- **Machine Learning anomaly rate**
- **High-risk port events**
- **Large packet events**
- **Unknown protocol events**

---

## 🔐 Security Detection

### ⚠️ High-Risk Ports

The following ports are monitored:

```text
23
135
139
445
## 📦 Large Packet Detection

Packets larger than **1500 bytes** are flagged for further inspection.

---

## ❓ Unknown Protocol Detection

Traffic that does not match:

- **TCP**
- **UDP**
- **ICMP**

is treated as an unknown protocol event.

---

## 📊 Dashboard

The web dashboard provides:

- **Total Packets**
- **TCP Traffic**
- **UDP Traffic**
- **ICMP Traffic**
- **Total Data**
- **Live Packet Stream**
- **Suspicious Traffic**
- **Top Network Generators**
- **AI Security Intelligence**
- **AI Anomaly Count**
- **Anomaly Percentage**
- **AI Risk Score**
- **Security Recommendations**

---

## 📄 Automated Security Report

The application can generate a PDF Security Report containing:

- **Total packets**
- **Suspicious packets**
- **TCP packets**
- **UDP packets**
- **ICMP packets**
- **Unknown protocol events**
- **Large packet events**
- **High-risk port events**
- **Total traffic**
- **Suspicious traffic details**
- **Severity information**

---

## 🧠 AI Detection Workflow

Network Traffic
       ↓
Packet Capture
       ↓
Feature Extraction
       ↓
Feature Normalization
       ↓
Isolation Forest
       ↓
ML Anomaly Detection
       ↓
Rule-Based Security Detection
       ↓
Risk Score Calculation
       ↓
Risk Classification
       ↓
AI Security Analysis
       ↓
Security Recommendation
## 🛠 Technologies Used

| **Technology** | **Purpose** |
|---|---|
| **Python** | Core programming |
| **Flask** | Web application |
| **Scapy** | Network packet capture |
| **NumPy** | Numerical processing |
| **Scikit-learn** | Machine Learning |
| **Isolation Forest** | Anomaly detection |
| **StandardScaler** | Feature normalization |
| **ReportLab** | PDF report generation |
| **HTML/CSS** | Dashboard interface |
| **JavaScript** | Live dashboard updates |
| **Chart.js** | Traffic visualization |

---

## 📁 Project Structure

```text
AI-Network-Traffic-Security-Analyzer/
│
├── app.py
├── packet_analyzer.py
├── ai_security.py
├── requirements.txt
├── README.md
├── .gitignore
│
└── templates/
    └── index.html
## ⚙️ Installation

### **1. Clone Repository**

```bash
git clone https://github.com/YOUR-USERNAME/AI-Network-Traffic-Security-Analyzer.git
### **2. Open Project Directory**

```bash
cd AI-Network-Traffic-Security-Analyzer
### **3. Create Virtual Environment**

```bash
python -m venv .venv
### **4. Activate Virtual Environment**

#### **Windows**

```bash
.venv\Scripts\activate

###**Linux / macOS**:
source .venv/bin/activate
###**5. Install Dependencies**
pip install -r requirements.txt
###**6. Run the Application**
python app.py
###**7. Open in Browser**
http://127.0.0.1:5000

###**🔴 Network Capture**
Use the dashboard controls:
▶ Start Capture — Start network monitoring
■ Stop Capture — Stop network monitoring
The dashboard automatically updates traffic information.

###**🎯 Project Objectives**
The main objectives are:
Monitor network traffic in real time
Detect potentially suspicious network activity
Apply Machine Learning for anomaly detection
Combine AI with rule-based security detection
Calculate an understandable security risk score
Provide security recommendations
Generate automated security reports

###**📌 Important Notes**
This project is intended for educational, research, and authorized network monitoring purposes.
Only capture and analyze traffic on systems or networks where you have permission.
The AI module is an analysis and monitoring component.
It should not be considered a replacement for a professional IDS/IPS or SOC system.

###**🔮 Future Improvements**
Possible future enhancements include:
DDoS Detection
Port Scanning Detection
Brute-Force Attack Detection
IP Reputation Checking
Threat Intelligence Integration
Historical Traffic Database
Email Security Alerts
Advanced Traffic Visualization
Deep Learning-Based Anomaly Detection
Real-Time Attack Classification
Docker Deployment
SOC-Style Monitoring Dashboard
15
139
445
