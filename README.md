# 🛡 AI Network Traffic Security Analyzer

An AI-assisted real-time network traffic monitoring and security analysis system built with Python, Flask, Scapy, and Machine Learning.

The system captures network packets, analyzes traffic behavior, detects suspicious activity, identifies anomalies using Machine Learning, calculates a security risk score, and generates a PDF security report.

---

## 🚀 Features

- 🔴 Real-time network packet capture
- 📊 TCP, UDP, and ICMP traffic monitoring
- 🔍 Packet-level inspection
- 🌐 Source and destination IP monitoring
- 🚪 Source and destination port analysis
- 🚨 Suspicious traffic detection
- ⚠️ High-risk port detection
- 📦 Large packet detection
- ❓ Unknown protocol detection
- 🤖 AI-based anomaly detection
- 📈 AI risk score calculation
- 🟢 LOW / 🟡 MEDIUM / 🔴 HIGH risk classification
- 🧠 AI-generated security analysis
- 💡 Security recommendations
- 🔎 Live packet search/filter
- 📊 Top network generator analysis
- 📄 Automated PDF security report generation
- 🌑 Professional cybersecurity dashboard
- 🔄 Real-time dashboard updates

---

## 🧠 AI & Machine Learning

The project uses the **Isolation Forest** algorithm for unsupervised anomaly detection.

### AI Features

The model analyzes network traffic using features such as:

- Packet size
- TCP traffic
- UDP traffic
- ICMP traffic
- High-risk source ports
- High-risk destination ports
- Large packet indicators
- Unknown protocol indicators

Packet size is transformed using a logarithmic transformation before being used by the ML model.

The system also combines:

**Machine Learning anomaly detection + Rule-based security detection**

to produce a more practical network security assessment.

---

## 🔐 Security Detection

The system currently monitors several security indicators.

### High-Risk Ports

```text
23
135
139
445
These ports are treated as potentially risky and are monitored during traffic analysis.

##large packets
Packets larger than:
1500 bytes
are flagged for further inspection.
##Unknown protocols
Traffic that does not match:
TCP
UDP
ICMP
is treated as an unknown protocol event.

##📊 Risk Scoring
The AI security module calculates a risk score from:
ML anomaly rate
High-risk port events
Large packet events
Unknown protocol events

##Risk Levels
Risk Score
Risk Level
0–34
🟢 LOW
35–69
🟡 MEDIUM
70–100
🔴 HIGH
The score is limited to a maximum of 100.

#🖥 Dashboard
The web dashboard provides:
Total packets
TCP packets
UDP packets
ICMP packets
Total traffic
Live packet stream
Suspicious traffic
Top source IPs
AI security intelligence
Current risk level
AI risk score
AI anomaly count
Anomaly percentage
AI analysis
Security recommendations

#📄 Security Report
The application can automatically generate a PDF security report.
The report contains:
Total packets
Suspicious packets
TCP traffic
UDP traffic
ICMP traffic
Unknown protocol events
Large packet events
High-risk port events
Total traffic
Suspicious traffic details
Severity information
#🛠 Technologies Used
Technology
Purpose
Python
Core programming
Flask
Web application
Scapy
Network packet capture
NumPy
Numerical processing
Scikit-learn
Machine Learning
Isolation Forest
Anomaly detection
StandardScaler
Feature normalization
ReportLab
PDF report generation
HTML/CSS
Dashboard interface
JavaScript
Live dashboard updates
Chart.js
Traffic visualization

#📁 Project Structure

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

#⚙️ Installation
##1. Clone the repository
git clone https://github.com/YOUR-USERNAME/AI-Network-Traffic-Security-Analyzer.git
##2. Open the project
cd AI-Network-Traffic-Security-Analyzer
##3. Create a virtual environment
python -m venv .venv
##4. Activate the virtual environment
Windows
.venv\Scripts\activate
##5. Install dependencies
pip install -r requirements.txt
#▶️ Running the Application
Start the Flask application:
python app.py
Then open the local address shown by Flask in your browser.
#🔴 Network Capture
Click:
▶ Start Capture
to begin monitoring network traffic.
To stop monitoring:
■ Stop Capture
The dashboard automatically updates live traffic information.
#🤖 AI Analysis Workflow
Network Traffic
       ↓
Packet Capture
       ↓
Packet Feature Extraction
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
Risk Level
       ↓
AI Security Analysis
       ↓
Security Recommendation

##📌 Important Notes
This project is intended for educational, research, and authorized network monitoring purposes.
Only capture and analyze network traffic on systems or networks where you have permission to do so.
The AI anomaly detector is an analysis and monitoring component and should not be treated as a replacement for a professional IDS/IPS or SOC system.

##🎯 Project Goals
The main goals of this project are:
Monitor network traffic in real time.
Detect potentially suspicious network activity.
Apply Machine Learning for anomaly detection.
Combine AI detection with security rules.
Calculate an understandable security risk score.
Provide security recommendations.
Generate an automated security report.
##🔮 Future Improvements
Possible future enhancements include:
Deep Learning-based anomaly detection
Real-time attack classification
DDoS detection
Port scanning detection
Brute-force detection
IP reputation checking
Threat intelligence integration
Historical traffic database
User authentication
Email security alerts
Advanced traffic visualization
Docker deployment
Network attack dataset training
Multi-user SOC dashboard

