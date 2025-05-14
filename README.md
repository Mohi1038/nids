<div align="center">
<h1>NIDS - Network Intrusion Detection System</h1>

<img src="https://raw.githubusercontent.com/devicons/devicon/master/icons/python/python-original.svg" width="60">
<img src="https://raw.githubusercontent.com/devicons/devicon/master/icons/fastapi/fastapi-original.svg" width="60">
<img src="https://raw.githubusercontent.com/devicons/devicon/master/icons/numpy/numpy-original.svg" width="60">
</br>
<img alt="Open in Visual Studio Code" src="https://img.shields.io/badge/Open%20in%20VS%20Code-007ACC?logo=visual-studio-code&logoColor=white">
<img alt="Contributors" src="https://img.shields.io/github/contributors/aradhya2708/nids">
<img alt="Forks" src="https://img.shields.io/github/forks/aradhya2708/nids?style=social">
<img alt="Stars" src="https://img.shields.io/github/stars/aradhya2708/nids?style=social">
<img alt="Build Status" src="https://img.shields.io/badge/build-passing-brightgreen">
<img alt="License" src="https://img.shields.io/badge/license-MIT-blue">

<h2>An Intelligent Network Intrusion Detection System with Machine Learning</h2>

<p><strong>Features • Installation • API Endpoints • Contributing</strong></p>
</div>

---

### 🌟 Overview

NIDS is a cutting-edge **Network Intrusion Detection System** leveraging machine learning to identify anomalous network traffic. By analyzing packet features in real time, it detects potential security threats with high accuracy. NIDS integrates a custom implementation of the Random Forest algorithm to deliver reliable threat detection and transparency.

---

### 🚀 Key Features
- **🛡️ Real-Time Packet Analysis**: Continuous monitoring of network traffic.
- **🤖 Custom Random Forest Classifier**: Purpose-built ML model for threat detection.
- **🧠 Intelligent Feature Extraction**: Transforms raw packets into meaningful indicators.
- **📊 Statistical Pattern Recognition**: Detects anomalies based on traffic patterns.
- **🔍 Service & Host Tracking**: Monitors connections across hosts and services.
- **🌐 FastAPI Web Interface**: Modern API for seamless integration.
- **⚙️ Customizable Detection Parameters**: Flexible configurations for various environments.

---

### 🌈 Why NIDS?
- **Low False Positives**: Custom-tuned algorithms minimize false alarms.
- **Transparent Decision Making**: Understandable model design over black-box solutions.
- **Lightweight Deployment**: Minimal dependencies for ease of deployment.
- **Real-Time Operation**: Instantaneous detection of suspicious activity.
- **Customizable**: Adaptable to specific network traffic patterns.

---

### 📋 Prerequisites
- **Python**: Version 3.8 or higher.
- **Network Interface**: Promiscuous mode enabled.
- **Permissions**: Root/Administrator access for packet capture.
- **Environment**: Linux (recommended).

---

### 🔧 Installation
1. **Clone the Repository**:
   ```bash
   git clone https://github.com/lakshya-jain/nids.git
   cd nids
   ```
2. **Create a Virtual Environment**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```
3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
4. **Set Up Models Directory**:
   Place your trained ML model in the `models` directory.

---

### 🌐 API Endpoints
- **GET /**: Check if the NIDS backend is running.
- **GET /capture/{count}**: Capture and analyze `count` network packets.
  - **Response**: Packet features and classification results (Normal/Anomalous).

---

### 📊 Detection Features
NIDS analyzes multiple attributes, such as:
- **Connection Statistics**: `same_srv_rate`, `count`.
- **Host Behavior**: `dst_host_count`, `dst_host_srv_count`.
- **Service Patterns**: `dst_host_same_srv_rate`, `service`.
- **Error Rates**: `serror_rate`, `rerror_rate`.
- **Authentication Indicators**: `logged_in`.
- **TCP Flags and Protocol Details**.

---

### 🔑 Example Workflow
1. Start the NIDS service.
2. Access API endpoints for packet capture and analysis.
3. Review classification results for anomalies.
4. Investigate suspicious packets.
5. Implement security measures as necessary.

---

### 💻 Technical Implementation
- **Custom Random Forest**: Bootstrapped feature subspace selection.
- **Decision Trees**: Information gain-based splits.
- **Packet Sniffing**: Deep inspection using Scapy.
- **Feature Engineering**: Extracts 14 critical attributes.
- **FastAPI Backend**: Modern, asynchronous API framework.

---

### 🤝 Contributing
1. Fork the repository.
2. Create a feature branch:
   ```bash
   git checkout -b feature/EnhancedDetection
   ```
3. Commit changes:
   ```bash
   git commit -m 'Add enhanced detection features'
   ```
4. Push to the branch:
   ```bash
   git push origin feature/EnhancedDetection
   ```
5. Open a Pull Request.

---

### 🔗 Resources
- 📄 **[Project Report](https://drive.google.com/file/d/1qLTRAscNorWcRLni7awWf6N4fko7jUcs/view)** – Comprehensive documentation covering architecture, implementation, and results.
- 🌐 **[Project Page](https://nids-2ndswaps-projects.vercel.app/)** – Learn about the project.

### 📃 License
NIDS is open-source under the **MIT License**. See the [LICENSE](LICENSE) file for details.

---

### 🙏 Acknowledgments
- Scapy project for packet manipulation capabilities.
- FastAPI for the web framework.
- Network security community for feature engineering insights.

Secure your network! 🛡️🔒

