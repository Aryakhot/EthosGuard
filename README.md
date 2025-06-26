🛡️ EthosGuard: Intelligent Cyber Threat Detection Framework

EthosGuard is an AI-powered, real-time cyber surveillance system designed to detect and mitigate three major classes of threats:
- 🌐 DDoS Attacks
- ✉️ Email Spam
- 💳 Financial Fraud

This multi-module framework leverages machine learning, real-time data streams, and API integrations to provide a unified, compliance-ready security solution for modern digital ecosystems.

🔍 Problem Statement

Modern businesses face increasing cybersecurity challenges from diverse attack vectors. Traditional detection systems either lack accuracy or scalability. **EthosGuard** addresses this by combining statistical methods and supervised ML to reduce false positives while maintaining real-time performance.

🚀 Key Features

- 🔐 Modular Threat Detection
  - DDoS Attack Detection via statistical anomaly thresholds
  - Spam Filtering via Gmail API and supervised NLP classifiers
  - Financial Fraud Detection using stacked ML ensembles

- ⚙️ Real-Time Analytics
  - Integrated data stream processing
  - Model predictions in real-time with alert capabilities

- 🧠 AI/ML-Driven
  - Random Forest, XGBoost, and Gradient Boosting classifiers
  - Imbalanced data handled using **SMOTE**, **ADASYN**, and **Tomek Links**

- 🌐 Deployable UI
  - Web interface built using Streamlit or Flask
  - Simple and accessible dashboards for security monitoring

🧱 Project Structure

ethosguard/
├── Home.py # Main controller script
├── ddosattack.sh # DDoS simulation shell script
├── gmail_api.py # Email spam detection logic
├── preprocessed_data.csv # Cleaned dataset for fraud detection
├── requirements.txt # Project dependencies
├── README.md # Project overview and documentation
│
├── models/ # Trained model artifacts
├── pages/ # UI components (Streamlit / Flask)
└── pycache/ # Auto-generated Python cache
