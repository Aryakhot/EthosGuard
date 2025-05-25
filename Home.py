import streamlit as st
from PIL import Image
import base64

# Configure page
st.set_page_config(
    page_title="EthosGuard - Security Suite",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Enhanced CSS with a modern color scheme and better visual hierarchy
st.markdown("""
<style>
    /* Main theme colors */
    :root {
        --primary-color: #3a86ff;
        --secondary-color: #4361ee;
        --accent-color: #4cc9f0;
        --text-color: #2b2d42;
        --light-bg: #f8f9fa;
        --card-shadow: rgba(0, 0, 0, 0.1) 0px 4px 12px;
    }
    
    /* Typography */
    h1, h2, h3 {
        font-family: 'Helvetica Neue', sans-serif;
        color: var(--text-color);
    }
    
    /* Overall layout improvements */
    .stApp {
        max-width: 1200px;
        margin: 0 auto;
        padding: 1rem;
    }
    
    /* Header styling */
    .main-header {
        background: linear-gradient(90deg, #3a86ff 0%, #4361ee 100%);
        color: white;
        padding: 2.5rem;
        border-radius: 12px;
        margin-bottom: 2.5rem;
        text-align: center;
        box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
    }
    
    .main-header h1 {
        color: white;
        font-size: 3.2rem;
        margin-bottom: 0.8rem;
        font-weight: 700;
        text-shadow: 0px 2px 4px rgba(0, 0, 0, 0.2);
    }
    
    .main-header p {
        font-size: 1.25rem;
        opacity: 0.95;
        max-width: 800px;
        margin: 0 auto;
        line-height: 1.6;
    }
    
    /* Card styling */
    .card-container {
        display: flex;
        flex-direction: column;
        height: 100%;
    }
    
    .card {
        background-color: white;
        padding: 1.8rem;
        border-radius: 14px;
        box-shadow: var(--card-shadow);
        transition: all 0.3s ease;
        height: 100%;
        border-top: 5px solid var(--primary-color);
        display: flex;
        flex-direction: column;
    }
    
    .card:hover {
        transform: translateY(-8px);
        box-shadow: rgba(0, 0, 0, 0.15) 0px 12px 28px;
    }
    
    .card-icon {
        font-size: 3.5rem;
        margin-bottom: 1.2rem;
        background: linear-gradient(135deg, var(--primary-color), var(--accent-color));
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        display: inline-block;
    }
    
    .card-title {
        font-size: 1.7rem;
        font-weight: 700;
        margin-bottom: 1.2rem;
        color: var(--text-color);
    }
    
    .card-description {
        font-size: 1.05rem;
        color: #333333;
        margin-bottom: 1.8rem;
        line-height: 1.6;
        flex-grow: 1;
    }
    
    /* Make all cards the same height */
    .equal-height {
        display: flex;
        flex-direction: column;
        height: 100%;
    }
    
    /* Streamlit button styling */
    .stButton > button {
        background: linear-gradient(90deg, var(--primary-color) 0%, var(--secondary-color) 100%);
        color: white !important;
        padding: 0.7rem 1.2rem !important;
        border-radius: 6px !important;
        text-align: center;
        text-decoration: none;
        display: inline-block !important;
        font-weight: 700 !important;
        font-size: 1.05rem !important;
        border: none !important;
        cursor: pointer;
        transition: all 0.3s ease;
        width: 100%;
        letter-spacing: 0.6px;
        text-shadow: 0px 1px 2px rgba(0, 0, 0, 0.3);
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        margin-top: auto;
    }
    
    .stButton > button:hover {
        opacity: 0.95;
        transform: scale(1.03);
        box-shadow: 0 6px 10px rgba(0, 0, 0, 0.15);
    }
    
    /* Column container to ensure equal height */
    .column-container {
        display: flex;
        flex-direction: column;
        height: 100%;
    }
    
    /* Footer styling */
    .footer {
        background-color: var(--light-bg);
        border-radius: 12px;
        padding: 2.5rem;
        margin-top: 3rem;
        box-shadow: 0 2px 10px rgba(0, 0, 0, 0.05);
    }

    .footer h3 {
        color: var(--secondary-color);
        border-bottom: 2px solid var(--accent-color);
        padding-bottom: 0.7rem;
        margin-bottom: 1.5rem;
        display: inline-block;
        font-size: 1.5rem;
        font-weight: 700;
    }

    .footer-list {
        list-style-type: none;
        padding-left: 0;
    }

    .footer-list li {
        margin-bottom: 1.5rem;
        display: flex;
        align-items: flex-start;
        color: #000;
        line-height: 1.6;
    }

    .footer-list li span {
        margin-right: 0.8rem;
        color: var(--primary-color);
        font-weight: bold;
        font-size: 1.5rem;
        flex-shrink: 0;
        padding-top: 0.2rem;
    }
    
    .footer-list li strong {
        font-weight: 700;
        margin-right: 0.5rem;
    }
    
    /* Status bar styling */
    .status-bar {
        position: fixed;
        bottom: 0;
        left: 0;
        width: 100%;
        background-color: #f1f3f5;
        padding: 10px;
        border-top: 1px solid #ddd;
        text-align: center;
        font-size: 0.9rem;
        color: #333;
        font-weight: 500;
        z-index: 1000;
        box-shadow: 0 -2px 10px rgba(0, 0, 0, 0.05);
    }
    
    /* Ensure columns are equal height */
    .st-emotion-cache-1r6slb0 {
        height: 100%;
    }
    
    /* Force card descriptions to be the same height */
    .card-description {
        min-height: 100px;
    }
    
    /* Responsive adjustments */
    @media (max-width: 992px) {
        .card {
            margin-bottom: 20px;
        }
        
        .main-header h1 {
            font-size: 2.5rem;
        }
    }
</style>
""", unsafe_allow_html=True)

# Header section
st.markdown("""
<div class="main-header">
    <h1>🛡️ EthosGuard Security Suite</h1>
    <p>Your comprehensive solution for enterprise-grade network and data security. 
    Advanced protection against modern cyber threats with real-time monitoring and AI-powered analytics.</p>
</div>
""", unsafe_allow_html=True)

# Create a container with equal height columns
# Create three columns for the cards - with equal height
col1, col2, col3 = st.columns(3)

# Standardize description lengths to ensure equal card heights
ddos_desc = "Real-time network traffic monitoring with advanced pattern recognition to detect and mitigate Distributed Denial of Service attacks before they impact your services."
fraud_desc = "Analyze financial transactions using machine learning algorithms to identify potentially fraudulent activities and secure your financial operations."
spam_desc = "AI-powered email content analysis to filter out spam, phishing attempts, and malicious communications to protect your organization's communications."

# Make sure all descriptions have similar length
max_len = max(len(ddos_desc), len(fraud_desc), len(spam_desc))
while len(ddos_desc) < max_len - 10:  # Adding some padding
    ddos_desc += " "

# DDoS Detection Card
with col1:
    st.markdown(f"""
    <div class="card-container">
        <div class="card">
            <div class="card-icon">🔍</div>
            <div class="card-title">DDoS Detection</div>
            <div class="card-description">
                {ddos_desc}
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)
    if st.button("Launch DDoS Detection", key="ddos"):
        st.switch_page("pages/1_DDoS_Detection.py")

# Fraud Detection Card
with col2:
    st.markdown("""
    <div class="card-container">
        <div class="card">
            <div class="card-icon">💰</div>
            <div class="card-title">Fraud Detection</div>
            <div class="card-description">
                Analyze financial transactions using machine learning algorithms to identify potentially fraudulent activities and secure your financial operations.
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)
    if st.button("Launch Fraud Detection", key="fraud"):
        st.switch_page("pages/2_Fraud_Detection.py")

# Spam Detection Card
with col3:
    st.markdown("""
    <div class="card-container">
        <div class="card">
            <div class="card-icon">📧</div>
            <div class="card-title">Spam Detection</div>
            <div class="card-description">
                AI-powered email content analysis to filter out spam, phishing attempts, and malicious communications to protect your organization's communications.
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)
    if st.button("Launch Spam Detection", key="spam"):
        st.switch_page("pages/3_Spam_Detection.py")

# Footer with additional information
st.markdown("""
<div class="footer">
    <h3>🔐 About EthosGuard Security Suite</h3>
    <ul class="footer-list">
        <li>
            <span>🔍</span> <strong>DDoS Detection:</strong> Our advanced traffic analysis tools monitor network activity patterns to identify and prevent Distributed Denial of Service attacks in real-time, preserving your service availability.
        </li>
        <li>
            <span>💰</span> <strong>Fraud Detection:</strong> Using machine learning and behavioral analytics, our system identifies suspicious financial transactions with high accuracy to protect your business from financial fraud.
        </li>
        <li>
            <span>📧</span> <strong>Spam Detection:</strong> Leveraging state-of-the-art natural language processing, our AI scanner protects your inbox from unwanted and potentially harmful emails, including sophisticated phishing attempts.
        </li>
    </ul>
</div>
""", unsafe_allow_html=True)

# Add a status bar at the bottom
st.markdown("""
<div class="status-bar">
    EthosGuard Security Suite v2.1 • All systems operational • Last updated: March 29, 2025
</div>
""", unsafe_allow_html=True)