import streamlit as st

st.set_page_config(
    page_title="DDoS Detection",
    page_icon="🔍",
    layout="wide"
)

import pandas as pd
import numpy as np
import joblib
import time
import threading
import os
from random import randint, random
from scapy.all import sniff, IP, TCP, UDP
from sklearn.decomposition import PCA

# Load the stacking model
model_path = r"C:\Users\visha\Desktop\ethosguard\models\stacking_model_ddos_detection.pkl"
try:
    stacking_model = joblib.load(model_path)
except Exception as e:
    st.error(f"Error loading model: {e}")
    stacking_model = None

# Expected feature names
selected_features = [
    ' Flow Duration', ' Total Fwd Packets', ' Total Backward Packets',
    'Total Length of Fwd Packets', ' Total Length of Bwd Packets',
    ' Fwd Packet Length Max', ' Fwd Packet Length Min',
    'Flow Bytes/s', ' Flow Packets/s'
]

# Updated threshold values (more conservative to reduce false positives)
thresholds = {
    ' Flow Duration': 10_000_000,  # 10 seconds
    ' Total Fwd Packets': 100,     # More realistic packet count
    ' Total Backward Packets': 50,  # More realistic packet count
    'Total Length of Fwd Packets': 100_000,
    ' Total Length of Bwd Packets': 50_000,
    ' Fwd Packet Length Max': 1_500,
    ' Fwd Packet Length Min': 20,   # Normal packets can be small
    'Flow Bytes/s': 500_000_000,
    ' Flow Packets/s': 10_000
}

# Function to capture packets continuously
def capture_packets():
    captured_packets = []
    
    def packet_handler(pkt):
        if IP in pkt:
            # Extract more useful packet data
            protocol = "TCP" if TCP in pkt else "UDP" if UDP in pkt else "Other"
            packet_info = {
                'Timestamp': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time())),
                'Source IP': pkt[IP].src,
                'Destination IP': pkt[IP].dst,
                'Protocol': protocol,
                'Packet Length': len(pkt)
            }
            captured_packets.append(packet_info)
    
    try:
        # Capture for a short time
        sniff(prn=packet_handler, timeout=3, store=False)
    except Exception as e:
        st.warning(f"Packet capture error: {e}")
    
    return pd.DataFrame(captured_packets)

def generate_ddos_packets(num_packets=5000):
    packets = []
    for _ in range(num_packets):
        # Generate data that will exceed thresholds
        packet = {
            'Timestamp': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time())),
            'Source IP': f'10.0.0.{randint(1, 5)}',  # Limited range to show concentration of attack
            'Destination IP': f'192.168.1.{randint(1, 10)}',
            'Protocol': "TCP" if randint(0, 1) == 0 else "UDP",
            'Packet Length': randint(1000, 15000),  # Larger packets
            # Add attack signature features that exceed multiple thresholds
            ' Flow Duration': randint(5_000_000, 15_000_000),
            ' Total Fwd Packets': randint(150, 500),
            ' Total Backward Packets': randint(50, 200),
            'Total Length of Fwd Packets': randint(150_000, 500_000),
            ' Total Length of Bwd Packets': randint(50_000, 200_000),
            ' Fwd Packet Length Max': randint(1_500, 2_000),
            ' Fwd Packet Length Min': randint(1_000, 1_800),
            'Flow Bytes/s': randint(600_000_000, 900_000_000),
            ' Flow Packets/s': randint(12_000, 25_000)
        }
        packets.append(packet)
    return pd.DataFrame(packets)

def simulate_ddos_effect():
    result = 0
    for _ in range(10000000):
        result += randint(1, 100)

# Improved threshold check that uses a scoring system
def check_thresholds(row):
    threshold_score = 0
    exceeded_features = []
    
    for feature, threshold in thresholds.items():
        if feature in row and row[feature] > threshold:
            threshold_score += 1
            exceeded_features.append(feature)
    
    # Require at least 3 thresholds to be exceeded for a positive detection
    is_attack = threshold_score >= 3
    
    return is_attack, threshold_score, exceeded_features

# Function to preprocess packets with better error handling
def preprocess_packets(df_packets):
    if df_packets.empty:
        return pd.DataFrame(columns=selected_features)

    # Convert timestamp to datetime for time-based calculations
    try:
        df_packets['Timestamp'] = pd.to_datetime(df_packets['Timestamp'])
    except Exception as e:
        st.warning(f"Error converting timestamps: {e}")
        df_packets['Timestamp'] = pd.to_datetime(df_packets['Timestamp'], errors='coerce')
    
    # Create result dataframe
    df_processed = pd.DataFrame(index=df_packets.index, columns=selected_features)
    
    try:
        # Group packets by flow (source IP + destination IP combination)
        flow_groups = df_packets.groupby(['Source IP', 'Destination IP'])
        
        # Calculate flow features more robustly
        for feature in selected_features:
            if feature in df_packets.columns:
                # If feature already exists (e.g., in simulated data), use as is
                df_processed[feature] = df_packets[feature]
            else:
                # Only calculate if not pre-generated
                if feature == ' Flow Duration':
                    flow_durations = flow_groups['Timestamp'].apply(
                        lambda x: (x.max() - x.min()).total_seconds() * 1000000 
                        if len(x) > 1 else 1000  # Default small value if only one packet
                    )
                    df_processed[feature] = df_packets.apply(
                        lambda row: flow_durations.get((row['Source IP'], row['Destination IP']), 1000), 
                        axis=1
                    )
                
                elif feature == ' Total Fwd Packets':
                    fwd_counts = flow_groups.size()
                    df_processed[feature] = df_packets.apply(
                        lambda row: fwd_counts.get((row['Source IP'], row['Destination IP']), 1),
                        axis=1
                    )
                
                elif feature == ' Total Backward Packets':
                    # Reverse the grouping for backward packets
                    back_groups = df_packets.groupby(['Destination IP', 'Source IP'])
                    back_counts = back_groups.size()
                    df_processed[feature] = df_packets.apply(
                        lambda row: back_counts.get((row['Destination IP'], row['Source IP']), 0),
                        axis=1
                    )
                
                elif feature == 'Total Length of Fwd Packets':
                    fwd_lengths = flow_groups['Packet Length'].sum()
                    df_processed[feature] = df_packets.apply(
                        lambda row: fwd_lengths.get((row['Source IP'], row['Destination IP']), row['Packet Length']),
                        axis=1
                    )
                
                elif feature == ' Total Length of Bwd Packets':
                    # Reverse the grouping for backward packets
                    back_groups = df_packets.groupby(['Destination IP', 'Source IP'])
                    back_lengths = back_groups['Packet Length'].sum()
                    df_processed[feature] = df_packets.apply(
                        lambda row: back_lengths.get((row['Destination IP'], row['Source IP']), 0),
                        axis=1
                    )
                
                elif feature == ' Fwd Packet Length Max':
                    fwd_max = flow_groups['Packet Length'].max()
                    df_processed[feature] = df_packets.apply(
                        lambda row: fwd_max.get((row['Source IP'], row['Destination IP']), row['Packet Length']),
                        axis=1
                    )
                
                elif feature == ' Fwd Packet Length Min':
                    fwd_min = flow_groups['Packet Length'].min()
                    df_processed[feature] = df_packets.apply(
                        lambda row: fwd_min.get((row['Source IP'], row['Destination IP']), row['Packet Length']),
                        axis=1
                    )
                
                elif feature == 'Flow Bytes/s':
                    # Ensure we don't divide by zero
                    df_processed[feature] = df_processed.apply(
                        lambda row: row['Total Length of Fwd Packets'] / (row[' Flow Duration'] / 1000000) 
                        if row[' Flow Duration'] > 0 else 0,
                        axis=1
                    )
                
                elif feature == ' Flow Packets/s':
                    # Ensure we don't divide by zero
                    df_processed[feature] = df_processed.apply(
                        lambda row: row[' Total Fwd Packets'] / (row[' Flow Duration'] / 1000000)
                        if row[' Flow Duration'] > 0 else 0,
                        axis=1
                    )
    except Exception as e:
        st.error(f"Error in packet preprocessing: {e}")
    
    # Replace NaN values with 0
    df_processed.fillna(0, inplace=True)
    
    # Clip extreme values to reasonable limits to reduce false positives
    df_processed = df_processed.clip(lower=0, upper=1e10)
    
    return df_processed

def process_packets(df_packets):
    if df_packets.empty:
        st.write("⚠️ No packets captured.")
        return None
    
    with st.spinner('Processing packets...'):
        # Preprocess packets
        df_processed = preprocess_packets(df_packets)
        
        # Add additional columns to track detection details
        df_packets['Threshold_Score'] = 0
        df_packets['Exceeded_Features'] = None
        
        # Calculate threshold-based predictions with the improved scoring system
        threshold_results = df_processed.apply(
            lambda row: check_thresholds(row), 
            axis=1
        )
        
        # Extract results
        threshold_based_prediction = pd.Series([result[0] for result in threshold_results], index=df_packets.index)
        df_packets['Threshold_Score'] = pd.Series([result[1] for result in threshold_results], index=df_packets.index)
        df_packets['Exceeded_Features'] = pd.Series([result[2] for result in threshold_results], index=df_packets.index)
        
        # If we have a model, use it for ML-based prediction
        if stacking_model is not None:
            try:
                # Apply PCA transformation
                pca = PCA(n_components=5)
                df_processed_pca = pca.fit_transform(df_processed[selected_features])
                
                # Get ML model predictions
                y_pred_model = stacking_model.predict(df_processed_pca)
                
                # Combine threshold and ML predictions, but require higher confidence
                # for threshold-only detections
                ml_predictions = []
                for i in range(len(threshold_based_prediction)):
                    if threshold_based_prediction.iloc[i]:
                        # If threshold score is high enough, trust it
                        if df_packets['Threshold_Score'].iloc[i] >= 5:
                            ml_predictions.append(1)
                        # Otherwise, use ML prediction
                        else:
                            ml_predictions.append(y_pred_model[i])
                    else:
                        ml_predictions.append(y_pred_model[i])
                
                df_packets['ML_Model_Prediction'] = ml_predictions
            except Exception as e:
                st.error(f"Error in ML prediction: {e}")
                df_packets['ML_Model_Prediction'] = threshold_based_prediction
        else:
            # If no model is available, require higher threshold score (at least 4)
            df_packets['ML_Model_Prediction'] = df_packets['Threshold_Score'] >= 4
        
        df_packets['Threshold_Based_Prediction'] = threshold_based_prediction
        
        # Final detection requires both methods to agree OR threshold score ≥ 5
        df_packets['Final_Detection'] = (
            (df_packets['ML_Model_Prediction'] & df_packets['Threshold_Based_Prediction']) | 
            (df_packets['Threshold_Score'] >= 5)
        )
        
        # Add processed features to the dataframe for display
        for feature in selected_features:
            if feature not in df_packets.columns:
                df_packets[feature] = df_processed[feature]
    
    return df_packets

def display_results(df_packets, packets_placeholder, metrics_placeholder, details_placeholder):
    # Use the specific placeholders for different sections to avoid full page refresh
    with packets_placeholder:
        st.write("### Captured Packets")
        
        # Display packet count and summary instead of full dataframe
        st.write(f"Total packets captured: {len(df_packets)}")
        
        # Only show the most recent 50 packets for better performance
        with st.expander("View Recent Packets", expanded=False):
            st.dataframe(df_packets.tail(50))
    
    # Get attack packets
    attack_packets = df_packets[df_packets['Final_Detection'] == True]
    
    # Show alert level based on attack percentage
    total_packets = len(df_packets)
    attack_count = len(attack_packets)
    
    if total_packets > 0:
        attack_percentage = (attack_count / total_packets) * 100
    else:
        attack_percentage = 0
    
    # Update metrics using its own placeholder
    with metrics_placeholder:
        # Create columns for metrics
        col1, col2, col3 = st.columns(3)
        col1.metric("Total Packets", total_packets)
        col2.metric("Attack Packets", attack_count)
        col3.metric("Attack Percentage", f"{attack_percentage:.2f}%")
        
        # Determine alert level
        if attack_percentage >= 10:
            st.error("🚨 **CRITICAL ALERT: Significant DDoS Attack Detected!**")
        elif attack_percentage >= 5:
            st.warning("🚨 **WARNING: Potential DDoS Attack Detected!**")
        elif attack_percentage > 0:
            st.info("⚠️ **Low-level Suspicious Activity Detected**")
        else:
            st.success("✅ No DDoS attack detected.")
    
    # Update details using its placeholder
    with details_placeholder:
        # Show attack details if any detected
        if not attack_packets.empty:
            st.write("### Attack Details")
            
            # Show which features were exceeded most often
            all_exceeded = []
            for features_list in attack_packets['Exceeded_Features']:
                if features_list:
                    all_exceeded.extend(features_list)
            
            if all_exceeded:
                feature_counts = pd.Series(all_exceeded).value_counts()
                st.write("#### Most Common Exceeded Thresholds:")
                st.bar_chart(feature_counts)
            
            # Show source IPs involved in attack
            offending_ips = attack_packets['Source IP'].value_counts()
            st.write("### Top Attack Sources")
            st.bar_chart(offending_ips)
            
            # Show sample of attack packets
            with st.expander("View Attack Packets", expanded=True):
                st.dataframe(attack_packets[['Source IP', 'Destination IP', 'Protocol', 
                                             'Packet Length', 'Threshold_Score', 'Exceeded_Features']])
            
            # Only show mitigation option if significant attack detected
            if attack_percentage >= 5:
                if st.button("🛡️ Mitigate Attack"):
                    mitigate_ddos(attack_packets)
        else:
            st.success("✅ No DDoS attack packets detected in this batch.")
            
        # Debug information
        with st.expander("Debug Information", expanded=False):
            st.write("#### Threshold Values Used")
            st.json(thresholds)
            
            st.write("#### Feature Statistics")
            st.dataframe(df_packets[selected_features].describe())

# Disconnect WiFi if attack detected (commented out for safety)
def disconnect_wifi():
    st.warning("⚠️ This would disconnect WiFi in a real deployment")
    # Uncomment these for actual disconnection (use with caution)
    # os.system("nmcli radio wifi off")  # Linux
    # os.system("netsh interface set interface Wi-Fi admin=disable")  # Windows

# Mitigate detected DDoS
def mitigate_ddos(attack_packets):
    offending_ips = attack_packets['Source IP'].unique()

    if len(offending_ips) > 0:
        st.write(f"🔥 **Mitigating DDoS Attack from: {', '.join(offending_ips[:5])}**" + 
                (f" and {len(offending_ips) - 5} more sources" if len(offending_ips) > 5 else ""))
        
        # Show mitigation actions
        with st.spinner("Simulating system protection measures..."):
            time.sleep(2)  # Short delay for user experience
            
            # Simulate system freeze in a way that doesn't actually freeze the UI
            st.warning("⚠️ Simulating resource allocation for defense")
            
            # Show firewall rules that would be added
            st.code(f"""
            # Example firewall rules that would be applied:
            iptables -A INPUT -s {offending_ips[0]} -j DROP
            iptables -A INPUT -p tcp --dport 80 -m connlimit --connlimit-above 20 -j DROP
            iptables -A INPUT -p tcp -m state --state NEW -m limit --limit 20/second --limit-burst 100 -j ACCEPT
            """)
            
            # Disconnect WiFi after attack detection (just display warning)
            disconnect_wifi()
            
            st.success("✅ Mitigation complete. System protected.")
    else:
        st.write("✅ No malicious activity detected.")

# Streamlit UI
def main():
    st.title("🔍 Real-Time DDoS Detection System")
    
    # Initialize session state
    if 'packets_buffer' not in st.session_state:
        st.session_state.packets_buffer = pd.DataFrame()
    if 'ddos_active' not in st.session_state:
        st.session_state.ddos_active = False
    if 'monitoring_active' not in st.session_state:
        st.session_state.monitoring_active = False
    if 'last_update' not in st.session_state:
        st.session_state.last_update = time.time()
    if 'detection_history' not in st.session_state:
        st.session_state.detection_history = []
    if 'auto_refresh' not in st.session_state:
        st.session_state.auto_refresh = False
    
    # Sidebar for controls
    with st.sidebar:
        st.header("🛠️ Controls")
        
        # Add a button to start monitoring
        if not st.session_state.monitoring_active:
            if st.button("🚀 Start Monitoring", use_container_width=True):
                st.session_state.monitoring_active = True
                st.session_state.last_update = time.time()
                st.session_state.packets_buffer = pd.DataFrame()  # Clear buffer on start
        else:
            if st.button("⏹️ Stop Monitoring", use_container_width=True):
                st.session_state.monitoring_active = False
                st.session_state.auto_refresh = False
        
        # Add a clear separator
        st.markdown("---")
        
        # Add a prominent button to initiate DDoS
        if st.session_state.monitoring_active:
            if not st.session_state.ddos_active:
                if st.button("🚨 INITIATE DDOS ATTACK", use_container_width=True, 
                           help="This will generate simulated DDoS traffic to demonstrate detection"):
                    st.session_state.ddos_active = True
                    st.warning("⚠️ DDoS attack initiated!")
            else:
                if st.button("🛑 STOP DDOS ATTACK", use_container_width=True):
                    st.session_state.ddos_active = False
                    st.success("DDoS attack stopped")
        
        # Display status indicators
        st.markdown("---")
        st.markdown("### System Status")
        
        status_col1, status_col2 = st.columns(2)
        with status_col1:
            st.markdown("Monitoring:")
        with status_col2:
            if st.session_state.monitoring_active:
                st.markdown("🟢 Active")
            else:
                st.markdown("🔴 Inactive")
        
        status_col1, status_col2 = st.columns(2)
        with status_col1:
            st.markdown("DDoS Attack:")
        with status_col2:
            if st.session_state.ddos_active:
                st.markdown("🔴 In Progress")
            else:
                st.markdown("🟢 None")
        
        # Add auto-refresh toggle
        st.markdown("---")
        st.markdown("### Refresh Settings")
        auto_refresh = st.checkbox("Enable Auto-Refresh", value=st.session_state.auto_refresh)
        st.session_state.auto_refresh = auto_refresh
        
        refresh_interval = st.slider(
            "Refresh Interval (seconds)", 
            min_value=1, 
            max_value=10, 
            value=3,
            help="How frequently to update the display."
        )
        
        # Manual refresh button
        if not st.session_state.auto_refresh and st.session_state.monitoring_active:
            if st.button("🔄 Refresh Now", use_container_width=True):
                # The refresh occurs naturally in the main area code
                pass
        
        # Add sensitivity settings
        st.markdown("---")
        st.markdown("### Detection Settings")
        detection_sensitivity = st.slider(
            "Detection Sensitivity", 
            min_value=1, 
            max_value=10, 
            value=5,
            help="Higher values increase sensitivity but may cause more false positives."
        )
        
        # Adjust thresholds based on sensitivity
        sensitivity_factor = (11 - detection_sensitivity) / 5  # 1 = most sensitive, 10 = least sensitive
        for feature in thresholds:
            thresholds[feature] = thresholds[feature] * sensitivity_factor
    
    # Main display area
    # Create placeholders that we'll update independently without reloading the whole page
    instruction_placeholder = st.empty()
    packets_placeholder = st.container()
    metrics_placeholder = st.container()
    details_placeholder = st.container()
    
    if st.session_state.monitoring_active:
        # Get packets (real or simulated based on state)
        new_packets = capture_packets()
        
        # If DDoS is active, add attack packets
        if st.session_state.ddos_active:
            ddos_packets = generate_ddos_packets(200)  # Generate a smaller batch of attack packets
            if not new_packets.empty:
                new_packets = pd.concat([new_packets, ddos_packets], ignore_index=True)
            else:
                new_packets = ddos_packets
        
        # Add new packets to our buffer
        if not new_packets.empty:
            if not st.session_state.packets_buffer.empty:
                st.session_state.packets_buffer = pd.concat([st.session_state.packets_buffer, new_packets], ignore_index=True)
                
                # Keep only the most recent packets (last 1000)
                if len(st.session_state.packets_buffer) > 1000:
                    st.session_state.packets_buffer = st.session_state.packets_buffer.tail(1000)
            else:
                st.session_state.packets_buffer = new_packets
        
        # Process and display results if we have packets
        if not st.session_state.packets_buffer.empty:
            processed_packets = process_packets(st.session_state.packets_buffer)
            if processed_packets is not None:
                # Update each section independently
                display_results(processed_packets, packets_placeholder, metrics_placeholder, details_placeholder)
        
        # Handle auto-refresh
        if st.session_state.auto_refresh:
            time.sleep(1)  # Short delay to prevent excessive CPU usage
            
            # Use JavaScript to refresh the page component after the specified interval
            # This creates a smoother experience than st.rerun()
            st.markdown(
                f"""
                <script>
                    // Set timeout for refresh
                    setTimeout(function() {{
                        // This triggers the page component to update without a full page reload
                        window.location.href = window.location.href;
                    }}, {refresh_interval * 1000});
                </script>
                """,
                unsafe_allow_html=True
            )
    else:
        # If not monitoring, show instructions
        with instruction_placeholder:
            st.info("""
            ## 📋 Instructions
            
            1. Click 'Start Monitoring' in the sidebar to begin real-time packet capture
            2. The system will continuously monitor network traffic
            3. Once monitoring is active, click 'INITIATE DDOS ATTACK' to simulate an attack
            4. Choose between Auto-Refresh or manual refresh
            5. Use 'Mitigate Attack' when an attack is detected
            6. Click 'Stop Monitoring' to end the session
            
            This application demonstrates real-time DDoS detection and mitigation capabilities.
            
            ### What's New in This Version:
            - Improved display updates that don't require full page reloads
            - Added auto-refresh toggle and interval control
            - Shows only the most recent 50 packets for better performance
            - Continuous cumulative data collection for accurate attack detection
            - Better threshold values to reduce false positives
            - Added scoring system that requires multiple indicators for detection
            """)

if __name__ == "__main__":
    main()