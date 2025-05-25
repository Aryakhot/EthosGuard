# Add at the top of the file
import streamlit as st

st.set_page_config(
    page_title="Fraud Detection",
    page_icon="💰",
    layout="wide"
)

# Rest of your fraud detection code remains the same
import pandas as pd
import joblib
import numpy as np
import os
import re

# Custom CSS for better styling
st.markdown("""
<style>
    .block-container {
        padding-top: 2rem;
        padding-bottom: 2rem;
    }
    .fraud-stats {
        background-color: #f8f9fa;
        padding: 15px;
        border-radius: 10px;
        margin-bottom: 20px;
    }
    .title-container {
        display: flex;
        align-items: center;
        margin-bottom: 20px;
    }
    .title-text {
        margin-left: 15px;
    }
</style>
""", unsafe_allow_html=True)

# Define absolute paths
base_path = r"C:\Users\visha\Desktop\ethosguard\models"

# Load the trained fraud detection model
@st.cache_resource
def load_model():
    try:
        return joblib.load(os.path.join(base_path, "stacking_model_old.pkl"))
    except Exception as e:
        st.error(f"Error loading model: {e}")
        return None

# Load the saved LabelEncoder
@st.cache_resource
def load_label_encoder():
    try:
        return joblib.load(os.path.join(base_path, "label_encoder.pkl"))
    except Exception as e:
        st.error(f"Error loading LabelEncoder: {e}")
        return None

# Function to format time with colons (e.g., 20595 -> 20:59:5)
def format_time(time_str):
    time_str = str(time_str).replace(',', '')
    # Pad with leading zeros if needed to ensure we have at least 6 digits
    time_str = time_str.zfill(6)
    # Insert colons after every 2 characters
    formatted_time = ':'.join([time_str[i:i+2] for i in range(0, len(time_str), 2)])
    return formatted_time

# Function to format amount as currency (e.g., 1000 -> $1,000.00 mn)
def format_amount(amount):
    try:
        # Convert to float and format with dollar sign and commas
        formatted = "${:,.2f} mn".format(float(amount))
        return formatted
    except (ValueError, TypeError):
        return amount  # Return original if conversion fails

# Initialize model and label encoder
model = load_model()
label_encoder = load_label_encoder()

# Define required columns
REQUIRED_COLUMNS = ["sender", "receiver", "time", "step", "type", "amount"]

# Streamlit App Title with custom styling
st.markdown("""
<div class="title-container">
    <h1>💰 Financial Fraud Detection System</h1>
</div>
""", unsafe_allow_html=True)

st.markdown("""
This system analyzes financial transactions to identify potential fraud. 
Upload your transaction data below to get started.
""")

# Create a container with better styling for the upload section
with st.container():
    st.markdown("### 📂 Upload Your Transaction Data")
    uploaded_file = st.file_uploader("Select a CSV file containing transaction data", type=["csv"])

if uploaded_file is not None:
    try:
        # Load and display data
        df = pd.read_csv(uploaded_file)
        
        # Create a display copy of the dataframe for visualization
        display_df = df.copy()
        
        # Remove commas from sender, receiver columns and format time with colons
        for col in ['sender', 'receiver']:
            if col in display_df.columns:
                display_df[col] = display_df[col].astype(str).str.replace(',', '')
        
        # Format time column with colons
        if 'time' in display_df.columns:
            display_df['time'] = display_df['time'].apply(format_time)
            
        # Format amount column with dollar sign and mn
        if 'amount' in display_df.columns:
            display_df['amount'] = display_df['amount'].apply(format_amount)
        
        # Display data sample with better formatting
        st.markdown("### 📊 Uploaded Data Sample")
        st.dataframe(display_df.head(), use_container_width=True)

        # Validate required columns
        missing_cols = [col for col in REQUIRED_COLUMNS if col not in df.columns]
        if missing_cols:
            st.error(f"⚠️ Missing required columns: {missing_cols}")
        else:
            # Show progress during analysis
            with st.spinner("Analyzing transactions for fraudulent activity..."):
                # Encode 'type' column safely
                if label_encoder:
                    known_labels = list(label_encoder.classes_)  # Get known categories

                    # Identify unknown transaction types
                    unique_types = df["type"].unique()
                    unknown_types = set(unique_types) - set(known_labels)

                    if unknown_types:
                        st.warning(f"⚠️ Some transaction types were not found in the trained model: {unknown_types}. They will be mapped to a known type.")
                        
                        # Choose the most frequent type from known labels
                        most_common_type = "TRANSFER" if "TRANSFER" in known_labels else known_labels[0]
                        df["type"] = df["type"].apply(lambda x: x if x in known_labels else most_common_type)

                    # Encode the 'type' column
                    df["type"] = label_encoder.transform(df["type"])

                # Extract features for prediction
                X = df[["step", "type", "amount"]]

                if X.empty:
                    st.error("❌ No valid transactions available for prediction after filtering. Please check the file format.")
                else:
                    # Make predictions
                    predictions = model.predict(X)

                    # Add predictions to DataFrame
                    df["Fraud Prediction"] = predictions
                    df["Fraud Prediction"] = df["Fraud Prediction"].map({0: "Not Fraud", 1: "Fraud"})

                    # Convert 'type' column back to original labels
                    df["type"] = label_encoder.inverse_transform(df["type"].astype(int))
                    
                    # Create a display copy for results
                    display_results = df.copy()
                    
                    # Remove commas from sender, receiver columns and format time with colons
                    for col in ['sender', 'receiver']:
                        if col in display_results.columns:
                            display_results[col] = display_results[col].astype(str).str.replace(',', '')
                    
                    # Format time column with colons
                    if 'time' in display_results.columns:
                        display_results['time'] = display_results['time'].apply(format_time)
                        
                    # Format amount column with dollar sign and mn
                    if 'amount' in display_results.columns:
                        display_results['amount'] = display_results['amount'].apply(format_amount)

                    # Display fraud statistics in a nicely formatted box
                    fraud_count = (df["Fraud Prediction"] == "Fraud").sum()
                    non_fraud_count = (df["Fraud Prediction"] == "Not Fraud").sum()
                    total_count = len(df)
                    
                    # Calculate percentages
                    fraud_percent = (fraud_count / total_count) * 100 if total_count > 0 else 0
                    non_fraud_percent = (non_fraud_count / total_count) * 100 if total_count > 0 else 0
                    
                    # Create a summary section with metrics
                    st.markdown("### 📈 Analysis Summary")
                    col1, col2, col3 = st.columns(3)
                    
                    with col1:
                        st.metric("Total Transactions", f"{total_count:,}")
                    with col2:
                        st.metric("Fraudulent", f"{fraud_count:,} ({fraud_percent:.1f}%)")
                    with col3:
                        st.metric("Non-Fraudulent", f"{non_fraud_count:,} ({non_fraud_percent:.1f}%)")

                    # Display results with better formatting
                    st.markdown("### 🔍 Prediction Results")
                    st.dataframe(
                        display_results[["sender", "receiver", "time", "step", "type", "amount", "Fraud Prediction"]],
                        use_container_width=True,
                        column_config={
                            "Fraud Prediction": st.column_config.TextColumn(
                                "Fraud Prediction",
                                help="Prediction results",
                                width="medium"
                            ),
                            "amount": st.column_config.TextColumn(
                                "Amount",
                                help="Transaction amount",
                                width="medium"
                            )
                        }
                    )

                    # Filter top 50 fraud transactions based on amount
                    top_frauds = df[df["Fraud Prediction"] == "Fraud"].nlargest(50, "amount")
                    
                    # Create display copy for top frauds
                    display_top_frauds = top_frauds.copy()
                    
                    # Remove commas from sender, receiver columns and format time with colons
                    for col in ['sender', 'receiver']:
                        if col in display_top_frauds.columns:
                            display_top_frauds[col] = display_top_frauds[col].astype(str).str.replace(',', '')
                    
                    # Format time column with colons
                    if 'time' in display_top_frauds.columns:
                        display_top_frauds['time'] = display_top_frauds['time'].apply(format_time)
                        
                    # Format amount column with dollar sign and mn
                    if 'amount' in display_top_frauds.columns:
                        display_top_frauds['amount'] = display_top_frauds['amount'].apply(format_amount)

                    if not top_frauds.empty:
                        st.markdown("### 🔥 Top 50 Fraud Transactions")
                        st.dataframe(
                            display_top_frauds[["sender", "receiver", "time", "step", "type", "amount", "Fraud Prediction"]],
                            use_container_width=True,
                            column_config={
                                "amount": st.column_config.TextColumn(
                                    "Amount",
                                    help="Transaction amount",
                                    width="medium"
                                )
                            }
                        )
                    else:
                        st.success("✅ No fraudulent transactions detected!")

                    # Downloadable CSV with predictions
                    # Ensure we format the time column before downloading
                    df_download = df.copy()
                    if 'time' in df_download.columns:
                        df_download['time'] = df_download['time'].apply(format_time)
                    if 'amount' in df_download.columns:
                        df_download['amount'] = df_download['amount'].apply(format_amount)
                    csv = df_download.to_csv(index=False)
                    
                    # Place download button in a container for better styling
                    st.markdown("### 📥 Download Results")
                    st.download_button(
                        "Download Fraud Predictions CSV",
                        data=csv,
                        file_name="fraud_predictions.csv",
                        mime="text/csv",
                        use_container_width=True
                    )

    except Exception as e:
        st.error(f"❌ Error processing file: {e}")
else:
    # Display some information when no file is uploaded
    st.info("👆 Please upload a CSV file to begin fraud detection analysis.")
    
    # Placeholder for what the app expects
    st.markdown("""
    ### Expected CSV Format
    Your CSV file should contain the following columns:
    - `sender`: Sender identifier
    - `receiver`: Receiver identifier
    - `time`: Transaction timestamp
    - `step`: Transaction step in the sequence
    - `type`: Transaction type
    - `amount`: Transaction amount
    """)