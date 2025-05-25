# Add at the top of the file
import streamlit as st

st.set_page_config(
    page_title="Spam Detection",
    page_icon="📧",
    layout="wide"
)

import joblib
import pandas as pd
from gmail_api import authenticate_gmail  # Ensure correct import
from googleapiclient.discovery import build
import base64
from sklearn.feature_extraction.text import TfidfVectorizer

import os

# Define absolute paths
base_path = r"C:\Users\visha\Desktop\ethosguard\models"

rf_model = joblib.load(os.path.join(base_path, "random_forest_model.pkl"))
xgb_model = joblib.load(os.path.join(base_path, "xgboost_model.pkl"))
stacking_model = joblib.load(os.path.join(base_path, "stacking_model.pkl"))
vectorizer = joblib.load(os.path.join(base_path, "tfidf_vectorizer.pkl"))

# Gmail API authentication
service = authenticate_gmail()

def get_emails():
    """Fetches unread emails from Gmail"""
    results = service.users().messages().list(userId='me', labelIds=['INBOX'], q="is:unread", maxResults=10).execute()
    messages = results.get('messages', [])
    emails = []
    
    for msg in messages:
        msg_data = service.users().messages().get(userId='me', id=msg['id']).execute()
        snippet = msg_data.get('snippet', '')
        emails.append(snippet)
    
    return emails

def classify_email(email_text):
    """Classifies email as spam or not spam"""
    email_tfidf = vectorizer.transform([email_text])
    
    rf_pred = rf_model.predict(email_tfidf)[0]
    xgb_pred = xgb_model.predict(email_tfidf)[0]
    stack_pred = stacking_model.predict(email_tfidf)[0]
    
    final_pred = "Spam" if stack_pred == 1 else "Not Spam"
    return final_pred, rf_pred, xgb_pred, stack_pred

# Streamlit UI
st.title("📧 Gmail Spam Detector")

if st.button("Fetch and Classify Emails"):
    emails = get_emails()
    
    if not emails:
        st.warning("No unread emails found.")
    else:
        for i, email in enumerate(emails):
            pred, rf, xgb, stack = classify_email(email)
            st.write(f"### Email {i+1}")
            st.write(f"**Snippet:** {email}")
            st.write(f"🔍 **Classification:** {pred} (RF: {rf}, XGB: {xgb}, Stacking: {stack})")