import os
import pickle
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build

# Define the required Gmail API scope
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

# Authenticate Gmail API
def authenticate_gmail():
    creds = None
    token_path = "token.pickle"  # Stores the user session token

    # Load existing credentials if available
    if os.path.exists(token_path):
        with open(token_path, "rb") as token:
            creds = pickle.load(token)

    # If credentials are invalid or missing, re-authenticate
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())  # Refresh expired token
        else:
            flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
            creds = flow.run_local_server(port=0)  # Opens browser for login

        # Save the credentials for future use
        with open(token_path, "wb") as token:
            pickle.dump(creds, token)

    # Build the Gmail API service
    return build("gmail", "v1", credentials=creds)

# Initialize the Gmail API service
service = authenticate_gmail()
print("✅ Gmail API authenticated successfully!")


