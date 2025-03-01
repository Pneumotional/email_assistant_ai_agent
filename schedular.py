import time
import os
import logging
import schedule
import requests
from dotenv import load_dotenv

# Gmail API imports
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
import base64
from email.mime.text import MIMEText
import pickle

# Load environment variables
load_dotenv()

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("gmail_scheduler.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("gmail_scheduler")

# Configuration
API_BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8000")  # Your FastAPI application URL
CHECK_INTERVAL_MINUTES = int(os.getenv("CHECK_INTERVAL_MINUTES", "5"))  # How often to check emails

# Gmail API Setup
SCOPES = ['https://www.googleapis.com/auth/gmail.modify']
TOKEN_FILE = 'token.pickle'
CREDENTIALS_FILE = 'credentials.json'

def get_gmail_service():
    """Authenticate and get the Gmail API service."""
    creds = None
    
    # Load credentials from file if exists
    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE, 'rb') as token:
            creds = pickle.load(token)
    
    # Check if credentials are invalid or missing
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            # Create new credentials
            flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_FILE, SCOPES)
            creds = flow.run_local_server(port=0)
        
        # Save the credentials for future use
        with open(TOKEN_FILE, 'wb') as token:
            pickle.dump(creds, token)
    
    # Build the Gmail service
    return build('gmail', 'v1', credentials=creds)

def get_unread_messages(service, max_results=10):
    """Get unread messages from Gmail inbox."""
    try:
        # Get list of unread messages
        results = service.users().messages().list(
            userId='me',
            labelIds=['INBOX', 'UNREAD'],
            maxResults=max_results
        ).execute()
        
        messages = results.get('messages', [])
        
        if not messages:
            logger.info("No new messages found.")
            return []
        
        # Get full message details for each message
        detailed_messages = []
        for message in messages:
            msg = service.users().messages().get(
                userId='me', 
                id=message['id'],
                format='full'
            ).execute()
            detailed_messages.append(msg)
        
        return detailed_messages
    
    except Exception as e:
        logger.error(f"Error getting unread messages: {str(e)}")
        return []

def extract_email_info(message):
    """Extract sender, subject, and body from a Gmail message."""
    headers = message['payload']['headers']
    
    # Extract email metadata
    sender = next((h['value'] for h in headers if h['name'].lower() == 'from'), '')
    subject = next((h['value'] for h in headers if h['name'].lower() == 'subject'), '(No Subject)')
    message_id = next((h['value'] for h in headers if h['name'].lower() == 'message-id'), '')
    reply_to = next((h['value'] for h in headers if h['name'].lower() == 'reply-to'), sender)
    
    # Extract email body
    body = ""
    if 'parts' in message['payload']:
        for part in message['payload']['parts']:
            if part['mimeType'] == 'text/plain':
                body_data = part['body'].get('data', '')
                if body_data:
                    body += base64.urlsafe_b64decode(body_data).decode('utf-8')
    else:
        # For messages without parts
        body_data = message['payload']['body'].get('data', '')
        if body_data:
            body = base64.urlsafe_b64decode(body_data).decode('utf-8')
    
    # Clean up quoted replies and signatures in the body
    body = clean_email_body(body)
    
    return {
        'id': message['id'],
        'thread_id': message['threadId'],
        'sender': sender,
        'subject': subject,
        'body': body,
        'message_id': message_id,
        'reply_to': reply_to
    }

def clean_email_body(body):
    """Remove quoted replies and signatures from email body."""
    # This is a simple implementation - you may need to make it more sophisticated
    
    # Remove content after common reply indicators
    indicators = [
        "\nOn ", "\n>", "\n-- \n",
        "From:", "Sent from my iPhone",
        "Sent from my device"
    ]
    
    for indicator in indicators:
        if indicator in body:
            parts = body.split(indicator, 1)
            body = parts[0].strip()
    
    return body

def create_reply(to, subject, body, message_id, thread_id):
    """Create a Gmail API compatible message for a reply."""
    message = MIMEText(body)
    message['to'] = to
    message['subject'] = subject if not subject.startswith('Re:') else subject
    message['In-Reply-To'] = message_id
    message['References'] = message_id
    
    # Encode the message
    raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode('utf-8')
    
    return {
        'raw': raw_message,
        'threadId': thread_id
    }

def send_reply(service, message):
    """Send a reply via Gmail API."""
    try:
        sent_message = service.users().messages().send(
            userId='me',
            body=message
        ).execute()
        
        logger.info(f"Message sent. ID: {sent_message['id']}")
        return sent_message
    except Exception as e:
        logger.error(f"Error sending reply: {str(e)}")
        return None

def mark_as_read(service, message_id):
    """Mark a message as read by removing the UNREAD label."""
    try:
        service.users().messages().modify(
            userId='me',
            id=message_id,
            body={'removeLabelIds': ['UNREAD']}
        ).execute()
        logger.info(f"Marked message {message_id} as read")
        return True
    except Exception as e:
        logger.error(f"Error marking message as read: {str(e)}")
        return False

def process_with_ai_agent(message_text):
    """Send the message to the AI agent API and get a response."""
    try:
        response = requests.post(
            f"{API_BASE_URL}/chat",
            json={"message": message_text}
        )
        
        if response.status_code == 200:
            result = response.json()
            return result.get("response", "I couldn't process your request at this time.")
        else:
            logger.error(f"Error from AI API: {response.status_code} - {response.text}")
            return "I couldn't process your request at this time. Please try again later."
    
    except Exception as e:
        logger.error(f"Error calling AI API: {str(e)}")
        return "I'm having trouble connecting to my processing system. Please try again later."

def format_ai_response(response_text):
    """Format the AI response to be email-friendly."""
    # Convert markdown to simple plain text
    response_text = response_text.replace('**', '')
    response_text = response_text.replace('*', '')
    response_text = response_text.replace('`', '')
    
    # Add email signature
    signature = "\n\n--\nThis is an automated response from the Policy Finder AI.\nIf you need further assistance, please reply to this email."
    
    return response_text + signature

def check_and_process_emails():
    """Check for new emails and process them with the AI agent."""
    logger.info("Checking for new emails...")
    
    try:
        service = get_gmail_service()
        unread_messages = get_unread_messages(service)
        
        if not unread_messages:
            logger.info("No new emails to process")
            return 0
        
        emails_processed = 0
        
        for message in unread_messages:
            try:
                # Extract email information
                email_info = extract_email_info(message)
                logger.info(f"Processing email from: {email_info['sender']} - Subject: {email_info['subject']}")
                
                # Process with AI agent
                ai_input = f"Subject: {email_info['subject']}\n\n{email_info['body']}"
                ai_response = process_with_ai_agent(ai_input)
                
                # Format response
                formatted_response = format_ai_response(ai_response)
                
                # Create reply message
                reply_message = create_reply(
                    to=email_info['reply_to'],
                    subject=f"Re: {email_info['subject']}",
                    body=formatted_response,
                    message_id=email_info['message_id'],
                    thread_id=email_info['thread_id']
                )
                
                # Send the reply
                send_reply(service, reply_message)
                
                # Mark the original message as read
                mark_as_read(service, email_info['id'])
                
                emails_processed += 1
                logger.info(f"Successfully processed and replied to email: {email_info['subject']}")
                
                # Brief pause between processing emails
                time.sleep(1)
            
            except Exception as e:
                logger.error(f"Error processing individual email: {str(e)}")
        
        return emails_processed
    
    except Exception as e:
        logger.error(f"Error in check_and_process_emails: {str(e)}")
        return 0

def main():
    logger.info("Starting Gmail Email Processor")
    
    # Schedule the job to run every X minutes
    schedule.every(CHECK_INTERVAL_MINUTES).minutes.do(check_and_process_emails)
    
    # Run once immediately at startup
    check_and_process_emails()
    
    # Keep the script running
    while True:
        schedule.run_pending()
        time.sleep(1)

if __name__ == "__main__":
    main()