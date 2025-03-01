from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
from phi.agent import Agent, RunResponse
from phi.model.groq import Groq
from dotenv import load_dotenv
import os
import base64
from email.mime.text import MIMEText
import time
import schedule
import logging
from fastapi.middleware.cors import CORSMiddleware
from selenium_main import get_policy_info
from contextlib import asynccontextmanager


# Gmail API imports
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
import pickle

# Load environment variables
load_dotenv()
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan handler for startup/shutdown events"""
    # Startup logic
    import threading
    threading.Thread(target=schedule_email_checking, daemon=True).start()
    logger.info("Email checking scheduler started")
    yield
    
# Initialize FastAPI app
app = FastAPI(lifespan=lifespan)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("gmail_agent.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("gmail_agent")

# Gmail API Setup
SCOPES = ['https://www.googleapis.com/auth/gmail.modify']  # Read and modify (but not delete) messages
TOKEN_FILE = 'token.pickle'
CREDENTIALS_FILE = 'credentials.json'  # Download this from Google Cloud Console

# Initialize the AI agent
policy_finder = Agent(
    tools=[get_policy_info],
    model=Groq(id='llama3-70b-8192'),
    markdown=True,
    instructions=[
        'The user will give you a Vehicle number or policy number'
        'When Given the query find the car number or Policy number and insert it into the tool function paramater as a string and run',
        'Give the Tool results to the user',
        'Return the details in a well formatted clean markdown and not json '
        'Add a line break for every policy detail item'
        'When responding to emails, be professional and concise.'
        'If the email is not about finding a policy or a policy detail, skip and abort operation'
    ],
    add_context=True
)

class ChatRequest(BaseModel):
    message: str

# Existing chat endpoint
@app.post("/chat")
async def chat_endpoint(request: ChatRequest):
    try:
        response = policy_finder.run(request.message)
        return {"response": response.content}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# New endpoint to manually trigger email checking
@app.post("/check-emails")
async def check_emails_endpoint():
    try:
        processed = process_new_emails()
        return {"status": "success", "emails_processed": processed}
    except Exception as e:
        logger.error(f"Error in check-emails endpoint: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

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

def get_unread_messages(service, max_results=1):
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
    # based on your specific needs
    
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

def format_ai_response(response_text):
    """Format the AI response to be email-friendly."""
    # Convert markdown to simple plain text
    response_text = response_text.replace('**', '')
    response_text = response_text.replace('*', '')
    response_text = response_text.replace('`', '')
    
    # Add email signature
    signature = "\n\n--\nThis is an automated response from the Policy Finder AI.\nIf you need further assistance, please reply to this email."
    
    return response_text + signature

def process_new_emails():
    """Check for new emails and process them with the AI agent."""
    try:
        service = get_gmail_service()
        unread_messages = get_unread_messages(service)
        
        if not unread_messages:
            return 0
        
        emails_processed = 0
        
        for message in unread_messages:
            try:
                # Extract email information
                email_info = extract_email_info(message)
                logger.info(f"Processing email from: {email_info['sender']} - Subject: {email_info['subject']}")
                
                # Process with AI agent
                ai_input = f"Subject: {email_info['subject']}\n\n{email_info['body']}"
                ai_response = policy_finder.run(ai_input)
                
                # Format response
                formatted_response = format_ai_response(ai_response.content)
                
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
            
            except Exception as e:
                logger.error(f"Error processing email: {str(e)}")
        
        return emails_processed
    
    except Exception as e:
        logger.error(f"Error in process_new_emails: {str(e)}")
        return 0

# Scheduler function to check emails periodically
def schedule_email_checking():
    # Run every 5 minutes
    schedule.every(5).minutes.do(process_new_emails)
    
    while True:
        schedule.run_pending()
        time.sleep(1)


async def startup_event():
    """Start the email checking scheduler in a separate thread."""
    import threading
    threading.Thread(target=schedule_email_checking, daemon=True).start()
    logger.info("Email checking scheduler started")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)