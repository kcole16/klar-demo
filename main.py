import os
import pickle
import requests
import json
from openai import OpenAI
from flask import Flask, redirect, url_for, session, request, render_template, jsonify
from flask_session import Session
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
import base64
from dotenv import load_dotenv
from bs4 import BeautifulSoup

# Load environment variables from a .env file (optional but recommended)
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get(
    'FLASK_SECRET_KEY',
    'YOUR_SECRET_KEY')  # Replace with your secret key or set in .env
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

# Configuration
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
CLIENT_SECRETS_FILE = 'credentials.json'
GOOGLE_IMAGE_API_KEY = os.environ.get('GOOGLE_IMAGE_API_KEY')  # Set in .env
GOOGLE_CSE_ID = os.environ.get('GOOGLE_CSE_ID')  # Set in .env
OPENAI_API_KEY = os.environ.get('OPENAI_API_KEY')  # Set in .env
OPENROUTER_API_KEY = os.environ.get('OPENROUTER_API_KEY')  # Set in .env


# Initialize OpenAI

def search_google_images(keyword):
    search_url = "https://www.googleapis.com/customsearch/v1"
    params = {
        "q": keyword,
        "cx": GOOGLE_CSE_ID,
        "key": GOOGLE_IMAGE_API_KEY,
        "searchType": "image",
        "num": 1,
        "imgType": "photo",
        "order": "relevance",
    }
    
    response = requests.get(search_url, params=params)
    response_json = response.json()
    image_url = None
    
    if "items" in response_json:
        # Get the first image URL from search results
        image_url = response_json["items"][0]["link"]
    return image_url


# Helper function to create Gmail service
def get_gmail_service():
    creds = None
    if 'credentials' in session:
        creds = pickle.loads(session['credentials'])
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
            session['credentials'] = pickle.dumps(creds)
        else:
            return None
    service = build('gmail', 'v1', credentials=creds)
    return service


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/authorize')
def authorize():
    flow = Flow.from_client_secrets_file(CLIENT_SECRETS_FILE, scopes=SCOPES)
    flow.redirect_uri = "https://klar.ngrok.app/oauth2callback"
    print(flow.redirect_uri)
    authorization_url, state = flow.authorization_url(
        access_type='offline', include_granted_scopes='true')
    session['state'] = state
    print(authorization_url)
    return redirect(authorization_url)


@app.route('/oauth2callback')
def oauth2callback():
    state = session['state']
    flow = Flow.from_client_secrets_file(CLIENT_SECRETS_FILE,
                                         scopes=SCOPES,
                                         state=state)
    # flow.redirect_uri = url_for('oauth2callback', _external=True)
    flow.redirect_uri = "https://klar.ngrok.app/oauth2callback"
    authorization_response = request.url
    flow.fetch_token(authorization_response=authorization_response)
    creds = flow.credentials
    session['credentials'] = pickle.dumps(creds)
    return redirect(url_for('process_emails'))


@app.route('/process_emails')
def process_emails():
    service = get_gmail_service()
    if not service:
        return redirect(url_for('authorize'))

    try:
        # Fetch the last 1000 emails
        messages = []
        query = '"order confirmation"'
        # query = 'order confirmation size'
        # query = 'label:"orders"'
        max_results = 300
        response = service.users().messages().list(userId='me',
                                                   maxResults=max_results, q=query).execute()
        if 'messages' in response:
            messages.extend(response['messages'])

        emails = []
        for msg in messages:
            msg_data = service.users().messages().get(userId='me',
                                                      id=msg['id'],
                                                      format='full').execute()
            payload = msg_data.get('payload', {})
            headers = payload.get('headers', [])
            subject = next(
                (h['value'] for h in headers if h['name'] == 'Subject'), '')
            image_candidates = None
            decoded_data = None
            for part in payload.get('parts', []):
                if part['mimeType'] == 'text/plain':
                    data = part['body'].get('data')
                    if data:
                        decoded_data = base64.urlsafe_b64decode(data).decode(
                            'utf-8', errors='ignore')
                        emails.append({
                            'subject': subject,
                            'body': decoded_data
                        })

        # Limit the number of emails to process to avoid exceeding OpenAI's rate limits
        MAX_EMAILS = max_results  # Adjust as needed based on rate limits and performance
        emails_to_process = emails[:MAX_EMAILS]

        # client = OpenAI()
        # client.api_key = OPENAI_API_KEY

        client = OpenAI(
          base_url="https://openrouter.ai/api/v1",
          api_key=OPENROUTER_API_KEY
        )

        clothing_items = []

        # Prepare the prompt for OpenAI
        for email in emails_to_process:
            email_text = f"Subject: {email['subject']}\n\n{email['body']}"
            prompt = ("""You are an assistant that analyzes emails to determine if each email contains a valid order for a clothing item. Follow these steps:

            1. Identify if it is an clothing item order: The email is an order if it contains specific details like:
               - An order number in the subject or body.
               - Keywords such as 'order confirmation,' or 'your recent order.'
               - Items that sound like clothing such as 'shirt', 'top', 'jeans', 'sweater', 'coat', 'jacket', 'skirt', 'dress', 'short', 'pants', 'blouse', 'hat' and any other clothing item

            2. Exclude ads: Do not consider emails that only contain promotional language without any purchase confirmation.

            3. Extract Clothing Order Information: If it is an order, record:
               - A boolean of 'is_order' if the email is a clothing item order 
               - An 'item_type' string specifying the store or brand name (exactly as it appears), followed by the full name of the clothing item.

            **Output Format**: Provide results for each email in JSON format, like this:
            - `{'is_order': boolean, 'item_type': string}`

            **Enclose all JSON property names in double quotes**

            **Email**:
            """ + "\n\n".join(email_text))

            response = client.chat.completions.create(
                model="deepseek/deepseek-chat",
                messages=[{
                    "role":
                    "system",
                    "content":
                    "You extract clothing order information from emails."
                }, {
                    "role": "user",
                    "content": prompt
                }]
            )
            gpt_output = response.choices[0].message.content
            try:
                order = json.loads(gpt_output.strip('```json').strip('```'))
                order['img_src'] = ""
                if order['is_order']:
                    order['img_src'] = search_google_images(order['item_type'])
                    clothing_items.append(order)
                else:
                    continue
            except Exception as e:
                print(e)
                print(gpt_output)
                continue
        unique_items = list({item['item_type']: item for item in clothing_items}.values())
        return render_template('index.html', clothing_items=unique_items)

    except Exception as e:
        print(e)
        return "An error occurred: " + str(e), 500


if __name__ == '__main__':
    # For development purposes only. Remove for production.
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # Only for development
    app.run('localhost', 5000, debug=True)
