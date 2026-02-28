import os
import requests
from flask import Flask, redirect, request, session, render_template_string
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.urandom(24)

CLIENT_ID = os.getenv("AZURE_CLIENT_ID")
CLIENT_SECRET = os.getenv("AZURE_CLIENT_SECRET")
TENANT_ID = os.getenv("AZURE_TENANT_ID")
GCP_URL = os.getenv("GCP_BACKEND_URL")
REDIRECT_URI = os.getenv("REDIRECT_URI") 
AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0"

# Modern Bootstrap 5 Template
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Multi-Cloud Federation</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background-color: #f8f9fa; display: flex; align-items: center; justify-content: center; height: 100vh; }
        .card { box-shadow: 0 4px 8px rgba(0,0,0,0.1); border-radius: 12px; border: none; text-align: center; padding: 20px;}
        .logo-container img { height: 50px; margin: 10px; }
    </style>
</head>
<body>
    <div class="container" style="max-width: 600px;">
        <div class="card p-5">
            <h2 class="mb-4">Cloud Security Assignment</h2>
            <div class="logo-container mb-4">
                <img src="https://upload.wikimedia.org/wikipedia/commons/9/93/Amazon_Web_Services_Logo.svg" alt="AWS">
                <span class="fs-3 mx-2">+</span>
                <img src="https://upload.wikimedia.org/wikipedia/commons/f/fa/Microsoft_Azure.svg" alt="Azure">
                <span class="fs-3 mx-2">+</span>
                <img src="https://upload.wikimedia.org/wikipedia/commons/5/51/Google_Cloud_logo.svg" alt="GCP">
            </div>
            
            {% if authenticated %}
                <div class="alert alert-success">
                    <strong>Authentication Successful!</strong><br>
                    Your Azure Entra ID token has been securely stored on AWS.
                </div>
                <form action="/call-gcp" method="post">
                    <button type="submit" class="btn btn-primary btn-lg w-100 mt-3">Pass Token to Google Cloud</button>
                </form>
            {% elif response_data %}
                <div class="alert alert-info text-start">
                    <h5>GCP Verification Result:</h5>
                    <p class="mb-0">{{ response_data }}</p>
                </div>
                <a href="/" class="btn btn-outline-secondary w-100 mt-3">Start Over</a>
            {% else %}
                <p class="text-muted mb-4">This AWS application requires identity verification via Microsoft Entra ID before accessing the secure Google Cloud backend.</p>
                <a href="/login" class="btn btn-dark btn-lg w-100">Sign in with Microsoft Entra ID</a>
            {% endif %}
        </div>
    </div>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE, authenticated=("id_token" in session))

@app.route("/login")
def login():
    auth_url = f"{AUTHORITY}/authorize?client_id={CLIENT_ID}&response_type=code&redirect_uri={REDIRECT_URI}&response_mode=query&scope=openid profile email"
    return redirect(auth_url)

@app.route("/callback")
def callback():
    code = request.args.get("code")
    token_data = {
        "client_id": CLIENT_ID, "scope": "openid profile email", "code": code,
        "redirect_uri": REDIRECT_URI, "grant_type": "authorization_code", "client_secret": CLIENT_SECRET,
    }
    token_r = requests.post(f"{AUTHORITY}/token", data=token_data)
    session["id_token"] = token_r.json().get("id_token")
    return redirect("/")

@app.route("/call-gcp", methods=["POST"])
def call_gcp():
    id_token = session.get("id_token")
    headers = {"Authorization": f"Bearer {id_token}"}
    try:
        response = requests.post(GCP_URL, headers=headers, verify=False)
        return render_template_string(HTML_TEMPLATE, response_data=response.text)
    except Exception as e:
        return render_template_string(HTML_TEMPLATE, response_data=f"Error: {str(e)}")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=443, ssl_context=('/home/ubuntu/cert.pem', '/home/ubuntu/key.pem'))
