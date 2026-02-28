import os
import requests
import json
import jwt
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

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Multi-Cloud Federation</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <style>
        body { background-color: #f8f9fa; display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 20px;}
        .card { box-shadow: 0 4px 8px rgba(0,0,0,0.1); border-radius: 12px; border: none; text-align: center; padding: 30px; width: 100%; max-width: 700px;}
        .logo-container img { height: 50px; margin: 10px; }
        pre { text-align: left; background-color: #2b2b2b; color: #f8f8f2; padding: 15px; border-radius: 8px; font-size: 0.85rem; overflow-x: auto;}
    </style>
</head>
<body>
    <div class="card">
        <h2 class="mb-4 fw-bold">Cloud Security Assignment</h2>
        <div class="logo-container mb-4">
            <img src="https://upload.wikimedia.org/wikipedia/commons/9/93/Amazon_Web_Services_Logo.svg" alt="AWS">
            <span class="fs-3 mx-2">+</span>
            <img src="https://upload.wikimedia.org/wikipedia/commons/f/fa/Microsoft_Azure.svg" alt="Azure">
            <span class="fs-3 mx-2">+</span>
            <img src="https://upload.wikimedia.org/wikipedia/commons/5/51/Google_Cloud_logo.svg" alt="GCP">
        </div>
        
        {% if gcp_response %}
            <!-- STEP 3: GCP Verification Result -->
            <div class="alert alert-info text-start border-info bg-light">
                <h5 class="alert-heading text-info-emphasis fw-bold mb-3">GCP Verification Result:</h5>
                <pre class="mb-0 bg-white text-dark border p-3">{{ gcp_response }}</pre>
            </div>
            <a href="/" class="btn btn-outline-secondary w-100 mt-3">Start Over</a>
            
        {% elif decoded_claims %}
            <!-- STEP 2: Azure Token Received -->
            <div class="alert alert-success border-success text-start mb-4">
                <strong><i class="bi bi-check-circle-fill"></i> Authentication Successful!</strong><br>
                AWS successfully received your Identity Token from Azure Entra ID.
            </div>
            
            <div class="accordion mb-4 text-start" id="tokenAccordion">
                <div class="accordion-item">
                    <h2 class="accordion-header">
                        <button class="accordion-button collapsed fw-bold" type="button" data-bs-toggle="collapse" data-bs-target="#collapseToken">
                            View Decoded Azure Token Claims (JSON)
                        </button>
                    </h2>
                    <div id="collapseToken" class="accordion-collapse collapse" data-bs-parent="#tokenAccordion">
                        <div class="accordion-body p-0">
                            <pre class="m-0 border-0 rounded-0">{{ decoded_claims }}</pre>
                        </div>
                    </div>
                </div>
            </div>

            <p class="text-muted small text-start">Next Step: Send this token across the internet to Google Cloud. GCP will mathematically verify Microsoft's cryptographic signature on the token before trusting it.</p>
            
            <form action="/call-gcp" method="post">
                <button type="submit" class="btn btn-primary btn-lg w-100 mt-2 shadow-sm">Pass Token to Google Cloud Engine</button>
            </form>
            
        {% else %}
            <!-- STEP 1: Initial Login State -->
            <p class="text-muted mb-4 px-3">This AWS application requires identity verification via Microsoft Entra ID before allowing access to the secure Google Cloud backend.</p>
            <a href="/login" class="btn btn-dark btn-lg w-100 shadow-sm">Sign in with Microsoft Entra ID</a>
        {% endif %}
    </div>
</body>
</html>
"""

@app.route("/")
def index():
    # If we have an ID token, decode it just to show the user what it looks like
    decoded_claims = None
    if "id_token" in session:
        try:
            # We skip signature verification here because AWS just received it directly from Azure via HTTPS
            decoded_dict = jwt.decode(session["id_token"], options={"verify_signature": False})
            decoded_claims = json.dumps(decoded_dict, indent=4)
        except Exception:
            decoded_claims = "Error decoding token for display."

    return render_template_string(HTML_TEMPLATE, decoded_claims=decoded_claims)

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
        # Format the JSON response beautifully
        try:
            formatted_json = json.dumps(response.json(), indent=4)
        except json.JSONDecodeError:
            formatted_json = response.text
            
        return render_template_string(HTML_TEMPLATE, gcp_response=formatted_json)
    except Exception as e:
        return render_template_string(HTML_TEMPLATE, gcp_response=f"Error connecting to GCP: {str(e)}")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=443, ssl_context=('cert.pem', 'key.pem'))
