from fastapi import FastAPI, Depends, HTTPException, status, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError
from typing import List, Optional
import os
import requests
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = FastAPI()
security = HTTPBearer()

# AWS Cognito config
COGNITO_REGION = os.getenv("COGNITO_REGION")
COGNITO_USER_POOL_ID = os.getenv("COGNITO_USER_POOL_ID")
COGNITO_ISSUER = f"https://cognito-idp.{COGNITO_REGION}.amazonaws.com/{COGNITO_USER_POOL_ID}"
JWKS_URL = f"{COGNITO_ISSUER}/.well-known/jwks.json"

# Fetch JWKS
jwks = requests.get(JWKS_URL).json()

# Static user data
user_data = [
    {
        "UserId": "pranav.chachra@commverseglobal.com",
        "NickName": "pranavchachracommverse",
        "userName": "pranavchachracommverse",
        "roles": ["admin", "business"],
        "OrganizationCode": "ACME",
        "PreferredCommodityCode": {"value": "Wheat", "label": "Wheat"},
        "PreferredCountryCode": {"value": "USA", "label": "United States"},
        "PreferredTopics": [
            {"label": "Market Movements/Price Changes", "value": "Market Movements/Price Changes"},
            {"label": "Supply & Demand Factors", "value": "Supply & Demand Factors"},
            {"label": "Economic Indicators & Analysis", "value": "Economic Indicators & Analysis"}
        ],
        "tiles": [
            {"name": "Debrief Data", "widgetName": "Debrief"},
            {"name": "Market Data", "widgetName": "marketData"},
            {"name": "Origination Data", "widgetName": "orgData"}
        ],
        "PreferredTimeWindowForInsightsInDays": 90,
        "organizations": [
            {
                "organizationCode": "ACME",
                "originationName": "Commverse",
                "workspaces": ["workspace1", "workspace2", "workspace3"]
            },
            {
                "organizationCode": "BETA",
                "originationName": "BetaCorp",
                "workspaces": ["alpha", "beta"]
            }
        ]
    }
]

def get_public_key(token):
    """Get the correct public key from JWKs using the token's kid"""
    headers = jwt.get_unverified_header(token)
    for key in jwks["keys"]:
        if key["kid"] == headers["kid"]:
            return {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"],
                "alg": key["alg"]
            }
    raise HTTPException(status_code=401, detail="Public key not found")

def decode_token(token: str):
    key = get_public_key(token)
    try:
        payload = jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            issuer=COGNITO_ISSUER
        )
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Token decode failed")

def verify_and_get_username(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    payload = decode_token(token)
    username = payload.get("username")
    if not username:
        raise HTTPException(status_code=401, detail="Username not found in token")
    return username

@app.get("/user-profile")
def get_user_profile(
    username: str = Depends(verify_and_get_username),
    organization_codes: Optional[str] = Header(None, alias="organization-codes")
):
    for user in user_data:
        if user["userName"].lower() == username.lower():
            # User's authorized org codes
            user_orgs = {org["organizationCode"].upper() for org in user.get("organizations", [])}

            # Requested org codes from header
            if organization_codes:
                requested_orgs = {code.strip().upper() for code in organization_codes.split(",")}
            else:
                requested_orgs = set()

            matched_orgs = user_orgs.intersection(requested_orgs)
            unmatched_orgs = requested_orgs - user_orgs

            if not requested_orgs:
                return {
                    "authorized": False,
                    "message": "No organization codes provided in request headers"
                }

            if matched_orgs and not unmatched_orgs:
                return {
                    "authorized": True,
                    "message": "User is authorized to access all of these organizations",
                    "authorized_organizations": list(matched_orgs)
                }
            elif matched_orgs:
                return {
                    "authorized": True,
                    "message": "User is authorized to access some of the organizations",
                    "authorized_organizations": list(matched_orgs),
                    "unauthorized_organizations": list(unmatched_orgs)
                }
            else:
                return {
                    "authorized": False,
                    "message": "User is not authorized to access any of the provided organizations",
                    "unauthorized_organizations": list(unmatched_orgs)
                }

    raise HTTPException(status_code=404, detail="User not found")
