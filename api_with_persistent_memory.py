# -*- coding: utf-8 -*-
from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.security import APIKeyHeader
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request as GoogleRequest
from google.oauth2.credentials import Credentials
from google.oauth2 import id_token as google_id_token
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from starlette.middleware.sessions import SessionMiddleware
from pydantic import BaseModel, Field  # Added Field for potential future use
from datetime import datetime, timezone, timedelta
from typing import Optional, List
from zoneinfo import ZoneInfo  # Preferred over pytz for standard library
import os
import sqlite3
from dotenv import load_dotenv
import secrets
from fastapi.middleware.cors import CORSMiddleware
import json
import logging

# Logging configuration
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Load environment variables from .env file
load_dotenv()

# Initialize FastAPI app
app = FastAPI(
    title="FastAPI Google Integration",  # Generic Title
    description="Example API for managing Google Tasks & Calendar with FastAPI and OAuth",  # Generic Description
    version="1.0",
    openapi_url="/openapi.json",
    # Removed specific server URL - relies on deployment environment
)

# Add CORS middleware - Make ALLOWED_ORIGINS configurable via .env
# Example: ALLOWED_ORIGINS=http://localhost:3000,https://your-frontend.com
allowed_origins_str = os.getenv(
    "ALLOWED_ORIGINS", "http://localhost:3000"
)  # Default to common local dev port
allowed_origins = [origin.strip() for origin in allowed_origins_str.split(",")]
logger.info(f"Configuring CORS for origins: {allowed_origins}")

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,  # Use configured origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add session middleware configuration
# Use environment variable for secret, generate one if not set (less ideal for production persistence)
SESSION_SECRET = os.getenv("SESSION_SECRET")
if not SESSION_SECRET:
    logger.warning(
        "⚠️ SESSION_SECRET not set in environment, generating a temporary one. Sessions may not persist across restarts."
    )
    SESSION_SECRET = secrets.token_urlsafe(32)

app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    max_age=3600,  # 1 hour session, consider making configurable
    https_only=True,  # Session cookie (holds OAuth state) only sent over HTTPS
    same_site="lax",  # Allows the cookie on Google's top-level redirect back to /callback
)

# Config variables from .env - Emphasize these MUST be set by the user
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
# Default REDIRECT_URI to localhost for easier local dev, should be overridden for production
REDIRECT_URI = os.getenv(
    "REDIRECT_URI", f"http://localhost:{os.getenv('PORT', '10000')}/callback"
)
SCOPES = [
    "https://www.googleapis.com/auth/tasks",
    "https://www.googleapis.com/auth/calendar.events",
]
# Identity scopes requested only during sign-in so /callback can check which
# Google account is being linked (full URL form avoids oauthlib scope-change errors)
OAUTH_SCOPES = SCOPES + [
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
]
# Comma-separated list of Google account emails allowed to link via /callback.
# If unset, /callback rejects every sign-in (fail closed).
ALLOWED_GOOGLE_EMAILS = {
    email.strip().lower()
    for email in os.getenv("ALLOWED_GOOGLE_EMAILS", "").split(",")
    if email.strip()
}
# Default DB_PATH to a relative path, user should ensure it's persistent if needed
DB_PATH = os.getenv("DB_PATH", "google_auth_tokens.db")
API_KEY = os.getenv("API_KEY")  # This is for securing YOUR API, not Google's
PORT = os.getenv("PORT", "10000")
# Default Timezone - make it clear this is configurable
DEFAULT_TIMEZONE = os.getenv(
    "DEFAULT_TIMEZONE", "UTC"
)  # Default to UTC, user can override

# Validate essential configuration
if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
    logger.error(
        "❌ Critical Error: GOOGLE_CLIENT_ID or GOOGLE_CLIENT_SECRET not found in environment variables. OAuth flow will fail."
    )
    # Optionally raise an exception here or exit if it's absolutely essential at startup
    # raise ValueError("GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET must be set")
else:
    logger.info("✅ Google OAuth Client ID and Secret loaded.")

if not ALLOWED_GOOGLE_EMAILS:
    logger.warning(
        "⚠️ ALLOWED_GOOGLE_EMAILS not set. All Google sign-ins via /callback will be rejected."
    )

if not API_KEY:
    logger.warning(
        "⚠️ Security Warning: API_KEY not set in environment variables. API endpoints relying on X-API-Key will be inaccessible or insecure if check is bypassed."
    )
else:
    # Log API key status (mask it for security)
    masked_key = API_KEY[:4] + "*" * (len(API_KEY) - 4) if len(API_KEY) > 4 else "****"
    logger.info(f"✅ API Key loaded successfully (masked): {masked_key}")


# API Key authentication dependency
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def verify_api_key(api_key: str = Depends(api_key_header)):
    """
    Checks if the provided X-API-Key matches the one from .env.
    Raises 401 if API_KEY is not configured or doesn't match.
    """
    if not API_KEY:  # Check if the server has an API key configured at all
        logger.error("❌ API Key not configured on the server. Denying request.")
        raise HTTPException(
            status_code=503, detail="API Key security is not configured on the server."
        )

    masked_received_key = (
        api_key[:4] + "*" * (len(api_key) - 4)
        if api_key and len(api_key) > 4
        else "****"
        if api_key
        else "None"
    )
    logger.debug(
        f"🛠️ Received API Key in request (masked): {masked_received_key}"
    )  # Debug level maybe more appropriate

    if not api_key or not secrets.compare_digest(
        api_key, API_KEY
    ):  # Use compare_digest for security
        logger.warning(f"❌ Invalid API Key received (masked): {masked_received_key}")
        raise HTTPException(status_code=401, detail="Invalid or missing API key")

    logger.debug("✅ API Key verified successfully")  # Debug level
    return api_key


# ------------------------------------------------------------------
# Database utility functions
# ------------------------------------------------------------------
def get_db_connection():
    """
    Creates and returns a database connection.
    Ensures the directory for the DB_PATH exists.
    """
    db_dir = os.path.dirname(DB_PATH)
    if db_dir and not os.path.exists(db_dir):
        try:
            os.makedirs(db_dir, exist_ok=True)
            logger.info(f"✅ Created database directory: {db_dir}")
        except OSError as e:
            logger.error(f"❌ Failed to create database directory {db_dir}: {e}")
            raise  # Re-raise the exception as this is critical

    try:
        conn = sqlite3.connect(
            DB_PATH, check_same_thread=False
        )  # check_same_thread=False needed for FastAPI/SQLite
        conn.row_factory = sqlite3.Row  # Enable dictionary-like access to rows
        return conn
    except sqlite3.Error as e:
        logger.error(f"❌ Failed to connect to database at {DB_PATH}: {e}")
        raise  # Re-raise


def init_db():
    """
    Initializes the SQLite database table if it does not exist.
    """
    try:
        with get_db_connection() as conn:  # Use context manager
            cursor = conn.cursor()
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS tokens (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT UNIQUE NOT NULL DEFAULT 'default_user', -- Add user identifier if multi-user needed
                    access_token TEXT NOT NULL,
                    refresh_token TEXT,
                    expires_at REAL NOT NULL, -- Store as Unix timestamp (float)
                    token_scope TEXT -- Store scopes associated with the token
                )
            """
            )
            # Optionally add index for user_id if multi-user
            # cursor.execute("CREATE INDEX IF NOT EXISTS idx_user_id ON tokens (user_id)")
            conn.commit()
        logger.info(f"✅ Database initialized/verified at {DB_PATH}")
    except sqlite3.Error as e:
        logger.error(f"❌ Failed to initialize database: {e}")
        raise


def get_stored_tokens(user_id: str = "default_user"):  # Add user_id parameter
    """
    Fetches the most recently saved tokens for a specific user.
    Returns None if no tokens are found for the user.
    """
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            # Fetch the latest valid token for the user
            cursor.execute(
                "SELECT access_token, refresh_token, expires_at, token_scope FROM tokens WHERE user_id = ? ORDER BY id DESC LIMIT 1",
                (user_id,),
            )
            result = cursor.fetchone()
        return dict(result) if result else None
    except sqlite3.Error as e:
        logger.error(f"❌ Failed to fetch tokens for user {user_id}: {e}")
        return None  # Return None on error


def save_tokens(tokens: dict, user_id: str = "default_user"):  # Add user_id parameter
    """
    Saves new tokens into the database for a specific user, replacing old ones.
    """
    if not all(
        k in tokens for k in ["access_token", "refresh_token", "expires_at", "scope"]
    ):
        logger.error(
            f"❌ Attempted to save incomplete token data for user {user_id}. Missing required keys."
        )
        return  # Or raise an error

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            # Use INSERT OR REPLACE (or UPSERT in newer SQLite) to handle existing user
            cursor.execute(
                """
                INSERT INTO tokens (user_id, access_token, refresh_token, expires_at, token_scope)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    access_token=excluded.access_token,
                    refresh_token=excluded.refresh_token,
                    expires_at=excluded.expires_at,
                    token_scope=excluded.token_scope
                """,
                (
                    user_id,
                    tokens["access_token"],
                    tokens.get(
                        "refresh_token"
                    ),  # Use .get() as refresh token might not always be present on refresh
                    tokens["expires_at"],
                    tokens["scope"],  # Store the granted scopes
                ),
            )
            conn.commit()
        logger.info(f"✅ Tokens saved/updated for user {user_id} in database.")
    except sqlite3.Error as e:
        logger.error(f"❌ Failed to save tokens for user {user_id}: {e}")
        # Consider raising an exception here depending on desired error handling


# Initialize database when app starts
init_db()


# ------------------------------------------------------------------
# Google OAuth Config & Helpers
# ------------------------------------------------------------------
def get_client_config():
    """
    Returns the Google OAuth2 client config dictionary.
    Raises ValueError if client ID/secret are missing.
    """
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        logger.error("❌ Google Client ID or Secret not configured.")
        raise ValueError("Google OAuth credentials are not configured in environment.")

    return {
        "web": {
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [
                REDIRECT_URI
            ],  # Ensure this matches Google Cloud Console config
        }
    }


def build_credentials(user_id: str = "default_user") -> Optional[Credentials]:
    """Builds Google Credentials object from stored tokens."""
    tokens = get_stored_tokens(user_id)
    if not tokens:
        logger.warning(f"No stored tokens found for user {user_id}.")
        return None

    try:
        # Convert stored timestamp back to datetime object if needed, though Credentials might handle it
        # expiry_dt = datetime.fromtimestamp(tokens["expires_at"], tz=timezone.utc)

        # Ensure the stored scopes match or are a subset of the required SCOPES
        stored_scopes = set(tokens.get("token_scope", "").split())
        required_scopes = set(SCOPES)
        if not required_scopes.issubset(stored_scopes):
            logger.warning(
                f"Stored token scopes ({stored_scopes}) do not fully cover required scopes ({required_scopes}) for user {user_id}. Re-authentication might be needed."
            )
            # Depending on strictness, you might return None here or let it proceed and potentially fail later

        credentials = Credentials(
            token=tokens["access_token"],
            refresh_token=tokens["refresh_token"],
            token_uri="https://oauth2.googleapis.com/token",  # Standard Google token URI
            client_id=GOOGLE_CLIENT_ID,
            client_secret=GOOGLE_CLIENT_SECRET,
            scopes=list(stored_scopes),  # Use the scopes from the stored token
            # Optionally set expiry directly if needed, but Credentials handles refresh
            # expiry=expiry_dt
        )
        # Associate the expiry timestamp with the credentials object (optional, Credentials usually manages this internally)
        # google-auth compares expiry against a naive UTC datetime
        credentials.expiry = datetime.fromtimestamp(
            tokens["expires_at"], tz=timezone.utc
        ).replace(tzinfo=None)
        return credentials
    except Exception as e:
        logger.error(
            f"Error building credentials from stored tokens for user {user_id}: {e}"
        )
        return None


def refresh_tokens(
    credentials: Credentials, user_id: str = "default_user"
) -> Optional[Credentials]:
    """Refreshes expired tokens and updates the database."""
    if not credentials or not credentials.refresh_token:
        logger.error(
            f"Cannot refresh token for user {user_id}: No credentials or refresh token available."
        )
        return None

    try:
        logger.info(f"Attempting to refresh token for user {user_id}...")
        credentials.refresh(GoogleRequest())  # Google's transport request

        if not credentials.token or not credentials.valid:
            logger.error(
                f"Token refresh failed for user {user_id} - no valid token received after refresh."
            )
            # Consider deleting invalid tokens from DB or marking them as invalid
            return None

        # Prepare token data for saving
        new_tokens = {
            "access_token": credentials.token,
            "refresh_token": credentials.refresh_token,  # Refresh token might be updated by Google
            "expires_at": (
                credentials.expiry.replace(tzinfo=timezone.utc).timestamp()
                if credentials.expiry
                else (datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()
            ),
            "scope": " ".join(credentials.scopes or SCOPES),  # Save current scopes
        }
        save_tokens(new_tokens, user_id)
        logger.info(f"✅ Token refresh successful for user {user_id}.")
        return credentials

    except Exception as refresh_error:
        logger.error(
            f"❌ Token refresh failed for user {user_id}: {refresh_error}",
            exc_info=True,
        )
        # This often indicates the refresh token is invalid (revoked, expired, etc.)
        # Consider deleting the stored tokens to force re-authentication
        # delete_tokens(user_id) # Implement a delete function if needed
        return None


# ------------------------------------------------------------------
# Unified Service Creation
# ------------------------------------------------------------------
def get_authenticated_service(
    api_name: str, api_version: str, user_id: str = "default_user"
):
    """
    Creates and returns an authenticated Google API service instance.
    Handles token loading, validation, and refresh.
    """
    credentials = build_credentials(user_id)

    if not credentials:
        logger.error(
            f"Authentication required for user {user_id} to access {api_name} v{api_version}. No valid credentials found."
        )
        raise HTTPException(
            status_code=401,
            detail=f"Authentication required for user {user_id}. Please initiate auth flow.",
        )

    if credentials.expired:
        logger.info(f"Credentials expired for user {user_id}. Attempting refresh...")
        credentials = refresh_tokens(credentials, user_id)
        if not credentials:
            logger.error(
                f"Failed to refresh credentials for user {user_id}. Re-authentication needed."
            )
            # Maybe delete stale tokens here
            raise HTTPException(
                status_code=401,
                detail=f"Failed to refresh authentication for user {user_id}. Please re-authenticate.",
            )

    if not credentials.valid:
        logger.error(
            f"Credentials are not valid for user {user_id} after potential refresh."
        )
        raise HTTPException(
            status_code=401,
            detail=f"Invalid credentials for user {user_id}. Please re-authenticate.",
        )

    try:
        service = build(
            serviceName=api_name,
            version=api_version,
            credentials=credentials,
            cache_discovery=False,
        )  # Disable cache for potential issues
        logger.debug(
            f"Successfully built authenticated service '{api_name} v{api_version}' for user {user_id}."
        )
        return service
    except HttpError as e:
        error_status = e.resp.status if hasattr(e.resp, "status") else 500
        error_content = e.content.decode() if e.content else str(e)
        logger.error(
            f"❌ Google API HTTP error ({error_status}) for user {user_id} accessing {api_name}: {error_content}",
            exc_info=True,
        )
        # Specific handling for common errors
        if error_status == 401 or error_status == 403:  # Unauthorized or Forbidden
            detail = f"Google API authorization error ({error_status}) for user {user_id}. Check permissions or re-authenticate."
        else:
            detail = f"Google API error ({error_status}) for user {user_id}."
        raise HTTPException(status_code=error_status, detail=detail)
    except Exception as e:
        logger.error(
            f"❌ Unexpected error creating service '{api_name}' for user {user_id}: {e}",
            exc_info=True,
        )
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error while creating API service for user {user_id}.",
        )


# Convenience functions for specific services
def get_tasks_service(user_id: str = "default_user"):
    """Returns an authenticated Google Tasks service"""
    return get_authenticated_service("tasks", "v1", user_id)


def get_calendar_service(user_id: str = "default_user"):
    """Returns an authenticated Google Calendar service"""
    return get_authenticated_service("calendar", "v3", user_id)


# ------------------------------------------------------------------
# OAuth2 Routes
# ------------------------------------------------------------------
@app.get("/auth", summary="Initiate OAuth2 Flow")
async def auth(request: Request, key: Optional[str] = None):
    """
    Redirects the user to Google's OAuth 2.0 consent screen to grant permissions.
    Requires the API key as a `key` query parameter (this URL is opened in a browser,
    so the X-API-Key header cannot be used), e.g. /auth?key=YOUR_API_KEY
    """
    if not API_KEY:
        logger.error("❌ API Key not configured on the server. Denying /auth.")
        raise HTTPException(
            status_code=503, detail="API Key security is not configured on the server."
        )
    if not key or not secrets.compare_digest(key, API_KEY):
        logger.warning("❌ Invalid or missing API key on /auth request.")
        raise HTTPException(status_code=401, detail="Invalid or missing API key")

    try:
        flow = Flow.from_client_config(
            get_client_config(),  # Fetches config from env vars
            scopes=OAUTH_SCOPES,
            redirect_uri=REDIRECT_URI,
        )
        # Random CSRF token, stored in the (signed) session and verified in /callback
        state = secrets.token_urlsafe(32)
        authorization_url, _ = flow.authorization_url(
            access_type="offline",  # Request refresh token
            prompt="consent",  # Force consent screen even if previously granted
            include_granted_scopes="true",
            state=state,
        )
        request.session["oauth_state"] = state
        # Persist the PKCE verifier (if the library generated one) for the token exchange
        request.session["oauth_code_verifier"] = flow.code_verifier
        logger.info(
            f"Redirecting user to Google for authentication. State: {state[:5]}..."
        )  # Log partial state
        return RedirectResponse(authorization_url)

    except ValueError:  # Catch specific error from get_client_config
        logger.exception("OAuth config error during /auth")
        raise HTTPException(status_code=500, detail="OAuth configuration error.")
    except Exception:
        logger.exception("❌ OAuth2 initiation failed")
        raise HTTPException(status_code=500, detail="Failed to initiate OAuth2 flow.")


@app.get("/callback", summary="Handle OAuth2 Callback")
async def callback(request: Request):
    """
    Handles the callback from Google after user authorization.
    Exchanges the authorization code for tokens and saves them.
    """
    state = request.query_params.get("state")
    code = request.query_params.get("code")
    error = request.query_params.get("error")
    # Pop state/verifier so each /auth can only be completed once
    stored_state = request.session.pop("oauth_state", None)
    code_verifier = request.session.pop("oauth_code_verifier", None)

    # Security Check: Validate state parameter
    if not state or not stored_state or not secrets.compare_digest(state, stored_state):
        logger.error("❌ OAuth state mismatch or missing in /callback.")
        raise HTTPException(
            status_code=400, detail="Invalid state parameter. Possible CSRF attack."
        )

    if error:
        logger.error(f"❌ OAuth Error received from Google: {error}")
        return JSONResponse(
            status_code=400, content={"error": f"Google authorization failed: {error}"}
        )

    if not code:
        logger.error("❌ No authorization code received in callback.")
        return JSONResponse(
            status_code=400,
            content={"error": "Missing authorization code from Google."},
        )

    try:
        flow = Flow.from_client_config(
            get_client_config(),
            scopes=OAUTH_SCOPES,
            redirect_uri=REDIRECT_URI,
            state=stored_state,
        )
        flow.code_verifier = code_verifier

        # Exchange authorization code for tokens
        flow.fetch_token(code=code)
        credentials = flow.credentials  # google.oauth2.credentials.Credentials object

        # Only accept Google accounts on the allowlist (fail closed if unset)
        raw_id_token = flow.oauth2session.token.get("id_token")
        if not raw_id_token:
            logger.error("❌ No ID token returned by Google; cannot verify account.")
            raise HTTPException(
                status_code=403, detail="Unable to verify Google account."
            )
        id_info = google_id_token.verify_oauth2_token(
            raw_id_token, GoogleRequest(), GOOGLE_CLIENT_ID
        )
        email = (id_info.get("email") or "").lower()
        if (
            not id_info.get("email_verified")
            or not email
            or email not in ALLOWED_GOOGLE_EMAILS
        ):
            logger.warning(
                f"❌ Rejected Google sign-in for non-allowlisted account: {email or 'unknown'}"
            )
            raise HTTPException(
                status_code=403, detail="This Google account is not allowed."
            )

        logger.info(
            f"🔑 Credentials received - "
            f"Token: {bool(credentials.token)}, "
            f"Refresh Token: {bool(credentials.refresh_token)}, "
            f"Expiry: {credentials.expiry}, "
            f"Scopes: {credentials.scopes}"
        )

        # If no refresh token, log warning (may happen if user previously auth'd without 'prompt=consent')
        if not credentials.refresh_token:
            logger.warning(
                "⚠️ No refresh token received! This might happen if the user previously granted permission without the 'prompt=consent' parameter during the /auth request, or if the app is already approved. Offline access might be limited."
            )
            # Decide if this is acceptable or an error for your use case.
            # For long-lived access, a refresh token is crucial.

        # Prepare token structure for DB (handle potential None refresh token)
        tokens_to_save = {
            "access_token": credentials.token,
            "refresh_token": credentials.refresh_token,  # Can be None
            "expires_at": (
                credentials.expiry.replace(tzinfo=timezone.utc).timestamp()
                if credentials.expiry
                else (datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()
            ),
            "scope": " ".join(credentials.scopes or SCOPES),  # Store granted scopes
        }

        # Determine user ID (e.g., from session, state, or default)
        user_id = "default_user"  # Replace with actual user identification logic if multi-user

        # Save tokens to database
        save_tokens(tokens_to_save, user_id)

        # Verify tokens were saved (optional but good practice)
        stored = get_stored_tokens(user_id)
        if not stored or stored["access_token"] != tokens_to_save["access_token"]:
            logger.error(
                f"❌ Failed to verify saved tokens in database for user {user_id}."
            )
            raise HTTPException(
                status_code=500,
                detail="Failed to save or verify authentication tokens.",
            )
        logger.info(f"✅ Tokens successfully saved and verified for user {user_id}.")

        # Success response - Do not expose tokens
        return JSONResponse(
            content={
                "message": "Authentication successful. Tokens saved.",
                "user_id": user_id,  # Indicate which user was authenticated
                "scopes_granted": credentials.scopes,
            }
        )

    except HTTPException:
        raise
    except ValueError:  # get_client_config or ID token verification errors
        logger.exception("OAuth error during callback")
        raise HTTPException(status_code=500, detail="OAuth2 callback failed.")
    except Exception:
        logger.exception("❌ OAuth2 callback processing failed")
        raise HTTPException(status_code=500, detail="OAuth2 callback failed.")


# ------------------------------------------------------------------
# Helper Functions
# ------------------------------------------------------------------
def find_task_list(service, list_name: str) -> Optional[str]:
    """
    Finds the task list ID by name (case-insensitive).
    Returns the task list ID if found, otherwise None.
    Handles potential pagination if list is very long (though unlikely for task lists).
    """
    try:
        page_token = None
        while True:
            response = (
                service.tasklists().list(maxResults=100, pageToken=page_token).execute()
            )  # Max 100 per page
            for tasklist in response.get("items", []):
                if tasklist.get("title", "").lower() == list_name.lower():
                    logger.info(
                        f"Found task list '{list_name}' with ID: {tasklist['id']}"
                    )
                    return tasklist["id"]
            page_token = response.get("nextPageToken")
            if not page_token:
                break  # Exit loop if no more pages
        logger.warning(f"Task list '{list_name}' not found.")
        return None
    except HttpError as e:
        logger.error(
            f"❌ Google Tasks API error while fetching lists: {str(e)}", exc_info=True
        )
        raise HTTPException(
            status_code=e.resp.status if hasattr(e, "resp") else 500,
            detail="Error fetching task lists from Google.",
        )
    except Exception as e:
        logger.error(
            f"❌ Unexpected error finding task list '{list_name}': {e}", exc_info=True
        )
        raise HTTPException(
            status_code=500, detail="Internal server error finding task list."
        )


def retrieve_all_tasks(
    service,
    tasklist_id: str,
    include_completed: bool = True,
    include_hidden: bool = False,
) -> List[dict]:
    """
    Retrieves all tasks from a specific task list, handling pagination.
    """
    tasks = []
    page_token = None
    while True:
        try:
            request = service.tasks().list(
                tasklist=tasklist_id,
                showCompleted=include_completed,
                showHidden=include_hidden,
                maxResults=100,  # Max allowed per page
                pageToken=page_token,
            )
            response = request.execute()
            tasks.extend(response.get("items", []))
            page_token = response.get("nextPageToken")
            if not page_token:
                break
        except HttpError as e:
            logger.error(
                f"❌ Google Tasks API error retrieving tasks from list {tasklist_id}: {e}",
                exc_info=True,
            )
            raise HTTPException(
                status_code=e.resp.status if hasattr(e, "resp") else 500,
                detail="Error retrieving tasks.",
            )
        except Exception as e:
            logger.error(
                f"❌ Unexpected error retrieving tasks from list {tasklist_id}: {e}",
                exc_info=True,
            )
            raise HTTPException(
                status_code=500, detail="Internal server error retrieving tasks."
            )
    logger.info("Retrieved %d tasks from list ID %s.", len(tasks), tasklist_id)
    return tasks


def build_task_hierarchy(tasks: List[dict]) -> List[dict]:
    """Organizes a flat list of tasks into a parent-child hierarchy."""
    task_map = {task["id"]: task for task in tasks}
    top_level_tasks = []

    for task_id, task in task_map.items():
        task.setdefault("subtasks", [])  # Ensure subtasks list exists
        parent_id = task.get("parent")
        if parent_id and parent_id in task_map:
            # Append task to its parent's subtasks list
            parent_task = task_map[parent_id]
            parent_task.setdefault("subtasks", []).append(task)
        elif not parent_id:  # If it has no parent, it's a top-level task
            top_level_tasks.append(task)

    # Optional: Sort top-level tasks and subtasks by position or title if needed
    # def sort_key(task): return task.get('position', 'z') # Example sort by position
    # top_level_tasks.sort(key=sort_key)
    # for task in task_map.values():
    #     task['subtasks'].sort(key=sort_key)

    return top_level_tasks


def parse_datetime_with_timezone(
    dt_str: Optional[str], default_tz_str: str = DEFAULT_TIMEZONE
) -> Optional[str]:
    """
    Parses a datetime string (ISO format or just date) and returns
    an ISO 8601 string formatted correctly for Google API (RFC3339),
    using the provided default timezone if none is specified in the string.
    Returns None if input is None or invalid.
    """
    if not dt_str:
        return None

    try:
        # Get the timezone object
        try:
            default_tz = ZoneInfo(default_tz_str)
        except Exception:
            logger.warning(
                f"Invalid DEFAULT_TIMEZONE '{default_tz_str}', falling back to UTC."
            )
            default_tz = ZoneInfo("UTC")

        # Handle date-only strings by assuming midnight in the default timezone
        if "T" not in dt_str:
            dt_naive = datetime.strptime(dt_str, "%Y-%m-%d")
            dt_aware = default_tz.localize(
                dt_naive
            )  # Obsolete, use dt_naive.replace(tzinfo=default_tz) if needed directly
            dt_aware = datetime(
                dt_naive.year, dt_naive.month, dt_naive.day, 0, 0, 0, tzinfo=default_tz
            )

        # Handle full datetime strings
        else:
            # Attempt parsing with timezone first
            try:
                # Handle Z for UTC directly
                if dt_str.endswith("Z"):
                    dt_str = dt_str[:-1] + "+00:00"
                dt_aware = datetime.fromisoformat(dt_str)
                # If parsed successfully but no timezone, assume default timezone
                if (
                    dt_aware.tzinfo is None
                    or dt_aware.tzinfo.utcoffset(dt_aware) is None
                ):
                    dt_aware = dt_aware.replace(tzinfo=default_tz)

            except ValueError:
                # If parsing with timezone fails, try without and assume default tz
                dt_naive = datetime.fromisoformat(
                    dt_str.replace("Z", "")
                )  # Remove Z if present
                dt_aware = dt_naive.replace(tzinfo=default_tz)

        # Convert to UTC and format as RFC3339 (which Google API expects for 'due' field)
        # Note: Calendar API 'dateTime' field expects timezone info, so convert but keep tz
        # For Tasks 'due' (which is date-only effectively, time part ignored by UI):
        # return dt_aware.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')[:-4] + 'Z'
        # Let's return the full ISO format with timezone, more versatile.
        # Google Calendar uses RFC3339 format, which is essentially ISO 8601 with timezone.
        # Tasks API 'due' field technically expects RFC3339 too, but UI might only show date.
        return dt_aware.isoformat(
            timespec="seconds"
        )  # Format like 2024-03-20T15:30:00+00:00 or 2024-03-20T08:30:00-07:00

    except ValueError:
        logger.error(
            f"❌ Invalid date/datetime format: '{dt_str}'. Use ISO 8601 (e.g., 'YYYY-MM-DD' or 'YYYY-MM-DDTHH:MM:SSZ' or 'YYYY-MM-DDTHH:MM:SS+HH:MM')."
        )
        raise ValueError(f"Invalid date/datetime format: {dt_str}")
    except Exception as e:
        logger.error(f"❌ Error parsing date '{dt_str}': {e}", exc_info=True)
        raise ValueError(f"Error parsing date: {dt_str}")


# ------------------------------------------------------------------
# Pydantic Models (Request/Response Bodies)
# ------------------------------------------------------------------
class TaskInput(BaseModel):
    list_name: str = Field(..., description="Name of the target Google Task list.")
    title: str = Field(..., min_length=1, description="Title of the task.")
    notes: Optional[str] = Field(
        None, description="Optional details or notes for the task."
    )
    due: Optional[str] = Field(
        None,
        description="Due date/time in ISO 8601 format (e.g., 'YYYY-MM-DD' or 'YYYY-MM-DDTHH:MM:SSZ'). Timezone assumed UTC if not specified.",
    )
    parent_task_id: Optional[str] = Field(
        None, description="ID of the parent task if this is a subtask."
    )
    subtasks: Optional[List[str]] = Field(
        None, description="List of titles for subtasks to be created under this task."
    )

    def get_google_api_body(self) -> dict:
        """Formats data for Google Tasks API insert/update, handling 'due' conversion."""
        body = {"title": self.title.strip()}
        if self.notes is not None:  # Allow empty string notes if intended
            body["notes"] = self.notes
        if self.due:
            # Convert due date using the helper function, using UTC as the default assumption if no timezone provided in string
            parsed_due = parse_datetime_with_timezone(self.due, "UTC")
            if parsed_due:
                body["due"] = parsed_due  # Google Tasks API expects RFC3339 format
            else:
                raise ValueError(
                    f"Invalid 'due' date format: {self.due}"
                )  # Should be caught by parse_datetime_with_timezone

        # Note: parent_task_id is used in the API call parameters, not the body itself for insert.
        return body


class TaskUpdate(BaseModel):
    title: Optional[str] = Field(
        None, min_length=1, description="New title for the task."
    )
    notes: Optional[str] = Field(
        None, description="New notes for the task. Set to empty string to clear."
    )
    due: Optional[str] = Field(
        None,
        description="New due date/time (ISO 8601). Set to None or empty string via PATCH to clear.",
    )
    status: Optional[str] = Field(
        None,
        pattern="^(needsAction|completed)$",
        description="New status: 'needsAction' or 'completed'.",
    )
    # Add other fields like 'parent' (move) or 'position' if needed

    @property
    def has_updates(self) -> bool:
        """Check if any update field is provided."""
        return any(v is not None for v in self.model_dump(exclude_unset=True).values())

    def get_google_api_body(self, current_task_body: dict) -> dict:
        """Merges updates into the current task body for PATCH request."""
        update_body = {}
        if self.title is not None:
            update_body["title"] = self.title.strip()
        if self.notes is not None:
            update_body["notes"] = self.notes  # Allow empty string
        if self.status is not None:
            update_body["status"] = self.status
            # Google API: Setting status to 'completed' requires setting 'completed' timestamp,
            # clearing it requires setting status to 'needsAction' and clearing 'completed'
            if self.status == "completed":
                # Setting 'completed' to None or omitting it on update should set it implicitly? Test this.
                # Explicitly: update_body['completed'] = datetime.now(timezone.utc).isoformat(timespec='seconds') + 'Z'
                # Let's rely on Google's implicit handling first. If 'completed' is set, clear 'due'.
                update_body["due"] = None  # Usually clear due date when completing
            else:  # needsAction
                update_body["completed"] = None  # Explicitly clear completion time

        if self.due is not None:
            if self.due == "":  # Allow clearing the due date
                update_body["due"] = None
            else:
                parsed_due = parse_datetime_with_timezone(
                    self.due, "UTC"
                )  # Assume UTC if not specified
                if parsed_due:
                    update_body["due"] = parsed_due
                    if (
                        self.status != "completed"
                    ):  # If setting due date, ensure task is not completed
                        update_body["status"] = "needsAction"
                        update_body["completed"] = None
                else:
                    raise ValueError(
                        f"Invalid 'due' date format provided for update: {self.due}"
                    )
        elif "due" in self.model_dump(exclude_unset=True) and self.due is None:
            # Handle explicit null setting to clear due date
            update_body["due"] = None

        # Important for PATCH: Only include fields that are actually changing.
        # The Google API client handles PATCH semantics correctly if you provide only changed fields.
        # However, constructing the body manually like this requires care.
        # Let's return only the fields present in the update request.

        final_body = current_task_body.copy()  # Start with existing task
        final_body.update(update_body)  # Overwrite with changes

        # Return only the changed fields relative to current_task_body
        # This is safer for PATCH as it avoids accidentally reverting other fields.
        patch_body = {k: final_body[k] for k in update_body if k in final_body}

        # Handle explicit nulls for clearing fields in PATCH
        if "notes" in self.model_dump(exclude_unset=True) and self.notes is None:
            patch_body["notes"] = None
        if "due" in self.model_dump(exclude_unset=True) and self.due is None:
            patch_body["due"] = None

        return patch_body  # Return only the fields intended for update


class TaskListInput(BaseModel):
    title: str = Field(..., min_length=1, description="Name for the new task list.")


class BatchDeleteRequest(BaseModel):
    task_ids: List[str] = Field(
        ..., min_length=1, description="List of task IDs to delete."
    )


class ReorderRequest(BaseModel):
    # ID of the task to move
    task_id: str = Field(..., description="The ID of the task to move.")
    # ID of the task *after* which the `task_id` should be placed.
    # If omitted or null, the task is moved to the top of the list (or top level).
    previous_sibling_id: Optional[str] = Field(
        None,
        description="ID of the task that should precede the moved task. Omit to move to top.",
    )
    # ID of the parent task under which the task should be moved.
    # If omitted or null, the task is moved to the top level.
    # `previous_sibling_id` takes precedence if both are provided for positioning within the same level.
    parent_id: Optional[str] = Field(
        None, description="ID of the parent task. Omit to move to top level."
    )


# --- Calendar Models ---
class EventDateTime(BaseModel):
    # Represents Google Calendar's dateTime/timeZone structure
    dateTime: str = Field(
        ...,
        description="ISO 8601 datetime string (e.g., 'YYYY-MM-DDTHH:MM:SSZ' or 'YYYY-MM-DDTHH:MM:SS+HH:MM').",
    )
    timeZone: Optional[str] = Field(
        DEFAULT_TIMEZONE,
        description=f"Timezone ID (e.g., 'America/New_York', 'Europe/London'). Defaults to server's DEFAULT_TIMEZONE ('{DEFAULT_TIMEZONE}').",
    )

    def get_google_api_format(self) -> dict:
        """Ensures dateTime is correctly formatted and includes timezone."""
        # Use the helper to parse and potentially add default timezone
        parsed_dt = parse_datetime_with_timezone(
            self.dateTime, self.timeZone or DEFAULT_TIMEZONE
        )
        if not parsed_dt:
            raise ValueError(f"Invalid dateTime format: {self.dateTime}")

        # Google Calendar API expects the timezone separately
        # Let's parse the final timezone from the parsed string
        final_dt_obj = datetime.fromisoformat(parsed_dt)
        final_tz_str = (
            final_dt_obj.tzinfo.tzname(final_dt_obj)
            if final_dt_obj.tzinfo
            else self.timeZone or DEFAULT_TIMEZONE
        )

        # Try to map standard offsets back to ZoneInfo keys if possible, otherwise use the provided/default string
        # This mapping is complex, stick to using the provided/default ZoneInfo key.
        # Ensure the final timezone is valid IANA format if possible.
        try:
            _ = ZoneInfo(final_tz_str)
            google_tz = final_tz_str
        except Exception:
            logger.warning(
                f"Could not validate timezone '{final_tz_str}' as ZoneInfo, using it directly."
            )
            google_tz = final_tz_str  # Use the string directly if ZoneInfo fails (e.g., might be fixed offset)

        return {
            "dateTime": final_dt_obj.isoformat(
                timespec="seconds"
            ),  # Ensure full ISO format
            "timeZone": google_tz,
        }


class EventInput(BaseModel):
    summary: str = Field(
        ..., min_length=1, description="Title or summary of the event."
    )
    description: Optional[str] = Field(
        None, description="Optional detailed description of the event."
    )
    start: EventDateTime = Field(..., description="Event start time and timezone.")
    end: EventDateTime = Field(..., description="Event end time and timezone.")
    location: Optional[str] = Field(None, description="Optional location of the event.")
    # For advanced creation:
    attendees: Optional[List[str]] = Field(
        None, description="List of attendee email addresses."
    )
    recurrence: Optional[List[str]] = Field(
        None,
        description="List of recurrence rules (RRULE, EXRULE, RDATE, EXDATE strings). Example: ['RRULE:FREQ=WEEKLY;COUNT=10']",
    )
    create_meet_link: bool = Field(
        False, description="Set to true to automatically create a Google Meet link."
    )

    def get_google_api_body(self) -> dict:
        """Formats data for Google Calendar API event insertion."""
        if not self.summary.strip():
            raise ValueError("Event summary cannot be empty.")

        try:
            start_data = self.start.get_google_api_format()
            end_data = self.end.get_google_api_format()

            # Basic validation: end time should be after start time
            start_dt = datetime.fromisoformat(start_data["dateTime"])
            end_dt = datetime.fromisoformat(end_data["dateTime"])
            if end_dt <= start_dt:
                raise ValueError("Event end time must be after start time.")

            body = {
                "summary": self.summary.strip(),
                "start": start_data,
                "end": end_data,
            }
            if self.description is not None:
                body["description"] = self.description
            if self.location is not None:
                body["location"] = self.location

            # Add advanced fields
            if self.attendees:
                body["attendees"] = [
                    {"email": email.strip()}
                    for email in self.attendees
                    if email.strip()
                ]
            if self.recurrence:
                body["recurrence"] = self.recurrence

            # Add conference data request if needed
            if self.create_meet_link:
                # Use a unique request ID
                conference_request_id = f"meet-request-{secrets.token_hex(8)}"
                body["conferenceData"] = {
                    "createRequest": {
                        "requestId": conference_request_id,
                        "conferenceSolutionKey": {"type": "hangoutsMeet"},
                    }
                }

            logger.info(f"Prepared Google Calendar event body: {body}")
            return body

        except ValueError as ve:
            logger.error(f"Validation error preparing event data: {ve}")
            raise  # Re-raise validation errors
        except Exception as e:
            logger.error(
                f"❌ Unexpected error preparing event data: {e}", exc_info=True
            )
            raise ValueError("Error preparing event data.")


class EventUpdate(BaseModel):
    summary: Optional[str] = Field(
        None, min_length=1, description="New summary for the event."
    )
    description: Optional[str] = Field(
        None, description="New description. Set to empty string to clear."
    )
    start: Optional[EventDateTime] = Field(None, description="New start time/timezone.")
    end: Optional[EventDateTime] = Field(None, description="New end time/timezone.")
    location: Optional[str] = Field(
        None, description="New location. Set to empty string to clear."
    )
    # Add attendees, recurrence updates if needed - complex due to patching lists

    @property
    def has_updates(self) -> bool:
        """Check if any update field is provided."""
        # Use exclude_unset=True to only consider fields explicitly provided in the request
        return bool(self.model_dump(exclude_unset=True))

    def get_google_api_body(self, current_event_body: dict) -> dict:
        """Constructs the body for a PATCH request, including only changed fields."""
        patch_body = {}
        update_data = self.model_dump(exclude_unset=True)  # Get only provided fields

        if "summary" in update_data:
            patch_body["summary"] = update_data["summary"].strip()
        if "description" in update_data:
            patch_body["description"] = update_data["description"]  # Allow empty string
        if "location" in update_data:
            patch_body["location"] = update_data["location"]

        # Handle time updates carefully
        start_updated = "start" in update_data
        end_updated = "end" in update_data

        if start_updated:
            try:
                patch_body["start"] = self.start.get_google_api_format()
            except Exception as e:
                raise ValueError(f"Invalid start time format for update: {e}")

        if end_updated:
            try:
                patch_body["end"] = self.end.get_google_api_format()
            except Exception as e:
                raise ValueError(f"Invalid end time format for update: {e}")

        # Validate start/end consistency if both are updated or one is updated relative to the existing one
        final_start_str = patch_body.get("start", {}).get(
            "dateTime"
        ) or current_event_body.get("start", {}).get("dateTime")
        final_end_str = patch_body.get("end", {}).get(
            "dateTime"
        ) or current_event_body.get("end", {}).get("dateTime")

        if final_start_str and final_end_str:
            try:
                final_start_dt = datetime.fromisoformat(final_start_str)
                final_end_dt = datetime.fromisoformat(final_end_str)
                if final_end_dt <= final_start_dt:
                    raise ValueError("Event end time must be after start time.")
            except ValueError as e:
                raise ValueError(
                    f"Error validating updated event times: {e}"
                )  # Re-raise validation error

        # Handle explicit nulls if needed (e.g., to clear description/location)
        if "description" in update_data and self.description is None:
            patch_body["description"] = None
        if "location" in update_data and self.location is None:
            patch_body["location"] = None

        if not patch_body:
            raise ValueError("No valid update fields provided.")

        return patch_body


# ------------------------------------------------------------------
# API Endpoints
# ------------------------------------------------------------------


# --- Health & Debug ---
@app.get("/health", summary="Health Check", tags=["_System"])
async def health_check():
    """
    Checks basic API health and tries to connect to Google Tasks API
    using potentially stored credentials (if any). Doesn't require API key.
    """
    google_status = "disconnected"
    google_error = None
    try:
        # Try to build credentials, don't necessarily need a full service call
        creds = build_credentials()  # Check default user
        if creds and creds.valid:
            google_status = "potentially_connected (valid token found)"
            # Optionally make a lightweight API call like tasklists.list
            # service = get_tasks_service()
            # service.tasklists().list(maxResults=1).execute()
            # google_status = "connected"
        elif creds and creds.expired and creds.refresh_token:
            google_status = "token_expired (refresh possible)"
        elif creds:
            google_status = "token_invalid"
        else:
            google_status = "not_authenticated (no token found)"

    except HttpError:
        google_status = "error_google_api"
        google_error = "Google API error"
        logger.exception("Health check Google API error")
    except Exception:
        google_status = "error_internal"
        google_error = "Internal error"
        logger.exception("Health check internal error")

    response_content = {
        "status": (
            "healthy"
            if google_status not in ["error_google_api", "error_internal"]
            else "unhealthy"
        ),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "google_api_status": google_status,
    }
    if google_error:
        response_content["google_api_error"] = google_error

    status_code = 200 if response_content["status"] == "healthy" else 503
    return JSONResponse(status_code=status_code, content=response_content)


@app.get(
    "/debug-tokens",
    summary="Debug Stored Tokens (Masked)",
    tags=["_System"],
    dependencies=[Depends(verify_api_key)],
)
async def debug_tokens(user_id: str = "default_user"):
    """
    [Requires API Key] Returns *masked* token data for debugging purposes.
    Never returns raw tokens. Shows data for 'default_user' unless user_id query param is provided.
    """
    tokens = get_stored_tokens(user_id)
    if not tokens:
        raise HTTPException(
            status_code=404,
            detail=f"No tokens found in the database for user '{user_id}'.",
        )

    def mask_token(token):
        if not token:
            return None
        return token[:8] + "..." + token[-4:] if len(token) > 12 else token[:4] + "..."

    expires_dt = (
        datetime.fromtimestamp(tokens["expires_at"], tz=timezone.utc)
        if tokens.get("expires_at")
        else None
    )
    now = datetime.now(timezone.utc)
    is_expired = expires_dt < now if expires_dt else "N/A"
    time_left = str(expires_dt - now) if expires_dt and not is_expired else "N/A"

    masked_tokens = {
        "user_id": user_id,
        "access_token_masked": mask_token(tokens.get("access_token")),
        "refresh_token_present": bool(tokens.get("refresh_token")),
        "refresh_token_masked": mask_token(tokens.get("refresh_token")),
        "expires_at_timestamp": tokens.get("expires_at"),
        "expires_at_utc": expires_dt.isoformat() if expires_dt else None,
        "is_expired": is_expired,
        "time_until_expiry": time_left,
        "scopes": tokens.get("token_scope", "").split(),
    }
    return JSONResponse(content=masked_tokens)


# --- Task Lists ---
@app.get(
    "/tasklists",
    summary="List Task Lists",
    tags=["Task Lists"],
    dependencies=[Depends(verify_api_key)],
)
async def get_task_lists(user_id: str = "default_user"):
    """
    [Requires API Key] Returns all available Google Task lists for the authenticated user.
    """
    try:
        service = get_tasks_service(user_id)
        tasklists_response = (
            service.tasklists().list().execute()
        )  # Fetches all lists (usually not many)
        formatted_lists = [
            {"id": tl.get("id"), "title": tl.get("title")}
            for tl in tasklists_response.get("items", [])
        ]
        return JSONResponse(content={"tasklists": formatted_lists})
    except HttpError as e:
        logger.error(
            f"API Error listing task lists for user {user_id}: {e}", exc_info=True
        )
        raise HTTPException(
            status_code=e.resp.status if hasattr(e, "resp") else 500,
            detail="Google API error listing task lists.",
        )
    except HTTPException as e:
        raise e  # Re-raise auth errors etc.
    except Exception as e:
        logger.error(
            f"Unexpected error listing task lists for user {user_id}: {e}",
            exc_info=True,
        )
        raise HTTPException(
            status_code=500, detail="Internal server error listing task lists."
        )


@app.post(
    "/tasklists",
    summary="Create Task List",
    status_code=201,
    tags=["Task Lists"],
    dependencies=[Depends(verify_api_key)],
)
async def create_task_list(
    tasklist_input: TaskListInput, user_id: str = "default_user"
):
    """
    [Requires API Key] Creates a new Google Task list for the authenticated user.
    """
    try:
        service = get_tasks_service(user_id)
        new_list_body = {"title": tasklist_input.title.strip()}
        created_list = service.tasklists().insert(body=new_list_body).execute()
        logger.info(
            f"User {user_id} created task list '{created_list.get('title')}' (ID: {created_list.get('id')})"
        )
        return JSONResponse(
            status_code=201,
            content={
                "message": f"Task list '{created_list.get('title')}' created successfully.",
                "id": created_list.get("id"),
                "title": created_list.get("title"),
            },
        )
    except HttpError as e:
        logger.error(
            f"API Error creating task list for user {user_id}: {e}", exc_info=True
        )
        raise HTTPException(
            status_code=e.resp.status if hasattr(e, "resp") else 500,
            detail="Google API error creating task list.",
        )
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(
            f"Unexpected error creating task list for user {user_id}: {e}",
            exc_info=True,
        )
        raise HTTPException(
            status_code=500, detail="Internal server error creating task list."
        )


# --- Tasks ---
@app.get(
    "/tasks/{list_name}",
    summary="List Tasks (Hierarchical)",
    tags=["Tasks"],
    dependencies=[Depends(verify_api_key)],
)
async def list_tasks(
    list_name: str, user_id: str = "default_user", include_completed: bool = False
):
    """
    [Requires API Key] Lists tasks from a specific Google Task list, organizing them hierarchically.
    By default, completed tasks are hidden unless `include_completed=true` query param is added.
    """
    try:
        service = get_tasks_service(user_id)
        tasklist_id = find_task_list(service, list_name)
        if not tasklist_id:
            raise HTTPException(
                status_code=404,
                detail=f"Task list '{list_name}' not found for user '{user_id}'.",
            )

        # Fetch tasks (including hidden for hierarchy building, filter later if needed)
        retrieve_all_tasks(
            service, tasklist_id, include_completed=True, include_hidden=True
        )

        # Filter based on include_completed *after* hierarchy building if needed, or let retrieve_all_tasks handle it.
        # Let's rely on retrieve_all_tasks filter for simplicity now.
        tasks_to_structure = retrieve_all_tasks(
            service,
            tasklist_id,
            include_completed=include_completed,
            include_hidden=False,
        )

        # Build hierarchy
        top_level_tasks = build_task_hierarchy(tasks_to_structure)

        return JSONResponse(
            content={
                "list_name": list_name,
                "list_id": tasklist_id,
                "tasks": top_level_tasks,
                "total_items_retrieved": len(tasks_to_structure),
            }
        )

    except HTTPException as e:
        raise e  # Handles 404 from find_task_list and auth errors
    except HttpError as e:
        logger.error(
            f"API Error listing tasks in '{list_name}' for user {user_id}: {e}",
            exc_info=True,
        )
        raise HTTPException(
            status_code=e.resp.status if hasattr(e, "resp") else 500,
            detail="Google API error listing tasks.",
        )
    except Exception as e:
        logger.error(
            f"Unexpected error listing tasks in '{list_name}' for user {user_id}: {e}",
            exc_info=True,
        )
        raise HTTPException(
            status_code=500, detail="Internal server error listing tasks."
        )


@app.post(
    "/tasks/add",
    summary="Add Task",
    status_code=201,
    tags=["Tasks"],
    dependencies=[Depends(verify_api_key)],
)
async def add_task(task_input: TaskInput, user_id: str = "default_user"):
    """
    [Requires API Key] Adds a new task (and optionally subtasks) to a specified Google Task list.
    """
    try:
        service = get_tasks_service(user_id)
        tasklist_id = find_task_list(service, task_input.list_name)
        if not tasklist_id:
            raise HTTPException(
                status_code=404,
                detail=f"Task list '{task_input.list_name}' not found for user '{user_id}'.",
            )

        # Validate parent task ID if provided
        if task_input.parent_task_id:
            try:
                # Check if parent task exists in the same list
                service.tasks().get(
                    tasklist=tasklist_id, task=task_input.parent_task_id
                ).execute()
            except HttpError as e:
                if e.resp.status == 404:
                    raise HTTPException(
                        status_code=404,
                        detail=f"Parent task with ID '{task_input.parent_task_id}' not found in list '{task_input.list_name}'.",
                    )
                else:
                    raise  # Re-raise other Google errors

        # Prepare main task body
        task_body = task_input.get_google_api_body()

        # Insert the main task
        new_task = (
            service.tasks()
            .insert(
                tasklist=tasklist_id,
                body=task_body,
                parent=task_input.parent_task_id,  # This param seems wrong, parent goes in body? API Doc check needed.
                # Correction: No, parent is NOT in body for insert, it's a URL parameter or sibling (`previous`).
                # Let's assume adding as top-level or subtask based on parent_task_id presence.
                # If parent_task_id is set, it should be added as a subtask. Google API might handle this via `parent` field in body?
                # Let's try adding parent to body, assuming TaskInput handles it.
                # Update: Google Tasks API v1 insert *does not* take parent in body. Subtasks are created by inserting *new* tasks with the 'parent' field set.
                # So, we insert the main task first, then subtasks referencing its ID.
            )
            .execute()
        )  # Execute the insert for the main task

        main_task_id = new_task.get("id")
        logger.info(
            f"User {user_id} added task '{new_task.get('title')}' (ID: {main_task_id}) to list '{task_input.list_name}'."
        )

        # Add subtasks if provided
        created_subtasks = []
        if task_input.subtasks and main_task_id:
            for subtask_title in task_input.subtasks:
                if not subtask_title.strip():
                    logger.warning("Skipping empty subtask title.")
                    continue
                subtask_body = {
                    "title": subtask_title.strip(),
                    "parent": main_task_id,
                }  # Set parent ID here
                try:
                    subtask = (
                        service.tasks()
                        .insert(
                            tasklist=tasklist_id,
                            body=subtask_body,
                            # No 'previous' specified, adds to end of subtask list
                        )
                        .execute()
                    )
                    created_subtasks.append(
                        {"title": subtask.get("title"), "id": subtask.get("id")}
                    )
                    logger.info(
                        f"Added subtask '{subtask.get('title')}' (ID: {subtask.get('id')}) to parent {main_task_id}."
                    )
                except HttpError as sub_err:
                    logger.error(f"Failed to add subtask '{subtask_title}': {sub_err}")
                    # Decide whether to continue adding others or raise error

        return JSONResponse(
            status_code=201,
            content={
                "message": f"Task '{new_task.get('title')}' added successfully.",
                "list_name": task_input.list_name,
                "task_id": main_task_id,
                "task_details": new_task,  # Return full created task object
                "subtasks_added": created_subtasks,
            },
        )

    except ValueError as ve:  # Catch validation errors from Pydantic models/helpers
        logger.warning(f"Validation error adding task: {ve}")
        raise HTTPException(status_code=400, detail=str(ve))
    except HTTPException as e:
        raise e  # Handles 404s etc.
    except HttpError as e:
        logger.error(
            f"API Error adding task to '{task_input.list_name}' for user {user_id}: {e}",
            exc_info=True,
        )
        raise HTTPException(
            status_code=e.resp.status if hasattr(e, "resp") else 500,
            detail="Google API error adding task.",
        )
    except Exception as e:
        logger.error(
            f"Unexpected error adding task to '{task_input.list_name}' for user {user_id}: {e}",
            exc_info=True,
        )
        raise HTTPException(
            status_code=500, detail="Internal server error adding task."
        )


@app.patch(
    "/tasks/{list_name}/{task_id}",
    summary="Update Task",
    tags=["Tasks"],
    dependencies=[Depends(verify_api_key)],
)
async def update_task(
    list_name: str, task_id: str, update_data: TaskUpdate, user_id: str = "default_user"
):
    """
    [Requires API Key] Updates properties of an existing task (title, notes, due, status).
    Uses PATCH semantics: only provided fields are updated.
    To clear 'notes' or 'due', provide them as empty strings or null (depending on client). Model handles "" for due clearing.
    """
    if not update_data.has_updates:
        raise HTTPException(status_code=400, detail="No update data provided.")

    try:
        service = get_tasks_service(user_id)
        tasklist_id = find_task_list(service, list_name)
        if not tasklist_id:
            raise HTTPException(
                status_code=404,
                detail=f"Task list '{list_name}' not found for user '{user_id}'.",
            )

        # Get the current task to apply patch logic if needed by helper (though googleapiclient should handle PATCH)
        try:
            current_task = (
                service.tasks().get(tasklist=tasklist_id, task=task_id).execute()
            )
        except HttpError as e:
            if e.resp.status == 404:
                raise HTTPException(
                    status_code=404,
                    detail=f"Task with ID '{task_id}' not found in list '{list_name}'.",
                )
            else:
                raise  # Re-raise other Google errors

        # Prepare the body for the PATCH request using the helper
        patch_body = update_data.get_google_api_body(
            current_task
        )  # Pass current task for context if needed

        if not patch_body:
            # This case might occur if validation removed all fields, though has_updates should prevent it
            raise HTTPException(
                status_code=400, detail="No valid update fields after processing."
            )

        updated_task = (
            service.tasks()
            .patch(  # Use PATCH method
                tasklist=tasklist_id, task=task_id, body=patch_body
            )
            .execute()
        )

        logger.info(f"User {user_id} updated task ID {task_id} in list '{list_name}'.")
        return JSONResponse(
            content={
                "message": "Task updated successfully.",
                "task": updated_task,  # Return the updated task object
            }
        )

    except ValueError as ve:  # Catch validation errors
        logger.warning(f"Validation error updating task {task_id}: {ve}")
        raise HTTPException(status_code=400, detail=str(ve))
    except HTTPException as e:
        raise e
    except HttpError as e:
        logger.error(
            f"API Error updating task {task_id} in '{list_name}' for user {user_id}: {e}",
            exc_info=True,
        )
        raise HTTPException(
            status_code=e.resp.status if hasattr(e, "resp") else 500,
            detail="Google API error updating task.",
        )
    except Exception as e:
        logger.error(
            f"Unexpected error updating task {task_id} in '{list_name}' for user {user_id}: {e}",
            exc_info=True,
        )
        raise HTTPException(
            status_code=500, detail="Internal server error updating task."
        )


@app.post(
    "/tasks/{list_name}/{task_id}/toggle",
    summary="Toggle Task Completion",
    tags=["Tasks"],
    dependencies=[Depends(verify_api_key)],
)
async def toggle_task_completion(
    list_name: str, task_id: str, user_id: str = "default_user"
):
    """
    [Requires API Key] Toggles the completion status of a task between 'needsAction' and 'completed'.
    """
    try:
        service = get_tasks_service(user_id)
        tasklist_id = find_task_list(service, list_name)
        if not tasklist_id:
            raise HTTPException(
                status_code=404, detail=f"Task list '{list_name}' not found."
            )

        try:
            task = service.tasks().get(tasklist=tasklist_id, task=task_id).execute()
        except HttpError as e:
            if e.resp.status == 404:
                raise HTTPException(
                    status_code=404,
                    detail=f"Task ID '{task_id}' not found in list '{list_name}'.",
                )
            else:
                raise

        current_status = task.get("status", "needsAction")
        new_status = "completed" if current_status == "needsAction" else "needsAction"

        patch_body = {"status": new_status}
        # Google API handles setting/clearing 'completed' timestamp based on status automatically.
        # Explicitly clear 'due' when completing? Optional, depends on desired workflow.
        # if new_status == 'completed':
        #     patch_body['due'] = None

        updated_task = (
            service.tasks()
            .patch(tasklist=tasklist_id, task=task_id, body=patch_body)
            .execute()
        )

        action = "completed" if new_status == "completed" else "marked as incomplete"
        logger.info(f"User {user_id} {action} task ID {task_id} in list '{list_name}'.")
        return JSONResponse(
            content={
                "message": f"Task status toggled to '{new_status}'.",
                "task": updated_task,
            }
        )

    except HTTPException as e:
        raise e
    except HttpError as e:
        logger.error(f"API Error toggling task {task_id}: {e}", exc_info=True)
        raise HTTPException(
            status_code=e.resp.status if hasattr(e, "resp") else 500,
            detail="Google API error toggling task.",
        )
    except Exception as e:
        logger.error(f"Unexpected error toggling task {task_id}: {e}", exc_info=True)
        raise HTTPException(
            status_code=500, detail="Internal server error toggling task."
        )


@app.delete(
    "/tasks/{list_name}/{task_id}",
    summary="Delete Task",
    tags=["Tasks"],
    dependencies=[Depends(verify_api_key)],
)
async def delete_task(list_name: str, task_id: str, user_id: str = "default_user"):
    """
    [Requires API Key] Deletes a specific task from a list.
    Warning: Deleting a parent task might also delete its subtasks (verify Google API behavior).
    """
    try:
        service = get_tasks_service(user_id)
        tasklist_id = find_task_list(service, list_name)
        if not tasklist_id:
            raise HTTPException(
                status_code=404, detail=f"Task list '{list_name}' not found."
            )

        try:
            # Check if task exists before deleting (optional, delete is idempotent)
            # service.tasks().get(tasklist=tasklist_id, task=task_id).execute()

            service.tasks().delete(tasklist=tasklist_id, task=task_id).execute()
            logger.info(
                f"User {user_id} deleted task ID {task_id} from list '{list_name}'."
            )
            # No content typically returned on successful DELETE
            return JSONResponse(
                status_code=200,
                content={
                    "message": f"Task '{task_id}' deleted successfully from '{list_name}'."
                },
            )
            # return Response(status_code=204) # Alternative: 204 No Content

        except HttpError as e:
            if e.resp.status == 404:
                # If the task is already gone, arguably it's not an error for DELETE
                logger.warning(
                    f"Task ID '{task_id}' not found during delete attempt (might be already deleted)."
                )
                raise HTTPException(
                    status_code=404,
                    detail=f"Task ID '{task_id}' not found in list '{list_name}'.",
                )
            else:
                logger.error(f"API Error deleting task {task_id}: {e}", exc_info=True)
                raise HTTPException(
                    status_code=e.resp.status,
                    detail="Google API error deleting task.",
                )

    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Unexpected error deleting task {task_id}: {e}", exc_info=True)
        raise HTTPException(
            status_code=500, detail="Internal server error deleting task."
        )


@app.post(
    "/tasks/{list_name}/batch-delete",
    summary="Batch Delete Tasks",
    tags=["Tasks"],
    dependencies=[Depends(verify_api_key)],
)
async def batch_delete_tasks_endpoint(
    list_name: str, delete_request: BatchDeleteRequest, user_id: str = "default_user"
):
    """
    [Requires API Key] Deletes multiple tasks from a list in a single batch operation for efficiency.
    Note: Partial failures are possible; check logs for details.
    """
    if not delete_request.task_ids:
        raise HTTPException(
            status_code=400, detail="No task IDs provided for batch deletion."
        )

    success_count = 0
    fail_count = 0
    errors = {}  # Store errors per request_id

    def batch_callback(request_id, response, exception):
        nonlocal success_count, fail_count  # Allow modifying outer scope variables
        if exception:
            fail_count += 1
            error_detail = str(exception)
            status_code = 500
            if isinstance(exception, HttpError):
                status_code = (
                    exception.resp.status if hasattr(exception.resp, "status") else 500
                )
                error_detail = f"Google API Error ({status_code}): {error_detail}"
                if status_code == 404:
                    error_detail += " (Task may have been already deleted)"

            logger.error(
                f"❌ Error deleting task {request_id} in batch: {error_detail}"
            )
            errors[request_id] = error_detail
        else:
            success_count += 1
            logger.info(f"✅ Successfully deleted task {request_id} in batch.")
            # Response is None for successful delete

    try:
        service = get_tasks_service(user_id)
        tasklist_id = find_task_list(service, list_name)
        if not tasklist_id:
            raise HTTPException(
                status_code=404, detail=f"Task list '{list_name}' not found."
            )

        batch = service.new_batch_http_request(callback=batch_callback)

        for task_id in delete_request.task_ids:
            batch.add(
                service.tasks().delete(tasklist=tasklist_id, task=task_id),
                request_id=task_id,  # Use task_id as unique identifier for callback
            )

        logger.info(
            f"Executing batch delete for {len(delete_request.task_ids)} tasks in list '{list_name}' for user {user_id}..."
        )
        batch.execute()
        logger.info(
            f"Batch delete executed. Success: {success_count}, Failures: {fail_count}"
        )

        status_code = (
            200 if fail_count == 0 else 207
        )  # 207 Multi-Status if partial success

        return JSONResponse(
            status_code=status_code,
            content={
                "message": f"Batch deletion executed for {len(delete_request.task_ids)} tasks in '{list_name}'.",
                "successful_deletions": success_count,
                "failed_deletions": fail_count,
                "errors": (
                    errors if errors else None
                ),  # Only include errors field if failures occurred
            },
        )

    except HTTPException as e:
        raise e
    except HttpError as e:  # Error executing the batch itself (e.g., auth)
        logger.error(
            f"API Error during batch delete setup/execution: {e}", exc_info=True
        )
        raise HTTPException(
            status_code=e.resp.status if hasattr(e, "resp") else 500,
            detail="Google API error during batch delete.",
        )
    except Exception as e:
        logger.error(f"Unexpected error during batch delete: {e}", exc_info=True)
        raise HTTPException(
            status_code=500, detail="Internal server error during batch delete."
        )


@app.post(
    "/tasks/{list_name}/reorder",
    summary="Reorder Task",
    tags=["Tasks"],
    dependencies=[Depends(verify_api_key)],
)
async def reorder_task(
    list_name: str, reorder_input: ReorderRequest, user_id: str = "default_user"
):
    """
    [Requires API Key] Moves a task within or between parent tasks in a list.
    Specify `previous_sibling_id` to position the task after another task at the same level.
    Specify `parent_id` to move the task under a different parent (or to the top level if null).
    Moving to top: Omit both `previous_sibling_id` and `parent_id`.
    Moving under parent: Set `parent_id`. `previous_sibling_id` can refine position within subtasks.
    Moving within same level: Set `previous_sibling_id`. `parent_id` should match current parent or be omitted.
    """
    try:
        service = get_tasks_service(user_id)
        tasklist_id = find_task_list(service, list_name)
        if not tasklist_id:
            raise HTTPException(
                status_code=404, detail=f"Task list '{list_name}' not found."
            )

        # Parameters for the move API call
        move_params = {"tasklist": tasklist_id, "task": reorder_input.task_id}
        if reorder_input.previous_sibling_id:
            move_params["previous"] = reorder_input.previous_sibling_id
        if reorder_input.parent_id:
            move_params["parent"] = reorder_input.parent_id
            # If moving under a parent AND specifying previous, ensure previous is also under that parent (API might enforce this)

        # It seems Google Tasks API `move` method handles both parent change and sibling position.
        # If only `parent` is given, it moves to the end of that parent's subtasks.
        # If only `previous` is given, it moves after that sibling within the current parent.
        # If both are given, `parent` defines the level, `previous` defines position within it.
        # If neither is given, moves to the *very top* of the *entire list*.

        # Optional: Validate task_id, previous_sibling_id, parent_id exist? Adds overhead. Assume valid for now.

        moved_task = service.tasks().move(**move_params).execute()

        logger.info(
            f"User {user_id} reordered task ID {reorder_input.task_id} in list '{list_name}'."
        )
        return JSONResponse(
            content={"message": "Task reordered successfully.", "task": moved_task}
        )

    except HTTPException as e:
        raise e
    except HttpError as e:
        # Handle specific errors like 404 for task/list/parent/previous not found
        if e.resp.status == 404:
            # Try to parse the error message for more context if possible
            error_content = e.content.decode() if e.content else "{}"
            error_json = {}
            try:
                error_json = json.loads(error_content)
            except Exception:
                pass
            error_msg = error_json.get("error", {}).get(
                "message", "Resource not found."
            )
            logger.warning(
                f"API Error 404 reordering task {reorder_input.task_id}: {error_msg}"
            )
            raise HTTPException(
                status_code=404, detail=f"Failed to reorder task: {error_msg}"
            )
        elif (
            e.resp.status == 400
        ):  # Bad request, e.g., invalid parent/previous combination
            error_content = e.content.decode() if e.content else "{}"
            error_json = {}
            try:
                error_json = json.loads(error_content)
            except Exception:
                pass
            error_msg = error_json.get("error", {}).get("message", "Invalid request.")
            logger.warning(
                f"API Error 400 reordering task {reorder_input.task_id}: {error_msg}"
            )
            raise HTTPException(
                status_code=400, detail=f"Failed to reorder task: {error_msg}"
            )
        else:
            logger.error(
                f"API Error reordering task {reorder_input.task_id}: {e}", exc_info=True
            )
            raise HTTPException(
                status_code=e.resp.status,
                detail="Google API error reordering task.",
            )
    except Exception as e:
        logger.error(
            f"Unexpected error reordering task {reorder_input.task_id}: {e}",
            exc_info=True,
        )
        raise HTTPException(
            status_code=500, detail="Internal server error reordering task."
        )


@app.get(
    "/tasks/search/{query}",
    summary="Search Tasks Across All Lists",
    tags=["Tasks"],
    dependencies=[Depends(verify_api_key)],
)
async def search_tasks(
    query: str, user_id: str = "default_user", include_completed: bool = False
):
    """
    [Requires API Key] Searches for tasks containing the query string in their title across all accessible task lists.
    Search is case-insensitive. By default, ignores completed tasks unless `include_completed=true`.
    """
    if not query or len(query) < 2:  # Add minimum query length?
        raise HTTPException(
            status_code=400, detail="Search query must be at least 2 characters long."
        )

    results = []
    try:
        service = get_tasks_service(user_id)
        # 1. Get all task lists
        tasklists_response = service.tasklists().list().execute()
        tasklists = tasklists_response.get("items", [])
        if not tasklists:
            return JSONResponse(
                content={
                    "query": query,
                    "results": [],
                    "message": "No task lists found.",
                }
            )

        # 2. Iterate and search within each list (potentially parallelizable)
        search_query_lower = query.lower()
        for tasklist in tasklists:
            list_id = tasklist.get("id")
            list_title = tasklist.get("title", "Unknown List")
            if not list_id:
                continue

            logger.debug(f"Searching in list '{list_title}' (ID: {list_id})...")
            # Retrieve tasks from this list (handles pagination)
            tasks_in_list = retrieve_all_tasks(
                service,
                list_id,
                include_completed=include_completed,
                include_hidden=False,
            )

            for task in tasks_in_list:
                task_title = task.get("title", "")
                # Simple substring search (case-insensitive)
                if search_query_lower in task_title.lower():
                    results.append(
                        {
                            "list_name": list_title,
                            "list_id": list_id,
                            "task_id": task.get("id"),
                            "title": task_title,
                            "status": task.get("status"),
                            "due": task.get("due"),
                            "notes_snippet": (
                                task.get("notes", "")[:50] + "..."
                                if task.get("notes")
                                else None
                            ),  # Add snippet?
                        }
                    )

        logger.info(
            f"Search for '{query}' completed for user {user_id}. Found {len(results)} results."
        )
        return JSONResponse(
            content={"query": query, "results": results, "count": len(results)}
        )

    except HTTPException as e:
        raise e
    except HttpError as e:
        logger.error(
            f"API Error searching tasks for '{query}' for user {user_id}: {e}",
            exc_info=True,
        )
        raise HTTPException(
            status_code=e.resp.status if hasattr(e, "resp") else 500,
            detail="Google API error searching tasks.",
        )
    except Exception as e:
        logger.error(
            f"Unexpected error searching tasks for '{query}' for user {user_id}: {e}",
            exc_info=True,
        )
        raise HTTPException(
            status_code=500, detail="Internal server error searching tasks."
        )


# --- Calendar Events ---


@app.get(
    "/calendar/events",
    summary="List Calendar Events",
    tags=["Calendar"],
    dependencies=[Depends(verify_api_key)],
)
async def list_events(
    user_id: str = "default_user",
    max_results: int = 20,
    time_min: Optional[str] = None,  # ISO 8601 format. Default: Now
    time_max: Optional[str] = None,  # ISO 8601 format. Default: None (open-ended)
    query: Optional[str] = None,  # Text search query
    single_events: bool = True,  # Expand recurring events?
    order_by: str = "startTime",  # "startTime" or "updated"
):
    """
    [Requires API Key] Lists events from the primary Google Calendar within a specified time range.
    Allows filtering by query text and controlling sorting and recurrence expansion.
    Time inputs should be in ISO 8601 format (e.g., 'YYYY-MM-DDTHH:MM:SSZ' or with timezone offset).
    """
    try:
        service = get_calendar_service(user_id)

        # Set timeMin default to now if not provided, ensuring RFC3339 format
        time_min_rfc3339 = (
            parse_datetime_with_timezone(time_min, DEFAULT_TIMEZONE)
            if time_min
            else datetime.now(timezone.utc).isoformat(timespec="seconds")
        )
        time_max_rfc3339 = (
            parse_datetime_with_timezone(time_max, DEFAULT_TIMEZONE)
            if time_max
            else None
        )

        list_params = {
            "calendarId": "primary",
            "maxResults": min(
                max(1, max_results), 2500
            ),  # Clamp between 1 and Google's max (2500)
            "orderBy": (
                order_by if order_by in ["startTime", "updated"] else "startTime"
            ),
            "singleEvents": single_events,  # True expands recurring events into instances
            "timeMin": time_min_rfc3339,
            # "timeZone": DEFAULT_TIMEZONE # Explicitly set timezone for timeMin/timeMax interpretation? API default is UTC. Let's omit unless needed.
        }
        if time_max_rfc3339:
            list_params["timeMax"] = time_max_rfc3339
        if query:
            list_params["q"] = query

        logger.info(
            f"Fetching calendar events for user {user_id} with params: {list_params}"
        )

        events_result = service.events().list(**list_params).execute()
        events = events_result.get("items", [])

        # Optionally format events further if needed, but raw Google format is often useful
        # formatted_events = [...]

        logger.info(f"Found {len(events)} events for user {user_id}.")
        return JSONResponse(
            content={
                "events": events,  # Return Google's event structure directly
                "count": len(events),
                "query_parameters": list_params,  # Echo back parameters used
            }
        )

    except ValueError as ve:  # Catch validation errors from date parsing
        logger.warning(f"Validation error listing events: {ve}")
        raise HTTPException(status_code=400, detail=str(ve))
    except HTTPException as e:
        raise e
    except HttpError as e:
        logger.error(
            f"API Error listing calendar events for user {user_id}: {e}", exc_info=True
        )
        raise HTTPException(
            status_code=e.resp.status if hasattr(e, "resp") else 500,
            detail="Google API error listing events.",
        )
    except Exception as e:
        logger.error(
            f"Unexpected error listing calendar events for user {user_id}: {e}",
            exc_info=True,
        )
        raise HTTPException(
            status_code=500, detail="Internal server error listing events."
        )


# Convenience endpoints for common time ranges
@app.get(
    "/calendar/events/today",
    summary="List Today's Calendar Events",
    tags=["Calendar"],
    dependencies=[Depends(verify_api_key)],
)
async def list_today_events(user_id: str = "default_user"):
    """
    [Requires API Key] Gets all calendar events for today (midnight to midnight)
    in the server's configured DEFAULT_TIMEZONE.
    """
    try:
        # Use the configured timezone
        try:
            tz = ZoneInfo(DEFAULT_TIMEZONE)
        except Exception:
            logger.warning(
                f"Invalid DEFAULT_TIMEZONE '{DEFAULT_TIMEZONE}', falling back to UTC for 'today' calculation."
            )
            tz = ZoneInfo("UTC")

        now_local = datetime.now(tz)
        start_local = now_local.replace(hour=0, minute=0, second=0, microsecond=0)
        end_local = start_local + timedelta(days=1)

        # Convert to RFC3339 for the API call
        time_min_iso = start_local.isoformat(timespec="seconds")
        time_max_iso = end_local.isoformat(timespec="seconds")

        logger.info(
            f"Fetching today's events for user {user_id} (Timezone: {DEFAULT_TIMEZONE}, Range: {time_min_iso} to {time_max_iso})"
        )
        # Use the main list_events endpoint logic by calling it internally
        # Need `await` if calling an async function from another async function
        return await list_events(
            user_id=user_id,
            time_min=time_min_iso,
            time_max=time_max_iso,
            max_results=100,  # Sensible limit for a day
            single_events=True,
            order_by="startTime",
        )
    except Exception as e:
        logger.error(
            f"❌ Error fetching today's events for user {user_id}: {str(e)}",
            exc_info=True,
        )
        # Avoid raising the raw exception from list_events, wrap it
        if isinstance(e, HTTPException):
            raise e  # Re-raise FastAPI/HTTP exceptions directly
        else:
            raise HTTPException(
                status_code=500,
                detail="Internal server error fetching today's events.",
            )


@app.get(
    "/calendar/events/week",
    summary="List Next 7 Days' Calendar Events",
    tags=["Calendar"],
    dependencies=[Depends(verify_api_key)],
)
async def list_week_events(user_id: str = "default_user"):
    """
    [Requires API Key] Gets all calendar events starting from today (midnight)
    for the next 7 days, based on the server's configured DEFAULT_TIMEZONE.
    """
    try:
        # Use the configured timezone
        try:
            tz = ZoneInfo(DEFAULT_TIMEZONE)
        except Exception:
            logger.warning(
                f"Invalid DEFAULT_TIMEZONE '{DEFAULT_TIMEZONE}', falling back to UTC for 'week' calculation."
            )
            tz = ZoneInfo("UTC")

        now_local = datetime.now(tz)
        start_local = now_local.replace(hour=0, minute=0, second=0, microsecond=0)
        end_local = start_local + timedelta(days=7)

        # Convert to RFC3339 for the API call
        time_min_iso = start_local.isoformat(timespec="seconds")
        time_max_iso = end_local.isoformat(timespec="seconds")

        logger.info(
            f"Fetching next 7 days' events for user {user_id} (Timezone: {DEFAULT_TIMEZONE}, Range: {time_min_iso} to {time_max_iso})"
        )
        return await list_events(
            user_id=user_id,
            time_min=time_min_iso,
            time_max=time_max_iso,
            max_results=250,  # Higher limit for a week
            single_events=True,
            order_by="startTime",
        )
    except Exception as e:
        logger.error(
            f"❌ Error fetching week's events for user {user_id}: {str(e)}",
            exc_info=True,
        )
        if isinstance(e, HTTPException):
            raise e
        else:
            raise HTTPException(
                status_code=500,
                detail="Internal server error fetching week's events.",
            )


@app.get(
    "/calendar/events/{event_id}",
    summary="Get Specific Calendar Event",
    tags=["Calendar"],
    dependencies=[Depends(verify_api_key)],
)
async def get_event(event_id: str, user_id: str = "default_user"):
    """
    [Requires API Key] Retrieves detailed information about a specific event
    from the primary calendar using its Event ID.
    """
    try:
        service = get_calendar_service(user_id)
        event = service.events().get(calendarId="primary", eventId=event_id).execute()
        return JSONResponse(content={"event": event})  # Return full event details

    except HttpError as e:
        if e.resp.status == 404:
            logger.warning(f"Event ID '{event_id}' not found for user {user_id}.")
            raise HTTPException(
                status_code=404, detail=f"Event ID '{event_id}' not found."
            )
        else:
            logger.error(
                f"API Error getting event {event_id} for user {user_id}: {e}",
                exc_info=True,
            )
            raise HTTPException(
                status_code=e.resp.status if hasattr(e, "resp") else 500,
                detail="Google API error getting event.",
            )
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(
            f"Unexpected error getting event {event_id} for user {user_id}: {e}",
            exc_info=True,
        )
        raise HTTPException(
            status_code=500, detail="Internal server error getting event."
        )


@app.post(
    "/calendar/events",
    summary="Add Calendar Event",
    status_code=201,
    tags=["Calendar"],
    dependencies=[Depends(verify_api_key)],
)
async def add_event(event_input: EventInput, user_id: str = "default_user"):
    """
    [Requires API Key] Adds a new event to the primary Google Calendar.
    Handles basic event details, timezone conversion, attendees, recurrence, and optional Meet link creation.
    Times are interpreted based on the provided timezone string or the server's DEFAULT_TIMEZONE.
    """
    try:
        service = get_calendar_service(user_id)
        event_body = (
            event_input.get_google_api_body()
        )  # Pydantic model handles formatting and validation

        insert_params = {"calendarId": "primary", "body": event_body}
        # Add conferenceDataVersion=1 if requesting a Meet link
        if event_input.create_meet_link:
            insert_params["conferenceDataVersion"] = 1
            # Optional: Send notifications to attendees?
            # insert_params['sendNotifications'] = True

        new_event = service.events().insert(**insert_params).execute()

        # Extract key info for response
        created_start = new_event.get("start", {}).get("dateTime")
        created_end = new_event.get("end", {}).get("dateTime")
        created_tz = new_event.get("start", {}).get("timeZone", DEFAULT_TIMEZONE)
        conference_link = None
        if "conferenceData" in new_event:
            for entry in new_event["conferenceData"].get("entryPoints", []):
                if entry.get("entryPointType") == "video":
                    conference_link = entry.get("uri")
                    break

        logger.info(
            f"User {user_id} created event '{new_event.get('summary')}' "
            f"(ID: {new_event.get('id')}) "
            f"Time: {created_start} to {created_end} ({created_tz})"
            f"{f' Meet: {conference_link}' if conference_link else ''}"
        )

        return JSONResponse(
            status_code=201,
            content={
                "message": f"Event '{new_event.get('summary')}' created successfully.",
                "event_id": new_event.get("id"),
                "event_link": new_event.get(
                    "htmlLink"
                ),  # Link to view in Google Calendar UI
                "start_time": created_start,
                "end_time": created_end,
                "timezone": created_tz,
                "conference_link": conference_link,
                "event_details": new_event,  # Return full event object
            },
        )

    except ValueError as ve:  # Catch validation errors from model/helpers
        logger.warning(f"Validation error adding event: {ve}")
        raise HTTPException(status_code=400, detail=str(ve))
    except HTTPException as e:
        raise e
    except HttpError as e:
        logger.error(
            f"API Error adding calendar event for user {user_id}: {e}", exc_info=True
        )
        raise HTTPException(
            status_code=e.resp.status if hasattr(e, "resp") else 500,
            detail="Google API error adding event.",
        )
    except Exception as e:
        logger.error(
            f"Unexpected error adding calendar event for user {user_id}: {e}",
            exc_info=True,
        )
        raise HTTPException(
            status_code=500, detail="Internal server error adding event."
        )


@app.patch(
    "/calendar/events/{event_id}",
    summary="Update Calendar Event",
    tags=["Calendar"],
    dependencies=[Depends(verify_api_key)],
)
async def update_event(
    event_id: str, update_data: EventUpdate, user_id: str = "default_user"
):
    """
    [Requires API Key] Updates an existing event on the primary calendar using PATCH.
    Only provided fields are modified. To clear optional fields like description or location,
    provide them as empty strings or null (model handles empty strings).
    """
    if not update_data.has_updates:
        raise HTTPException(status_code=400, detail="No update data provided.")

    try:
        service = get_calendar_service(user_id)

        # Get current event to apply patch logic if helper needs it (googleapiclient should handle PATCH well)
        try:
            current_event = (
                service.events().get(calendarId="primary", eventId=event_id).execute()
            )
        except HttpError as e:
            if e.resp.status == 404:
                raise HTTPException(
                    status_code=404, detail=f"Event ID '{event_id}' not found."
                )
            else:
                raise

        # Prepare PATCH body
        patch_body = update_data.get_google_api_body(
            current_event
        )  # Pass current event for context

        # Update the event using PATCH
        updated_event = (
            service.events()
            .patch(
                calendarId="primary",
                eventId=event_id,
                body=patch_body,
                # conferenceDataVersion=1 if updating conference data? Check API docs. Usually needed on insert.
                # sendNotifications=True/False ?
            )
            .execute()
        )

        logger.info(f"User {user_id} updated event ID {event_id}.")
        return JSONResponse(
            content={
                "message": "Event updated successfully.",
                "event": updated_event,  # Return updated event object
            }
        )

    except ValueError as ve:  # Catch validation errors
        logger.warning(f"Validation error updating event {event_id}: {ve}")
        raise HTTPException(status_code=400, detail=str(ve))
    except HTTPException as e:
        raise e
    except HttpError as e:
        logger.error(
            f"API Error updating event {event_id} for user {user_id}: {e}",
            exc_info=True,
        )
        raise HTTPException(
            status_code=e.resp.status if hasattr(e, "resp") else 500,
            detail="Google API error updating event.",
        )
    except Exception as e:
        logger.error(
            f"Unexpected error updating event {event_id} for user {user_id}: {e}",
            exc_info=True,
        )
        raise HTTPException(
            status_code=500, detail="Internal server error updating event."
        )


@app.delete(
    "/calendar/events/{event_id}",
    summary="Delete Calendar Event",
    tags=["Calendar"],
    dependencies=[Depends(verify_api_key)],
)
async def delete_event(
    event_id: str, user_id: str = "default_user", send_notifications: bool = False
):
    """
    [Requires API Key] Deletes an event from the primary calendar.
    Use `send_notifications=true` query param to notify attendees.
    """
    try:
        service = get_calendar_service(user_id)

        # Delete the event
        service.events().delete(
            calendarId="primary", eventId=event_id, sendNotifications=send_notifications
        ).execute()

        logger.info(
            f"User {user_id} deleted event ID {event_id} from calendar (Notifications: {send_notifications})."
        )
        # No body on successful DELETE
        return JSONResponse(
            status_code=200,
            content={"message": f"Event '{event_id}' deleted successfully."},
        )
        # return Response(status_code=204) # Alternative: 204 No Content

    except HttpError as e:
        if e.resp.status == 404:
            logger.warning(
                f"Event ID '{event_id}' not found during delete attempt (might be already deleted)."
            )
            raise HTTPException(
                status_code=404, detail=f"Event ID '{event_id}' not found."
            )
        # Handle 410 Gone specifically? Sometimes used for deleted recurring instances
        elif e.resp.status == 410:
            logger.warning(f"Event ID '{event_id}' is gone (likely deleted).")
            raise HTTPException(
                status_code=410, detail=f"Event ID '{event_id}' is gone."
            )
        else:
            logger.error(
                f"API Error deleting event {event_id} for user {user_id}: {e}",
                exc_info=True,
            )
            raise HTTPException(
                status_code=e.resp.status if hasattr(e, "resp") else 500,
                detail="Google API error deleting event.",
            )
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(
            f"Unexpected error deleting event {event_id} for user {user_id}: {e}",
            exc_info=True,
        )
        raise HTTPException(
            status_code=500, detail="Internal server error deleting event."
        )


# ------------------------------------------------------------------
# OpenAI Plugin Manifest (Example)
# ------------------------------------------------------------------
@app.get("/.well-known/ai-plugin.json", include_in_schema=False)
async def get_plugin_manifest():
    """Serves the AI Plugin manifest JSON file."""
    # Replace with your actual API URL base AFTER deployment
    api_base_url = os.getenv(
        "API_BASE_URL", f"http://localhost:{PORT}"
    )  # Get from env or default to localhost

    return {
        "schema_version": "v1",
        "name_for_human": "Google Tasks & Calendar",  # User-facing name
        "name_for_model": "GoogleTasksCalendarManager",  # Model-facing name (alphanumeric)
        "description_for_human": "Manage your Google Tasks and Calendar. Add tasks with subtasks, schedule events with meeting links, list upcoming items, and more.",
        "description_for_model": "Plugin for managing Google Tasks (add, list, update, delete, toggle completion, search) and Google Calendar events (add, list, update, delete, get details). Handles tasks with subtasks, events with attendees, recurrence, and Google Meet links. Uses OAuth2 for authentication, which must be initiated via the /auth endpoint if credentials are not present or invalid.",
        "auth": {
            # If using API Key for plugin auth AND OAuth for Google:
            # Matches verify_api_key, which reads the key from the X-API-Key header
            "type": "service_http",
            "authorization_type": "custom",
            "custom_auth_header": "X-API-Key",
            "verification_tokens": {
                # Replace with your actual verification token if required by the LLM provider (e.g., OpenAI)
                "openai": os.getenv(
                    "OPENAI_PLUGIN_VERIFICATION_TOKEN",
                    "dummy_verification_token_replace_me",
                )
            },
            # If relying SOLELY on OAuth (requires LLM to handle redirect flow):
            # "type": "oauth",
            # "client_url": f"{api_base_url}/auth", # Endpoint to start flow
            # "scope": " ".join(SCOPES), # Scopes needed by the plugin
            # "authorization_url": "https://accounts.google.com/o/oauth2/auth", # Standard Google Auth URL
            # "authorization_content_type": "application/json", # Usually correct
            # "verification_tokens": { ... }
            # --- OR --- if no plugin-level auth, just Google OAuth handled by backend:
            # "type": "none" # BUT you need to ensure /auth flow is triggered when needed. The model needs hints.
        },
        "api": {
            "type": "openapi",
            # Use relative URL or dynamically generated absolute URL
            "url": f"{api_base_url}/openapi.json",  # Point to your generated OpenAPI spec
            "is_user_authenticated": False,  # Set to false - auth handled by API key or OAuth flow described above
        },
        "logo_url": f"{api_base_url}/logo.png",  # Serve a logo image at /logo.png
        "contact_email": "support@example.com",  # Replace with your support email
        "legal_info_url": "http://www.example.com/legal",  # Replace with your legal info URL
    }


@app.get("/openapi.json", include_in_schema=False)
async def get_openapi_spec():
    """Serves the OpenAPI schema generated by FastAPI."""
    # FastAPI automatically generates this based on routes and models
    # Ensure Pydantic models and route docstrings are descriptive for the LLM
    from fastapi.openapi.utils import get_openapi

    return JSONResponse(
        get_openapi(
            title=app.title,
            version=app.version,
            openapi_version=app.openapi_version,
            description=app.description,
            routes=app.routes,
            # Include servers if needed, potentially dynamic based on request
            # servers=[{"url": os.getenv("API_BASE_URL", f"http://localhost:{PORT}")}]
        )
    )


# Serve a placeholder logo (replace with your actual logo file)
@app.get("/logo.png", include_in_schema=False)
async def plugin_logo():
    from fastapi.responses import FileResponse

    # Create a dummy logo.png or provide path to your actual logo
    logo_path = "logo.png"  # Assumes logo.png is in the same directory
    if not os.path.exists(logo_path):
        # Create a tiny dummy png if it doesn't exist
        try:
            from PIL import Image

            img = Image.new("RGB", (60, 30), color="red")
            img.save(logo_path)
            logger.info("Created dummy logo.png")
        except ImportError:
            logger.warning(
                "Pillow not installed, cannot create dummy logo.png. Please provide a logo.png file."
            )
            raise HTTPException(status_code=404, detail="logo.png not found.")
        except Exception as e:
            logger.error(f"Failed to create dummy logo: {e}")
            raise HTTPException(status_code=500, detail="Failed to create logo file.")

    return FileResponse(logo_path, media_type="image/png")


# ------------------------------------------------------------------
# Run the app (for local development)
# ------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn

    logger.info(f"Starting FastAPI application on http://0.0.0.0:{PORT}")
    logger.info(f"Default Timezone configured: {DEFAULT_TIMEZONE}")
    logger.info(f"Database path: {os.path.abspath(DB_PATH)}")
    logger.info(f"OAuth Redirect URI: {REDIRECT_URI}")
    uvicorn.run(app, host="0.0.0.0", port=int(PORT))
