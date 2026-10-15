# AI Persistent Memory API with Google Integration

This project demonstrates a backend system designed to provide an AI assistant (like a **Custom GPT**) with both persistent memory capabilities and integration with Google Tasks and Google Calendar.

It consists of two main components:

1.  **Persistent Memory API (Cloudflare Worker):** A serverless API built using Cloudflare Workers and KV Store (`cloudflare.js`) to handle storing, retrieving, updating, deleting, and summarizing memories associated with a user ID. This API is called by the Custom GPT to give it long-term memory.
2.  **Google Integration API (FastAPI):** A Python backend application built with FastAPI (`api_with_persistent_memory.py`), **deployed on Render.com in this example**, that securely connects to Google Tasks and Google Calendar APIs using OAuth 2.0. This allows the Custom GPT to manage the user's tasks and events via API calls.

## Architecture

+-----------------+      +-----------------------------+      +----------------------+|   Custom GPT    |----->|  Memory API (CF Worker)     |<---->| Cloudflare KV Store  ||                 |      |  (/store, /retrieve, etc.)  |      | (User Memories)      |+-----------------+      +-----------------------------+      +----------------------+|| Calls based on user request|+-----------------------------+      +----------------------+      +----------------------+|  Google API (FastAPI App)   |<---->| Google Tasks API     |      | Google Calendar API  ||  (Deployed on Render.com)   |      +----------------------+      +----------------------+|  (/tasks, /calendar, /auth) |+-----------------------------+| Uses+----------------------+| SQLite DB            || (Google OAuth Tokens)|+----------------------+
* The Custom GPT interacts with both APIs based on the user's conversational requests.
* The Memory API uses Cloudflare KV for storing user-specific memories.
* The Google Integration API (hosted on Render) handles the OAuth 2.0 flow with Google, stores tokens securely (in an SQLite DB), and proxies requests to the actual Google services.

## Key Features

**Memory API (Cloudflare Worker - `cloudflare.js`)**

* Stores memories with categories, priorities, and tags.
* Retrieves memories by category or all memories for a user.
* Supports filtering (by tag, search term) and sorting (by timestamp, priority, etc.).
* Updates and deletes specific memory items using unique IDs.
* Deletes entire categories or all user data.
* Integrates with OpenAI API for AI-powered summarization (`/retrieve-memory-summary`).
* Includes placeholders for future features like semantic search and action triggering.
* Uses Cloudflare KV for data persistence.
* Requires `Authorization: Bearer <MEMORY_API_KEY>` on every request (single-tenant: the one key grants access to all `user_id` values).
* API contract defined in `memory_api_openapi.json`.

**Google Integration API (FastAPI - `api_with_persistent_memory.py`)**

* Handles Google OAuth 2.0 authentication flow (`/auth`, `/callback`). Start it by opening `/auth?key=<API_KEY>` in a browser; only Google accounts listed in `ALLOWED_GOOGLE_EMAILS` can complete it.
* Securely stores and refreshes Google API tokens using an SQLite database.
* Provides endpoints to manage Google Tasks:
    * List task lists (`/tasklists`).
    * Create task lists (`/tasklists`).
    * List tasks hierarchically (`/tasks/{list_name}`).
    * Add tasks with optional subtasks (`/tasks/add`).
    * Update tasks (title, notes, due, status) (`/tasks/{list_name}/{task_id}`).
    * Toggle task completion (`/tasks/{list_name}/{task_id}/toggle`).
    * Delete tasks (`/tasks/{list_name}/{task_id}`).
    * Batch delete tasks (`/tasks/{list_name}/batch-delete`).
    * Reorder tasks (`/tasks/{list_name}/reorder`).
    * Search tasks across lists (`/tasks/search/{query}`).
* Provides endpoints to manage Google Calendar:
    * List events with filtering (`/calendar/events`, `/calendar/events/today`, `/calendar/events/week`).
    * Add events with attendees, recurrence, and optional Meet links (`/calendar/events`).
    * Get specific event details (`/calendar/events/{event_id}`).
    * Update events (`/calendar/events/{event_id}`).
    * Delete events (`/calendar/events/{event_id}`).
* Secures API endpoints with an `X-API-Key` header.
* Generates OpenAPI documentation (`/openapi.json`).
* Includes endpoints for potential AI Plugin integration (`/.well-known/ai-plugin.json`, `/logo.png`).
* API contract (actions used by the example Custom GPT) defined in `google_actions_openapi.json`.

## Code Files

* **`api_with_persistent_memory.py`:** The main Python code for the FastAPI application handling Google API interactions and OAuth.
* **`cloudflare.js`:** The main JavaScript code for the Cloudflare Worker handling the persistent memory API via KV.
* **`requirements.txt`:** Python dependencies for the FastAPI application.
* **`memory_api_openapi.json`:** OpenAPI specification defining the Memory API (Cloudflare Worker).
* **`google_actions_openapi.json`:** OpenAPI specification defining the Google Integration API (FastAPI).
* **`.env.example`:** Template for environment variables needed by the FastAPI application.
* **`wrangler.toml.example`:** Template for Cloudflare Worker configuration.
* **`.gitignore`:** Specifies intentionally untracked files for Git.
* **`package.json` / `eslint.config.js` / `.prettierrc.json`:** Configuration for Node.js tooling (ESLint, Prettier) used during development of the Cloudflare Worker.

## Configuration

This project requires external configuration to run:

**1. FastAPI Google Integration App (`api_with_persistent_memory.py`)**

* Requires environment variables defined in `.env.example`. Create a `.env` file based on the example and provide:
    * Google Cloud Console credentials (`GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`).
    * Authorized Redirect URI (`REDIRECT_URI`) matching the Google credentials and your deployment URL (e.g., your Render service URL + `/callback`).
    * A secret `API_KEY` for securing the FastAPI endpoints (also required as `?key=` to start `/auth`).
    * `ALLOWED_GOOGLE_EMAILS`: comma-separated Google account emails allowed to link via OAuth. Required; if unset, all sign-ins are rejected.
    * A secret `SESSION_SECRET` for session management.
    * Database path (`DB_PATH`), timezone (`DEFAULT_TIMEZONE`), server port (`PORT`), allowed CORS origins (`ALLOWED_ORIGINS`).
    * Optional: `API_BASE_URL` (your Render service URL) and `OPENAI_PLUGIN_VERIFICATION_TOKEN` for AI plugin features.

**2. Cloudflare Worker Memory API (`cloudflare.js`)**

* Requires configuration via `wrangler.toml` (based on `wrangler.toml.example`):
    * A unique `name` for the worker.
    * A Cloudflare KV Namespace binding named `MEMORY_KV`. You must create this namespace in the Cloudflare dashboard and add its ID to `wrangler.toml`.
* Requires Secrets configured in Cloudflare (via dashboard or `wrangler secret put`):
    * `MEMORY_API_KEY` (required): `npx wrangler secret put MEMORY_API_KEY`. Clients must send `Authorization: Bearer <MEMORY_API_KEY>`; requests are rejected with 401 if it is wrong and 503 if the secret is not set. Configure it in your Custom GPT Action as API Key auth of type Bearer. This one key grants access to every `user_id`, so treat the deployment as single-tenant.
    * `OPENAI_API_KEY`: Needed for the summarization endpoint.
* Optional `ALLOWED_ORIGIN` var (`[vars]` in `wrangler.toml`): the one browser origin allowed by CORS. If unset, no `Access-Control-Allow-Origin` header is sent (server-to-server callers like Custom GPT Actions are unaffected).

## Running (Conceptual)

* **FastAPI App:** Typically run using an ASGI server like Uvicorn locally (`uvicorn api_with_persistent_memory:app --reload --port 10000` after setting up `.env` and installing requirements). For public access (as used by the Custom GPT), requires deployment to a hosting service like **Render.com**.
* **Cloudflare Worker:** Deployed using the Wrangler CLI: `npx wrangler deploy` (after configuring `wrangler.toml` and secrets).

*(Disclaimer: This is a showcase repository demonstrating the integration pattern. Specific deployment steps may vary.)*

