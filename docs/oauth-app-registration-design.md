# OAuth App Registration for Plane CE

## Problem

Self-hosted Plane CE instances have no OAuth server capability. Users who want
to integrate third-party tools (MCP servers, CI/CD, custom apps) must share a
single API key. This is insecure for multi-user teams and blocks the official
Plane MCP server's per-user OAuth flow entirely.

Plane Cloud has these endpoints but they're not in the open-source codebase:
- `/auth/o/authorize-app/`
- `/auth/o/token/`
- `/auth/o/app-installation/`

Reference: https://github.com/makeplane/plane/issues/8782

## Design Goals

1. RFC 6749 compliant OAuth 2.0 Authorization Code flow
2. Compatible with Plane Cloud's MCP server expectations
3. Admin-managed app registration (not self-service initially)
4. Workspace-scoped tokens (an app installation is per-workspace)
5. No breaking changes to existing auth or API key flows

## Data Model

### OAuthApp (new model in `plane/db/models/`)

```python
class OAuthApp(BaseModel):
    """Registered OAuth application."""
    name = CharField(max_length=255)
    description = TextField(blank=True)
    client_id = CharField(max_length=64, unique=True, db_index=True)
    client_secret = CharField(max_length=128)  # hashed
    redirect_uris = JSONField(default=list)  # list of allowed redirect URIs
    homepage_url = URLField(blank=True)
    logo_url = URLField(blank=True)
    is_active = BooleanField(default=True)
    created_by = ForeignKey(User)

    # Scopes this app can request
    allowed_scopes = JSONField(default=list)
    # e.g., ["read:projects", "write:issues", "read:pages"]
```

### OAuthAppInstallation (workspace-level)

```python
class OAuthAppInstallation(BaseModel):
    """An OAuth app installed in a workspace."""
    app = ForeignKey(OAuthApp)
    workspace = ForeignKey(Workspace)
    installed_by = ForeignKey(User)
    is_active = BooleanField(default=True)
    metadata = JSONField(default=dict)
```

### OAuthAuthorizationCode (temporary, short-lived)

```python
class OAuthAuthorizationCode(BaseModel):
    """Temporary auth code for OAuth code exchange."""
    code = CharField(max_length=128, unique=True)
    app = ForeignKey(OAuthApp)
    user = ForeignKey(User)
    workspace = ForeignKey(Workspace)
    redirect_uri = TextField()
    scopes = JSONField(default=list)
    code_challenge = CharField(max_length=128, blank=True)  # PKCE
    code_challenge_method = CharField(max_length=10, blank=True)  # S256
    expires_at = DateTimeField()
    used = BooleanField(default=False)
```

### OAuthAccessToken

```python
class OAuthAccessToken(BaseModel):
    """Long-lived access token issued to an app for a user."""
    token = CharField(max_length=128, unique=True, db_index=True)
    app = ForeignKey(OAuthApp)
    user = ForeignKey(User)
    workspace = ForeignKey(Workspace)
    scopes = JSONField(default=list)
    expires_at = DateTimeField()
    is_revoked = BooleanField(default=False)
```

### OAuthRefreshToken

```python
class OAuthRefreshToken(BaseModel):
    """Refresh token for obtaining new access tokens."""
    token = CharField(max_length=128, unique=True, db_index=True)
    access_token = OneToOneField(OAuthAccessToken)
    expires_at = DateTimeField(null=True)  # null = never expires
    is_revoked = BooleanField(default=False)
```

## API Endpoints

### App Management (Admin API)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/instances/oauth-apps/` | Register new OAuth app |
| GET | `/api/instances/oauth-apps/` | List registered apps |
| GET | `/api/instances/oauth-apps/<id>/` | Get app details |
| PATCH | `/api/instances/oauth-apps/<id>/` | Update app config |
| DELETE | `/api/instances/oauth-apps/<id>/` | Delete app |

Permission: InstanceAdminPermission (God Mode only)

### OAuth Flow (Public API)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/auth/o/authorize-app/` | Authorization page (shows consent screen) |
| POST | `/auth/o/authorize-app/` | User approves/denies authorization |
| POST | `/auth/o/token/` | Exchange auth code for access token |
| POST | `/auth/o/token/revoke/` | Revoke a token |

### App Installation (Workspace API)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/auth/o/app-installation/` | Install app in workspace |
| GET | `/api/workspaces/<slug>/oauth-apps/` | List installed apps |
| DELETE | `/api/workspaces/<slug>/oauth-apps/<id>/` | Uninstall app |

## OAuth Flow

```
1. App redirects user to:
   GET /auth/o/authorize-app/?
     client_id=xxx&
     redirect_uri=xxx&
     response_type=code&
     scope=read:projects write:issues&
     state=xxx&
     code_challenge=xxx&          # PKCE (optional)
     code_challenge_method=S256

2. User sees consent screen (if not already authorized)
   - App name, description, logo
   - Requested scopes
   - Workspace selection
   - Approve / Deny buttons

3. On approve:
   - Create OAuthAuthorizationCode (10 min TTL)
   - Redirect to: redirect_uri?code=xxx&state=xxx

4. App exchanges code for token:
   POST /auth/o/token/
   {
     grant_type: "authorization_code",
     client_id: "xxx",
     client_secret: "xxx",
     code: "xxx",
     redirect_uri: "xxx",
     code_verifier: "xxx"  # PKCE
   }

   Response:
   {
     access_token: "plane_oauth_xxx",
     token_type: "Bearer",
     expires_in: 86400,
     refresh_token: "plane_rt_xxx",
     scope: "read:projects write:issues"
   }

5. App uses token:
   GET /api/v1/workspaces/xxx/projects/
   Authorization: Bearer plane_oauth_xxx

6. Token refresh:
   POST /auth/o/token/
   {
     grant_type: "refresh_token",
     client_id: "xxx",
     refresh_token: "plane_rt_xxx"
   }
```

## Scope Model

Initial scopes (can be expanded):
- `read:projects` — list/view projects
- `write:projects` — create/update projects
- `read:issues` — list/view work items
- `write:issues` — create/update/delete work items
- `read:pages` — list/view pages
- `write:pages` — create/update pages
- `read:cycles` — list/view cycles
- `write:cycles` — create/update cycles
- `read:modules` — list/view modules
- `write:modules` — create/update modules
- `read:members` — list workspace/project members
- `admin` — full access (implies all scopes)

## Authentication Middleware

New `OAuthTokenAuthentication` class:
- Reads `Authorization: Bearer plane_oauth_xxx` header
- Validates token against OAuthAccessToken model
- Checks expiry, revocation, scope
- Sets `request.user` and `request.auth` (with scope info)
- Coexists with existing APIKeyAuthentication and SessionAuthentication

## Admin UI

### New page: Settings > OAuth Apps (God Mode admin)

**Route:** `/oauth-apps/`

**List view:**
- Table: Name, Client ID (truncated), Created, Status
- "Register new app" button

**Registration form:**
- App name (required)
- Description
- Homepage URL
- Redirect URIs (multi-value input)
- Allowed scopes (checkboxes)
- Submit → generates client_id + client_secret (shown once)

**Detail view:**
- Edit name, description, redirect URIs, scopes
- Regenerate client secret
- Delete app
- View installations (which workspaces have installed this app)

### Sidebar addition

Add "OAuth Apps" menu item below "Authentication" in the admin sidebar.

## Implementation Plan

### Phase 1: Backend models + management endpoints
- Create OAuthApp, OAuthAppInstallation models
- Create Django migration
- Create admin CRUD endpoints for OAuthApp
- Add to admin URL routing

### Phase 2: OAuth flow endpoints
- Create authorization endpoint (consent page)
- Create token endpoint (code exchange)
- Create OAuthAuthorizationCode, OAuthAccessToken, OAuthRefreshToken models
- Implement PKCE support
- Create token revocation endpoint

### Phase 3: Token authentication middleware
- Create OAuthTokenAuthentication class
- Register in DRF authentication backends
- Add scope checking to API views

### Phase 4: Admin UI
- Create OAuth Apps admin page (list + CRUD)
- Create app registration form with secret display
- Add sidebar menu item

### Phase 5: Consent screen
- Create authorization consent page (server-rendered or SPA)
- Handle workspace selection
- Handle scope display and approval

## Security Considerations

- Client secrets are hashed (bcrypt) in the database, never stored in plaintext
- Authorization codes are single-use and expire in 10 minutes
- Access tokens expire in 24 hours by default
- PKCE support (S256) for public clients
- Redirect URI validation: exact match against registered URIs
- Rate limiting on token endpoint
- Scope downscoping: token can only have scopes the app is allowed + user approved
- Token prefix (`plane_oauth_`) makes tokens easily identifiable in logs

## Compatibility with Plane Cloud

The endpoints match what the official Plane MCP server expects:
- `/auth/o/authorize-app/` → our authorization endpoint
- `/auth/o/token/` → our token endpoint
- `/auth/o/app-installation/` → our installation endpoint

This ensures the official MCP server works against CE without modification.
