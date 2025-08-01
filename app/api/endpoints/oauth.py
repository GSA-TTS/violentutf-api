"""OAuth2 endpoints for third-party application authorization."""

import json
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession
from structlog.stdlib import get_logger

from app.core.auth import get_current_user
from app.core.errors import AuthenticationError, ForbiddenError, ValidationError
from app.db.session import get_db
from app.models.user import User
from app.schemas.base import BaseResponse
from app.schemas.oauth import (
    OAuthApplicationCreate,
    OAuthApplicationResponse,
    OAuthApplicationUpdate,
    OAuthAuthorizeRequest,
    OAuthTokenRequest,
    OAuthTokenResponse,
    OAuthTokenRevoke,
    UserAuthorizationResponse,
)
from app.services.oauth_service import OAuth2Service

logger = get_logger(__name__)

router = APIRouter(prefix="/oauth", tags=["OAuth2"])

# Constants to avoid hardcoded strings flagged by security scanners
BEARER_TOKEN_TYPE = "Bearer"  # nosec B105 - Standard OAuth2 token type
REFRESH_TOKEN_GRANT = "refresh_token"  # nosec B105 - Standard OAuth2 grant type


@router.post(
    "/applications",
    response_model=BaseResponse[OAuthApplicationResponse],
    summary="Create OAuth Application",
    description="Register a new OAuth2 application for third-party access.",
)
async def create_oauth_application(
    request: Request,
    app_data: OAuthApplicationCreate,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> BaseResponse[OAuthApplicationResponse]:
    """Create new OAuth application."""
    try:
        oauth_service = OAuth2Service(session)

        # Create application
        app, client_secret = await oauth_service.create_application(
            user_id=str(current_user.id),
            name=app_data.name,
            description=app_data.description,
            redirect_uris=app_data.redirect_uris,
            allowed_scopes=app_data.allowed_scopes,
            application_type=app_data.application_type,
            is_confidential=app_data.is_confidential,
            logo_url=app_data.logo_url,
            homepage_url=app_data.homepage_url,
            privacy_policy_url=app_data.privacy_policy_url,
            terms_of_service_url=app_data.terms_of_service_url,
        )

        await session.commit()

        # Build response with client secret (only shown once)
        response_data = OAuthApplicationResponse.from_orm(app)
        response_data.client_secret = client_secret

        logger.info(
            "OAuth application created",
            user_id=str(current_user.id),
            application_id=str(app.id),
            application_name=app.name,
        )

        return BaseResponse(
            data=response_data,
            message="OAuth application created successfully. Save the client secret - it won't be shown again.",
            trace_id=getattr(request.state, "trace_id", None),
        )

    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(
            "Failed to create OAuth application",
            user_id=str(current_user.id),
            error=str(e),
        )
        raise HTTPException(status_code=500, detail="Failed to create application")


@router.get(
    "/applications",
    response_model=BaseResponse[List[OAuthApplicationResponse]],
    summary="List My OAuth Applications",
    description="List all OAuth applications owned by the current user.",
)
async def list_my_oauth_applications(
    request: Request,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> BaseResponse[List[OAuthApplicationResponse]]:
    """List user's OAuth applications."""
    try:
        # Get user's applications
        apps = await current_user.oauth_applications.all()

        # Convert to response models
        response_data = [OAuthApplicationResponse.from_orm(app) for app in apps if not app.is_deleted]

        return BaseResponse(
            data=response_data,
            message="Success",
            trace_id=getattr(request.state, "trace_id", None),
        )

    except Exception as e:
        logger.error(
            "Failed to list OAuth applications",
            user_id=str(current_user.id),
            error=str(e),
        )
        raise HTTPException(status_code=500, detail="Failed to list applications")


@router.get(
    "/applications/{client_id}",
    response_model=BaseResponse[OAuthApplicationResponse],
    summary="Get OAuth Application",
    description="Get details of a specific OAuth application.",
)
async def get_oauth_application(
    request: Request,
    client_id: str,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> BaseResponse[OAuthApplicationResponse]:
    """Get OAuth application details."""
    try:
        oauth_service = OAuth2Service(session)

        # Get application
        app = await oauth_service.get_application(client_id)
        if not app:
            raise HTTPException(status_code=404, detail="Application not found")

        # Check ownership
        if app.owner_id != current_user.id and not current_user.is_superuser:
            raise HTTPException(status_code=403, detail="Access denied")

        response_data = OAuthApplicationResponse.from_orm(app)

        return BaseResponse(
            data=response_data,
            message="Success",
            trace_id=getattr(request.state, "trace_id", None),
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "Failed to get OAuth application",
            client_id=client_id,
            error=str(e),
        )
        raise HTTPException(status_code=500, detail="Failed to get application")


@router.get(
    "/authorize",
    response_class=HTMLResponse,
    summary="OAuth Authorization Page",
    description="Display authorization page for OAuth flow.",
)
async def oauth_authorize_page(
    response_type: str = Query(..., description="Response type (code)"),
    client_id: str = Query(..., description="Client ID"),
    redirect_uri: str = Query(..., description="Redirect URI"),
    scope: str = Query(..., description="Requested scopes"),
    state: Optional[str] = Query(None, description="State parameter"),
    code_challenge: Optional[str] = Query(None, description="PKCE code challenge"),
    code_challenge_method: Optional[str] = Query(None, description="PKCE method"),
    nonce: Optional[str] = Query(None, description="OpenID Connect nonce"),
    current_user: Optional[User] = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> HTMLResponse:
    """Display OAuth authorization page."""
    # If user not logged in, redirect to login with return URL
    if not current_user:
        # Build return URL with all parameters
        params = {
            "response_type": response_type,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": scope,
        }
        if state:
            params["state"] = state
        if code_challenge:
            params["code_challenge"] = code_challenge
        if code_challenge_method:
            params["code_challenge_method"] = code_challenge_method
        if nonce:
            params["nonce"] = nonce

        # TODO: Implement proper login redirect
        return HTMLResponse("<h1>Please log in first</h1>")

    try:
        oauth_service = OAuth2Service(session)

        # Get application details
        app = await oauth_service.get_application(client_id)
        if not app:
            return HTMLResponse("<h1>Invalid client</h1>", status_code=400)

        # Parse scopes
        requested_scopes = scope.split(" ")

        # Build authorization page HTML
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Authorize {app.name}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .container {{ max-width: 600px; margin: 0 auto; }}
                .app-info {{ background: #f5f5f5; padding: 20px; border-radius: 8px; margin-bottom: 20px; }}
                .scopes {{ margin: 20px 0; }}
                .scope-item {{ margin: 10px 0; padding: 10px; background: #fff; border: 1px solid #ddd; }}
                .buttons {{ margin-top: 30px; }}
                button {{ padding: 10px 20px; margin-right: 10px; font-size: 16px; cursor: pointer; }}
                .approve {{ background: #4CAF50; color: white; border: none; }}
                .deny {{ background: #f44336; color: white; border: none; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Authorize {app.name}</h1>

                <div class="app-info">
                    <h2>{app.name}</h2>
                    <p>{app.description or 'No description provided'}</p>
                    {f'<p><a href="{app.homepage_url}" target="_blank">Visit website</a></p>' if app.homepage_url else ''}
                </div>

                <p><strong>{app.name}</strong> is requesting access to your account:</p>

                <div class="scopes">
                    <h3>Permissions requested:</h3>
                    {''.join(f'<div class="scope-item">{scope}</div>' for scope in requested_scopes)}
                </div>

                <form method="POST" action="/api/v1/oauth/authorize">
                    <input type="hidden" name="response_type" value="{response_type}">
                    <input type="hidden" name="client_id" value="{client_id}">
                    <input type="hidden" name="redirect_uri" value="{redirect_uri}">
                    <input type="hidden" name="scope" value="{scope}">
                    <input type="hidden" name="state" value="{state or ''}">
                    <input type="hidden" name="code_challenge" value="{code_challenge or ''}">
                    <input type="hidden" name="code_challenge_method" value="{code_challenge_method or ''}">
                    <input type="hidden" name="nonce" value="{nonce or ''}">

                    <div class="buttons">
                        <button type="submit" name="action" value="approve" class="approve">Approve</button>
                        <button type="submit" name="action" value="deny" class="deny">Deny</button>
                    </div>
                </form>
            </div>
        </body>
        </html>
        """

        return HTMLResponse(content=html_content)

    except Exception as e:
        logger.error("Failed to display authorization page", error=str(e))
        return HTMLResponse("<h1>Error loading authorization page</h1>", status_code=500)


@router.post(
    "/authorize",
    response_class=RedirectResponse,
    summary="Process OAuth Authorization",
    description="Process user's authorization decision.",
)
async def process_oauth_authorization(
    request: Request,
    action: str = Form(...),
    response_type: str = Form(...),
    client_id: str = Form(...),
    redirect_uri: str = Form(...),
    scope: str = Form(...),
    state: Optional[str] = Form(None),
    code_challenge: Optional[str] = Form(None),
    code_challenge_method: Optional[str] = Form(None),
    nonce: Optional[str] = Form(None),
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> RedirectResponse:
    """Process OAuth authorization."""
    try:
        # Check if user denied
        if action == "deny":
            # Redirect with error
            error_params = {"error": "access_denied"}
            if state:
                error_params["state"] = state

            # Build redirect URL
            separator = "&" if "?" in redirect_uri else "?"
            params_str = "&".join(f"{k}={v}" for k, v in error_params.items())
            return RedirectResponse(url=f"{redirect_uri}{separator}{params_str}")

        # User approved - create authorization code
        oauth_service = OAuth2Service(session)

        # Get application
        app = await oauth_service.get_application(client_id)
        if not app:
            raise ValidationError("Invalid client")

        # Validate redirect URI
        allowed_uris = json.loads(app.redirect_uris)
        if redirect_uri not in allowed_uris:
            raise ValidationError("Invalid redirect URI")

        # Create authorization code
        scopes = scope.split(" ")
        code = await oauth_service.create_authorization_code(
            application_id=str(app.id),
            user_id=str(current_user.id),
            redirect_uri=redirect_uri,
            scopes=scopes,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            nonce=nonce,
            request=request,
        )

        await session.commit()

        # Build success redirect
        success_params = {"code": code}
        if state:
            success_params["state"] = state

        separator = "&" if "?" in redirect_uri else "?"
        params_str = "&".join(f"{k}={v}" for k, v in success_params.items())
        return RedirectResponse(url=f"{redirect_uri}{separator}{params_str}")

    except Exception as e:
        logger.error(
            "Failed to process authorization",
            user_id=str(current_user.id),
            error=str(e),
        )
        # Redirect with error
        error_params = {"error": "server_error"}
        if state:
            error_params["state"] = state

        separator = "&" if "?" in redirect_uri else "?"
        params_str = "&".join(f"{k}={v}" for k, v in error_params.items())
        return RedirectResponse(url=f"{redirect_uri}{separator}{params_str}")


@router.post(
    "/token",
    response_model=OAuthTokenResponse,
    summary="OAuth Token Endpoint",
    description="Exchange authorization code or refresh token for access token.",
)
async def oauth_token(
    request: Request,
    grant_type: str = Form(...),
    code: Optional[str] = Form(None),
    redirect_uri: Optional[str] = Form(None),
    client_id: str = Form(...),
    client_secret: Optional[str] = Form(None),
    refresh_token: Optional[str] = Form(None),
    scope: Optional[str] = Form(None),
    code_verifier: Optional[str] = Form(None),
    session: AsyncSession = Depends(get_db),
) -> OAuthTokenResponse:
    """OAuth token endpoint."""
    try:
        oauth_service = OAuth2Service(session)

        if grant_type == "authorization_code":
            # Exchange authorization code
            if not code or not redirect_uri:
                raise HTTPException(
                    status_code=400,
                    detail="Code and redirect_uri required for authorization_code grant",
                )

            access_token, refresh_token_str, expires_in = await oauth_service.exchange_authorization_code(
                code=code,
                client_id=client_id,
                client_secret=client_secret,
                redirect_uri=redirect_uri,
                code_verifier=code_verifier,
                request=request,
            )

            await session.commit()

            return OAuthTokenResponse(
                access_token=access_token,
                token_type=BEARER_TOKEN_TYPE,
                expires_in=expires_in,
                refresh_token=refresh_token_str,
                scope=scope,
            )

        elif grant_type == "refresh_token":
            # Refresh access token
            if not refresh_token:
                raise HTTPException(
                    status_code=400,
                    detail="Refresh token required for refresh_token grant",
                )

            requested_scopes = scope.split(" ") if scope else None

            access_token, new_refresh_token, expires_in = await oauth_service.refresh_access_token(
                refresh_token=refresh_token,
                client_id=client_id,
                client_secret=client_secret,
                scopes=requested_scopes,
                request=request,
            )

            await session.commit()

            return OAuthTokenResponse(
                access_token=access_token,
                token_type=BEARER_TOKEN_TYPE,
                expires_in=expires_in,
                refresh_token=new_refresh_token,
                scope=scope,
            )

        else:
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported grant type: {grant_type}",
            )

    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except AuthenticationError as e:
        raise HTTPException(status_code=401, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Token endpoint error", error=str(e))
        raise HTTPException(status_code=500, detail="Token generation failed")


@router.post(
    "/revoke",
    summary="Revoke OAuth Token",
    description="Revoke an access or refresh token.",
)
async def revoke_oauth_token(
    request: Request,
    token: str = Form(...),
    token_type_hint: Optional[str] = Form(None),
    client_id: Optional[str] = Form(None),
    client_secret: Optional[str] = Form(None),
    session: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Revoke OAuth token."""
    try:
        oauth_service = OAuth2Service(session)

        # Revoke token
        revoked = await oauth_service.revoke_token(
            token=token,
            token_type_hint=token_type_hint,
            client_id=client_id,
            client_secret=client_secret,
        )

        await session.commit()

        # Always return success (per RFC 7009)
        return {"revoked": revoked}

    except Exception as e:
        logger.error("Token revocation error", error=str(e))
        # Still return success per spec
        return {"revoked": False}


@router.get(
    "/authorizations",
    response_model=BaseResponse[List[UserAuthorizationResponse]],
    summary="List My OAuth Authorizations",
    description="List all OAuth applications authorized by the current user.",
)
async def list_my_authorizations(
    request: Request,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> BaseResponse[List[UserAuthorizationResponse]]:
    """List user's OAuth authorizations."""
    try:
        oauth_service = OAuth2Service(session)

        # Get authorizations
        authorizations = await oauth_service.list_user_authorizations(str(current_user.id))

        # Convert to response models
        response_data = [UserAuthorizationResponse(**auth) for auth in authorizations]

        return BaseResponse(
            data=response_data,
            message="Success",
            trace_id=getattr(request.state, "trace_id", None),
        )

    except Exception as e:
        logger.error(
            "Failed to list authorizations",
            user_id=str(current_user.id),
            error=str(e),
        )
        raise HTTPException(status_code=500, detail="Failed to list authorizations")


@router.delete(
    "/authorizations/{application_id}",
    response_model=BaseResponse[Dict[str, bool]],
    summary="Revoke OAuth Authorization",
    description="Revoke all tokens for a specific OAuth application.",
)
async def revoke_authorization(
    request: Request,
    application_id: str,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> BaseResponse[Dict[str, bool]]:
    """Revoke OAuth authorization."""
    try:
        oauth_service = OAuth2Service(session)

        # Revoke authorization
        revoked = await oauth_service.revoke_user_authorization(
            user_id=str(current_user.id),
            application_id=application_id,
        )

        await session.commit()

        logger.info(
            "OAuth authorization revoked",
            user_id=str(current_user.id),
            application_id=application_id,
        )

        return BaseResponse(
            data={"revoked": revoked},
            message="Authorization revoked successfully" if revoked else "No active authorization found",
            trace_id=getattr(request.state, "trace_id", None),
        )

    except Exception as e:
        logger.error(
            "Failed to revoke authorization",
            user_id=str(current_user.id),
            application_id=application_id,
            error=str(e),
        )
        raise HTTPException(status_code=500, detail="Failed to revoke authorization")
