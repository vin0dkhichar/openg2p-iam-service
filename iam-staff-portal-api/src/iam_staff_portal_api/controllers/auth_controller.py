from typing import Annotated
from urllib.parse import urlencode

from fastapi import Depends, Request
from fastapi.responses import RedirectResponse
from openg2p_fastapi_common.controller import BaseController
from iam_core.schemas import (
    AuthCredentials,
    AuthPrincipal,
    LoginProviderHttpResponse,
    StartAuthTransactionResponse,
)
from iam_core.services import AuthService, ProviderRepository
from iam_core.user_auth.dependencies import JwtBearerAuth, UnauthorizedError, auth_principal, require_auth
from iam_core.user_auth.oidc_client import OidcClient

from ..config import Settings

_config = Settings.get_config(strict=False)


class AuthController(BaseController):
    '''
    Controller for authentication-related endpoints, such as retrieving user profile information and handling login/logout.
    '''
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.provider_repository = ProviderRepository.get_component()
        self.router.prefix += "/auth"
        self.router.tags += ["/auth"]
        self.auth_service = AuthService()

        self.router.add_api_route("/get_user_profile", self.get_user_profile, methods=["GET"])
        self.router.add_api_route("/logout", self.logout, methods=["GET"])
        self.router.add_api_route(
            "/get_login_providers",
            self.get_login_providers,
            responses={200: {"model": LoginProviderHttpResponse}},
            methods=["GET"],
        )
        self.router.add_api_route(
            "/start_authentication_transaction",
            self.start_authentication_transaction,
            responses={200: {"model": StartAuthTransactionResponse}},
            methods=["POST"],
        )

    async def get_user_profile(
        self,
        auth: Annotated[
            AuthPrincipal,
            Depends(require_auth(auth_principal)),
        ],
    ):
        return auth.model_dump(exclude={"credentials"})

    async def logout(
        self,
        request: Request,
        auth: Annotated[
            AuthCredentials,
            Depends(JwtBearerAuth())
        ],
    ):
        issuer = getattr(auth, "iss", None)

        login_provider = await self.provider_repository.get_by_iss(issuer)
        if not login_provider:
            raise UnauthorizedError("G2P-AUT-401", "Invalid issuer")

        redirect_uri = getattr(login_provider, "default_redirect_uri", None)

        oidc_client = OidcClient()
        metadata = await oidc_client.get_server_metadata(login_provider)

        logout_endpoint = metadata.get("end_session_endpoint")
        if not logout_endpoint:
            raise Exception("Logout endpoint not available in provider metadata")

        id_token = request.cookies.get("X-ID-Token")

        params = {
            "post_logout_redirect_uri": redirect_uri,
        }

        if id_token:
            params["id_token_hint"] = id_token

        if getattr(login_provider, "client_id", None):
            params["client_id"] = login_provider.client_id

        logout_url = f"{logout_endpoint}?{urlencode(params)}"

        response = RedirectResponse(url=logout_url)

        response.delete_cookie(
            "X-Access-Token",
            path=_config.auth_cookie_path,
            domain=_config.auth_cookie_domain,
        )
        response.delete_cookie(
            "X-ID-Token",
            path=_config.auth_cookie_path,
            domain=_config.auth_cookie_domain,
        )

        return response

    async def get_login_providers(self):
        return await self.auth_service.get_login_providers()

    async def start_authentication_transaction(self, id: int, redirect_uri: str = "/"):
        return await self.auth_service.start_authentication_transaction(
            provider_id=id,
            redirect_uri=redirect_uri,
        )
