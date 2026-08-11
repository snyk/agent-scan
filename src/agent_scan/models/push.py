"""Models used to prepare authenticated scan pushes."""

from typing import Any

from mcp.client.auth import TokenStorage
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from pydantic import BaseModel, ConfigDict, Field, RootModel, field_validator
from pydantic.alias_generators import to_camel


class ControlServer(BaseModel):
    url: str
    headers: dict[str, str]
    identifier: str


class TokenAndClientInfo(BaseModel):
    # Use Field(alias=...) for the 'token' because OAuthToken's
    # internal fields (accessToken) are also camelCase.
    token: OAuthToken = Field(alias="token")
    server_name: str
    client_id: str
    token_url: str
    mcp_server_url: str
    updated_at: int

    model_config = ConfigDict(
        # Convert snake_case to camelCase for lookup while allowing snake_case in Python
        alias_generator=to_camel,
        populate_by_name=True,
    )

    @field_validator("token", mode="before")
    @classmethod
    def map_token_keys(cls, value: Any) -> Any:
        if isinstance(value, dict):
            # Map camelCase keys to snake_case for the OAuthToken model
            mapping = {
                "accessToken": "access_token",
                "tokenType": "token_type",
                "refreshToken": "refresh_token",
                "expiresIn": "expires_in",
            }
            return {mapping.get(key, key): item for key, item in value.items()}
        return value


class TokenAndClientInfoList(RootModel[list[TokenAndClientInfo]]):
    pass


class FileTokenStorage(TokenStorage):
    def __init__(self, data: TokenAndClientInfo):
        self.data = data

    async def get_tokens(self) -> OAuthToken | None:
        return self.data.token

    async def set_tokens(self, tokens: OAuthToken) -> None:
        raise NotImplementedError("set_tokens is not supported for FileTokenStorage")

    async def get_client_info(self) -> OAuthClientInformationFull | None:
        return OAuthClientInformationFull(
            client_id=self.data.client_id,
            redirect_uris=["http://localhost:3030/callback"],
        )

    async def set_client_info(self, client_info: OAuthClientInformationFull) -> None:
        """Store client information."""
        raise NotImplementedError("set_client_info is not supported for FileTokenStorage")
