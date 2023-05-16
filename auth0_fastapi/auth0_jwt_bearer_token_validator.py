from typing import Optional

from fastapi import Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, SecurityScopes
from jwt import PyJWK, PyJWKClient, decode as py_jwt_decode
from jwt.exceptions import PyJWKClientError, DecodeError

from auth0_fastapi.exceptions import UnauthenticatedException, UnauthorizedException


class Auth0JWTBearerTokenValidator:
    _domain: str
    _audience: str
    _algorithms: str
    _issuer: str
    _signing_key: PyJWK

    def __init__(self, domain: str, audience: str, issuer: str, algorithms: str = 'RS256') -> None:
        self._domain = domain
        self._audience = audience
        self._algorithms = algorithms
        self._issuer = issuer

        jwks_url = f'https://{self._domain}/.well-known/jwks.json'
        self._jwks_client = PyJWKClient(jwks_url)

    async def get_authenticated_user(
            self,
            security_scopes: SecurityScopes,
            token: Optional[HTTPAuthorizationCredentials] = Depends(HTTPBearer()),
    ):
        if token is None:
            raise UnauthenticatedException

        # Retrieve the signing keys from cache or the Auth0 servers
        try:
            self._signing_key = self._jwks_client.get_signing_key_from_jwt(token.credentials).key
        except PyJWKClientError as error:
            raise UnauthorizedException(str(error))
        except DecodeError as error:
            raise UnauthorizedException(str(error))

        # Decode the JWT token
        try:
            payload = py_jwt_decode(
                jwt=token.credentials,
                key=self._signing_key,
                issuer=self._issuer,
                algorithms=self._algorithms,
                audience=self._audience,
            )
        except Exception as error:
            raise UnauthorizedException(str(error))

        # Validate the scopes if any is required
        if len(security_scopes.scopes) > 0:
            token_scope_str: str = payload.get('scope', '')

            if isinstance(token_scope_str, str):
                token_scopes = token_scope_str.split()

                for scope in security_scopes.scopes:
                    if scope not in token_scopes:
                        raise UnauthorizedException(detail=f'Missing "{scope}" scope')
            else:
                # Auth0 provides the scope as a string, so this is not likely to happen, but better be sure
                raise UnauthorizedException(detail='Token "scope" field must be a string')

        return payload
