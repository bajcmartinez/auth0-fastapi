# Auth0 FastAPI

This library provides a simple and elegant way to validate [Auth0](https://auth0.com) tokens in your API and keep your endpoints protected.

Benefits of using this library:
- Token validation, ensure the access tokens are properly structured, and signed.
- Support of scopes for permission based authorization.
- Automatic swagger UI support, just enter your token and test your endpoints.
- Super easy to use.

## Installation

```
pip install auth0_fastapi
```

## Example usage

```python

from fastapi import FastAPI, Depends, Security
from auth0_fastapi import Auth0JWTBearerTokenValidator

auth = Auth0JWTBearerTokenValidator(
    domain="<your-auth0-domain>",
    audience="<your-auth0-api-audience>",
    issuer="<your-auth0-issuer>"
)

app = FastAPI()

@app.get("/public")
def get_public():
    return {"message": "Anyone can access"}

@app.get("/protected", dependencies=[Security(auth.get_authenticated_user)])
def get_protected():
    return {"message": "Any authenticated user can access"}


@app.get("/secured", dependencies=[Security(auth.get_authenticated_user, scopes=['read:secure'])])
def get_secured():
    return {"message": "Only users with permission 'read:secure' can access"}

@app.get("/get-token-payload")
def get_token_payload(token_payload=Security(auth.get_authenticated_user)):
    return {"message": token_payload}
```

## Disclaimer

This is not an official plugin, it is however used in production by my own applications and follows best practices.

Please report any issues you encounter, happy coding!

