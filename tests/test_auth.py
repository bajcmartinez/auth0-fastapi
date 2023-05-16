from fastapi import FastAPI, Security
from fastapi.testclient import TestClient

from auth0_fastapi import Auth0JWTBearerTokenValidator

access_token = ''

auth = Auth0JWTBearerTokenValidator(
    domain="gotolcs-dev.eu.auth0.com",
    audience="testapi.com",
    issuer='https://gotolcs-dev.eu.auth0.com/'
)

app = FastAPI()
client = TestClient(app)


@app.get('/public')
async def get_public():
    return {'message': 'Anonymous user'}


@app.get('/protected')
async def get_protected(user=Security(auth.get_authenticated_user)):
    return user


@app.get('/scoped')
async def get_scoped(user=Security(auth.get_authenticated_user, scopes=['read:secrets'])):
    return user


@app.get('/wrongly_scoped')
async def get_wrongly_scoped(user=Security(auth.get_authenticated_user, scopes=['read:not_in_scope'])):
    return user


@app.get('/requires_two_scopes')
async def get_twice_scoped(user=Security(auth.get_authenticated_user, scopes=['read:secrets', 'read:not_in_scope'])):
    return user


# Tests
def get_bearer_header(token: str) -> dict[str, str]:
    return {'Authorization': 'Bearer ' + token}


def test_anonymous_can_access_public():
    resp = client.get('/public')
    assert resp.status_code == 200, resp.text


def test_anonymous_cannot_access_protected():
    resp = client.get('/protected')
    assert resp.status_code == 403, resp.text


def test_anonymous_cannot_access_scoped():
    resp = client.get('/scoped')
    assert resp.status_code == 403, resp.text


def test_authenticated_can_access_public():
    resp = client.get('/public', headers=get_bearer_header(access_token))
    assert resp.status_code == 200, resp.text


def test_authenticated_can_access_protected():
    resp = client.get('/protected', headers=get_bearer_header(access_token))
    assert resp.status_code == 200, resp.text


def test_authenticated_can_access_scoped():
    resp = client.get('/scoped', headers=get_bearer_header(access_token))
    assert resp.status_code == 200, resp.text


def test_authenticated_cannot_access_two_scopes():
    resp = client.get('/requires_two_scopes', headers=get_bearer_header(access_token))
    assert resp.status_code == 403, resp.text


def test_authenticated_cannot_access_scoped():
    resp = client.get('/wrongly_scoped', headers=get_bearer_header(access_token))
    assert resp.status_code == 403, resp.text
