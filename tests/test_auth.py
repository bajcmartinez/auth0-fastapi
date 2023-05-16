from fastapi import FastAPI, Security
from fastapi.testclient import TestClient

from auth0_fastapi import Auth0JWTBearerTokenValidator

access_token = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImhCdG9aQjBacG5EdkY0ZXp1aXMwdSJ9.eyJpc3MiOiJodHRwczovL2dvdG9sY3MtZGV2LmV1LmF1dGgwLmNvbS8iLCJzdWIiOiJBZTloTTB6cHZyTEJJR0VkOGJLQUhkUENWdTBFNDRtakBjbGllbnRzIiwiYXVkIjoidGVzdGFwaS5jb20iLCJpYXQiOjE2ODQyMjYxNTcsImV4cCI6MTY4NDMxMjU1NywiYXpwIjoiQWU5aE0wenB2ckxCSUdFZDhiS0FIZFBDVnUwRTQ0bWoiLCJzY29wZSI6InJlYWQ6c2VjcmV0cyIsImd0eSI6ImNsaWVudC1jcmVkZW50aWFscyIsInBlcm1pc3Npb25zIjpbInJlYWQ6c2VjcmV0cyJdfQ.aEWvHAetN8zunVJT11P89OJJ-Sz-lqenEqc_B4WI8iKc0vfhgof-hTFOD2771CevPG0oSLWOu5MRKLUrUwK8YU7CL2wsLDOJ3M49Fvo9z2eeFcVUpdnLHbt779W7bmimS1IIT19ExZCjQg80C3ERqgYrDbHDAJNAzb3HWzwpnUAtVz0BcgGSYTS6YPzQ4dyHfVSNQps0jahauke21-QKC0ArRTlWMRvKE9XzqhK_ps4Uxy2t-mx4Ddh1Q9QXwnE0JvaJfuPSA02UXWUjAa7bG0yyKrYjfqI-7HIhuLykMAoa6WfgXvrYwMrjydtbhC0Pz-sV_4m9k3YHghqgdXC9fQ'

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
