#!/usr/bin/env python3
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Final, Optional, cast
from uuid import uuid4
import json
import os
import pdb
import requests
import socketserver
import sys
import threading
import time
import urllib.parse
import webbrowser

# modifiable global variable due to library interface constraint
TOKEN: Optional[dict] = None

STATE: Final[str]         = str(uuid4())
HOST: Final[str]          = os.environ['SB1_HOST']
PORT: Final[int]          = int(os.environ['SB1_PORT'])
CLIENT_ID: Final[str]     = os.environ['SB1_CLIENT_ID']
CLIENT_SECRET: Final[str] = os.environ['SB1_CLIENT_SECRET']
FIN_INST: Final[str]      = os.environ['SB1_FIN_INST']
REDIRECT_URI: Final[str]  = os.environ['SB1_REDIRECT_URI']

def oauth_token(state: str, code: str, grant_type: str) -> Optional[dict]:
    """
        Gets a new OAuth token by either using an authorization code obtained
        through BankID authentication or by using a refresh token.
        Valid grant_type values:
            - 'authorization_code'
            - 'refresh_token'
    """

    url = 'https://api.sparebank1.no/oauth/token'
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    data = {
        'client_id':     CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'grant_type':    grant_type,
    }
    if grant_type == 'authorization_code':
        data['code'] = code
        data['state'] = state
        data['redirect_uri'] = REDIRECT_URI
    elif grant_type == 'refresh_token':
        data['refresh_token'] = code
    else:
        raise ValueError("grant_type must be 'authorization_code' or 'refresh_token'")

    resp = requests.post('https://api.sparebank1.no/oauth/token', data=data, headers=headers)
    if not resp.ok:
        return None

    token = json.loads(resp.text)

    token['time'] = int(time.time())

    return token

def oauth_token_refresh(token: dict) -> Optional[dict]:
    """ uses the `refresh_token` key in `token` to get a new `token` """
    return oauth_token("0", token['refresh_token'], 'refresh_token')

def oauth_token_new(state: str, code: str) -> Optional[dict]:
    """ uses an authentication code obtained through BankID authentication to obtain a new oauth token """
    return oauth_token(state, code, 'authorization_code') 

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        """ BankId authentication redirects to this handler with the url
            parameters `code` and `state`, which are used to obtain an OAuth
            code.
            BaseHTTPRequestHandler handlers can't return any values so a global
            variable `TOKEN` is set instead.
        """
        parsed_path = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed_path.query)

        code = params.get("code", [None])[0]
        state = params.get("state", [None])[0]

        assert code
        assert state

        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        with open('close_page.html', 'rb') as f:
            self.wfile.write(f.read())

        global TOKEN
        TOKEN = oauth_token_new(state, code)

def browser_auth() -> Optional[dict]:
    state = uuid4()

    auth_url = 'https://api.sparebank1.no/oauth/authorize'
    auth_url += f'?client_id={CLIENT_ID}'
    auth_url += f'&state={state}'
    auth_url += f'&redirect_uri={REDIRECT_URI}'
    if FIN_INST:
        auth_url += f'&finInst={FIN_INST}'
    auth_url += f'&response_type=code'

    print(f"opening {auth_url} in browser", file=sys.stderr)
    webbrowser.open(auth_url)

    with HTTPServer((HOST, PORT), Handler) as httpd:
        # handle_request sets the global variable TOKEN
        httpd.handle_request()

    return TOKEN

def token_oauth_expired(token: dict) -> bool:
    """ Returns true if access token is expired """
    return token['time'] + token['expires_in'] < int(time.time())

def token_refresh_expired(token: dict) -> bool:
    """ Return true if refresh token is expired """
    return token['time'] + token['refresh_token_expires_in'] < int(time.time())

def authenticate() -> dict:
    """ Main authentication function, returns a token dict containing `acess_token` """
    try:
        f = open('smn-oauth.json', 'r+')
        with f:
            token = json.load(f)
    except FileNotFoundError:
        token = None

    if not token:
        print(f"Token not found, BankID authentication required...", file=sys.stderr)
        token = browser_auth()
    elif token_refresh_expired(token):
        print(f"Refresh token expired, authenticating...", file=sys.stderr)
        token = browser_auth()
    elif token_oauth_expired(token):
        print(f"OAuth expired, refreshing...", file=sys.stderr)
        token = oauth_token_refresh(token)
        if not token:
            print(f"Failed to refresh, authenticating", file=sys.stderr)
            browser_auth()

    if not token:
        print(f"Fatal error: failed to get token", file=sys.stderr)
        exit(1)

    with open('smn-oauth.json', 'w') as f:
        json.dump(token, f, indent=4)
        f.truncate()

    return token

def main():
    token = authenticate()

    hw = requests.get(
        'https://api.sparebank1.no/personal/banking/accounts?includeCreditCardAccounts=true&includeAskAccounts=true',
        headers = {
            'Authorization': f"Bearer {token['access_token']}",
            'Accept':        'application/vnd.sparebank1.v1+json; charset=utf-8'
        }
    )

    for acc in hw.json()['accounts']:
        print(f'{(acc["description"] + ':'):<25} {acc["balance"]:>10.0f} {acc["currencyCode"]}')

if __name__ == "__main__":
    main()
