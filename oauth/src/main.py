from os import environ
from datetime import datetime, timedelta
from http.cookies import SimpleCookie
import requests
import jwt
from requests_oauthlib import OAuth2Session
from oauthlib.oauth2 import InvalidGrantError


URS_HOSTNAME = environ['URS_HOSTNAME']
URS_TOKEN_URI = environ['URS_TOKEN_URI']
URS_CLIENT_ID = environ['URS_CLIENT_ID']
URS_CLIENT_PASSWORD = environ['URS_CLIENT_PASSWORD']
URS_REDIRECT_URI = environ['URS_REDIRECT_URI']
COOKIE_NAME = environ['COOKIE_NAME']
COOKIE_DOMAIN = environ['COOKIE_DOMAIN']
COOKIE_DURATION_IN_SECONDS = environ['COOKIE_DURATION_IN_SECONDS']
PRIVATE_KEY = environ['PRIVATE_KEY']

URS = OAuth2Session(URS_CLIENT_ID, redirect_uri=URS_REDIRECT_URI)


def get_400_response():
    return {
        'statusCode': 400,
        'body': None,
    }


def get_redirect_response(url, token):
    return {
        'statusCode': 307,
        'headers': {
            'Location': url,
            'Set-Cookie': get_cookie_string(token),
        },
        'body': None,
    }


def get_cookie_string(token):
    cookie = SimpleCookie()
    cookie[COOKIE_NAME] = token
    cookie[COOKIE_NAME]['expires'] = COOKIE_DURATION_IN_SECONDS
    cookie[COOKIE_NAME]['domain'] = COOKIE_DOMAIN
    return cookie.output(header='')


def get_urs_token(code):
    token_uri = URS_HOSTNAME + URS_TOKEN_URI
    urs_token = URS.fetch_token(token_uri, code=code, client_secret=URS_CLIENT_PASSWORD)
    return urs_token


def get_user(urs_token):
    user_profile_uri = URS_HOSTNAME + urs_token['endpoint']
    auth_string = urs_token['token_type'] + ' ' + urs_token['access_token']
    response = requests.get(user_profile_uri, headers={'Authorization': auth_string})
    response.raise_for_status()
    return response.json


def get_token(user):
    expiration_time = datetime.utcnow() + timedelta(seconds=COOKIE_DURATION_IN_SECONDS)
    payload = {
        'username': user['username'],
        'restricted_data_use_agreement': False,
        'exp': expiration_time.strftime('%s'),
    }
    token = jwt.encode(payload, PRIVATE_KEY, 'RS256')
    return token


def lambda_handler(event, context):
    parms = event['queryStringParameters']
    if not parms.get('code') or not parms.get('state'):
        return get_400_response()

    try:
        urs_token = get_urs_token(parms['code'])
    except InvalidGrantError:
        return get_400_response()

    user = get_user(urs_token)
    token = get_token(user)

    return get_redirect_response(parms['state'], token)
