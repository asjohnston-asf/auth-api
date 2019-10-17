from os import environ
from datetime import datetime, timedelta
from http.cookies import SimpleCookie
from urllib.parse import urljoin
from requests import Session
import jwt
from requests_oauthlib import OAuth2Session
from oauthlib.oauth2 import InvalidGrantError


URS_HOSTNAME = environ['URS_HOSTNAME']
URS_TOKEN_URI = environ['URS_TOKEN_URI']
URS_CLIENT_ID = environ['URS_CLIENT_ID']
URS_CLIENT_PASSWORD = environ['URS_CLIENT_PASSWORD']
URS_REDIRECT_URI = environ['URS_REDIRECT_URI']
URS_GROUP_NAME = environ['URS_GROUP_NAME']
COOKIE_NAME = environ['COOKIE_NAME']
COOKIE_DOMAIN = environ['COOKIE_DOMAIN']
COOKIE_DURATION_IN_SECONDS = int(environ['COOKIE_DURATION_IN_SECONDS'])
JWT_KEY = environ['JWT_KEY']
JWT_ALGORITHM = environ['JWT_ALGORITHM']

URS = OAuth2Session(URS_CLIENT_ID, redirect_uri=URS_REDIRECT_URI)
SESSION = Session()


def get_400_response():
    return {
        'statusCode': 400,
        'body': 'The provided authorization code is invalid.',
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
    token_uri = urljoin(URS_HOSTNAME, URS_TOKEN_URI)
    urs_token = URS.fetch_token(token_uri, code=code, client_secret=URS_CLIENT_PASSWORD)
    return urs_token


def get_user(urs_token):
    user_profile_uri = URS_HOSTNAME + urs_token['endpoint']
    auth_string = urs_token['token_type'] + ' ' + urs_token['access_token']
    response = SESSION.get(user_profile_uri, headers={'Authorization': auth_string})
    response.raise_for_status()
    return response.json()


def get_restricted_data_use_agreement(user):
    for group in user['user_groups']:
        if group['client_id'] == URS_CLIENT_ID and group['name'] == URS_GROUP_NAME:
            return True
    return False


def get_token(user):
    expiration_time = datetime.utcnow() + timedelta(seconds=COOKIE_DURATION_IN_SECONDS)
    payload = {
        'user-id': user['uid'],
        'restricted-data-use-agreement': get_restricted_data_use_agreement(user),
        'exp': expiration_time.strftime('%s'),
    }
    token = jwt.encode(payload, JWT_KEY, JWT_ALGORITHM)
    return token


def lambda_handler(event, context):
    parms = event['queryStringParameters']

    try:
        urs_token = get_urs_token(parms['code'])
    except InvalidGrantError:
        return get_400_response()

    user = get_user(urs_token)
    token = get_token(user)

    return get_redirect_response(parms['state'], token)
