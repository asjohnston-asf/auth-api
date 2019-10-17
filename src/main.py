from os import environ
from datetime import datetime, timedelta
from http.cookies import SimpleCookie
from urllib.parse import urljoin
from json import loads
from boto3 import client
from requests import Session
import jwt
from requests_oauthlib import OAuth2Session
from oauthlib.oauth2 import InvalidGrantError


SECRETS_MANAGER = client('secretsmanager')
SECRET = SECRETS_MANAGER.get_secret_value(SecretId=environ['CONFIG_SECRET_ARN'])
CONFIG = loads(SECRET['SecretString'])

URS = OAuth2Session(CONFIG['UrsClientId'], redirect_uri=CONFIG['UrsRedirectUri'])
SESSION = Session()


def error_response(status_code, message):
    response = {
        'statusCode': status_code,
        'body': message,
    }
    print(f"Response: {response}")
    return response


def redirect_response(url, token):
    response = {
        'statusCode': 307,
        'headers': {
            'Location': url,
            'Set-Cookie': get_cookie_string(token),
        },
        'body': None,
    }
    print(f"Response: {response}")
    return response


def get_cookie_string(token):
    cookie = SimpleCookie()
    cookie[CONFIG['CookieName']] = token
    cookie[CONFIG['CookieName']]['expires'] = CONFIG['CookieDurationInSeconds']
    cookie[CONFIG['CookieName']]['domain'] = CONFIG['CookieDomain']
    return cookie.output(header='')


def get_urs_token(code):
    token_uri = urljoin(CONFIG['UrsHostname'], CONFIG['UrsTokenUri'])
    urs_token = URS.fetch_token(token_uri, code=code, client_secret=CONFIG['UrsClientPassword'])
    return urs_token


def get_user(urs_token):
    user_profile_uri = urljoin(CONFIG['UrsHostname'], urs_token['endpoint'])
    auth_string = urs_token['token_type'] + ' ' + urs_token['access_token']
    response = SESSION.get(user_profile_uri, headers={'Authorization': auth_string})
    response.raise_for_status()
    return response.json()


def get_token_payload(user):
    expiration_time = datetime.utcnow() + timedelta(seconds=CONFIG['CookieDurationInSeconds'])
    payload = {
        'user-id': user['uid'],
        'groups': [group['name'] for group in user['user_groups'] if group['client_id'] == CONFIG['UrsClientId']],
        'exp': expiration_time.strftime('%s'),
    }
    return payload


def lambda_handler(event, context):
    parms = event['queryStringParameters']
    if parms is None:
        parms = {}
    print(f"Parameters: {parms}")

    if 'error' in parms:
        return error_response(401, parms.get('error_msg'))

    if 'code' not in parms:
        return error_response(400, 'Missing required parameter: code')
    if 'state' not in parms:
        return error_response(400, 'Missing required parameter: state')

    try:
        urs_token = get_urs_token(parms['code'])
    except InvalidGrantError as e:
        return error_response(401, e.description)

    #TODO catch connection errors
    user = get_user(urs_token)
    token_payload = get_token_payload(user)
    print(f"Token payload: {token_payload}")
    token = jwt.encode(token_payload, CONFIG['JwtKey'], CONFIG['JwtAlgorithm']).decode()

    return redirect_response(parms['state'], token)
