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


def static_response(status_code, message=None):
    response = {
        'statusCode': status_code,
        'body': message,
    }
    return response


def login_response(url, token):
    response = static_response(307)
    response['headers'] = {
        'Location': url,
        'Set-Cookie': get_cookie_string(token),
    }
    return response


def logout_response():
    response = static_response(200, 'Logged Out')
    response['headers'] = {
        'Set-Cookie': get_cookie_string()
    }
    return response


def get_cookie_string(token=None):
    cookie = SimpleCookie()
    cookie[CONFIG['CookieName']] = token
    if token:
        cookie[CONFIG['CookieName']]['expires'] = CONFIG['CookieDurationInSeconds']
    else:
        cookie[CONFIG['CookieName']]['expires'] = 0
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


def login(parms):
    if 'error' in parms:
        return static_response(401, parms.get('error_msg'))

    if not parms.get('code'):
        return static_response(400, 'Missing required parameter: code')

    try:
        urs_token = get_urs_token(parms['code'])
    except InvalidGrantError as e:
        return static_response(401, e.description)

    #TODO catch connection errors
    user = get_user(urs_token)
    token_payload = get_token_payload(user)
    print(f'Token payload: {token_payload}')
    token = jwt.encode(token_payload, CONFIG['JwtPrivateKey'], CONFIG['JwtAlgorithm']).decode()

    default_url = urljoin(CONFIG['UrsHostname'], CONFIG['UrsProfileUri'])
    url = parms.get('state', default_url)
    return login_response(url, token)


def lambda_handler(event, context):
    uri = event['resource']
    print(f'Uri: {uri}')

    parms = event['queryStringParameters']
    if parms is None:
        parms = {}
    print(f'Parameters: {parms}')

    if uri == '/login':
        response = login(parms)
    if uri == '/logout':
        response = logout_response()
    if uri == '/key':
        response = static_response(200, CONFIG['JwtPublicKey'])

    print(f'Response: {response}')
    return response
