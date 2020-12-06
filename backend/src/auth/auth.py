import json
from flask import request, _request_ctx_stack,abort
from functools import wraps
from jose import jwt
from urllib.request import urlopen


AUTH0_DOMAIN = 'moapps.us.auth0.com'
ALGORITHMS = ['RS256']
API_AUDIENCE = 'coffeeshop'

## AuthError Exception

class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


def get_token_auth_header():
    auth=request.headers.get("Authorization",None)
    if not auth:
        raise AuthError({
        'code':'authorization_header_missing',
        'description':'no authorization header'
        },401)
    auth_parts=auth.split()
    if auth_parts[0].lower()!='bearer':
        raise AuthError({
        'code':'invalid_authorization_header',
        'description':'Bearer keyword missing'
        },401)
    if len(auth_parts)==1:
        raise AuthError({
        'code':'invalid_authorization_header',
        'description':'missing token'
        },401)
    if len(auth_parts)>2:
        raise AuthError({
        'code':'invalid_authorization_header',
        'description':'invalid token structure'
        },401)
    token=auth_parts[1]
    return token

def check_permissions(permission, payload):
    if 'permissions' not in payload:
        raise AuthError({
            'code': 'invalid_claims',
            'description': 'no permissions in jwt'
        }, 401)

    if permission not in payload['permissions']:
        raise AuthError({
            'code': 'unauthorized',
            'description': 'permission not found'
        }, 401)
    return True
    
def verify_decode_jwt(token):
    jsonurl = urlopen(f'https://{AUTH0_DOMAIN}/.well-known/jwks.json')
    jwks = json.loads(jsonurl.read())
    unverified_header = jwt.get_unverified_header(token)
    rsa_key = {}
    if 'kid' not in unverified_header:
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Authorization malformed.'
        }, 401)

    for key in jwks['keys']:
        if key['kid'] == unverified_header['kid']:
            rsa_key = {
                'kty': key['kty'],
                'kid': key['kid'],
                'use': key['use'],
                'n': key['n'],
                'e': key['e']
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=API_AUDIENCE,
                issuer='https://' + AUTH0_DOMAIN + '/'
            )

            return payload

        except jwt.ExpiredSignatureError:
            raise AuthError({
                'code': 'token_expired',
                'description': 'Token expired.'
            }, 401)

        except jwt.JWTClaimsError:
            raise AuthError({
                'code': 'invalid_claims',
                'description': 'Incorrect claims. Please, check the audience and issuer.'
            }, 401)
        except Exception:
            raise AuthError({
                'code': 'invalid_header',
                'description': 'Unable to parse authentication token.'
            }, 401)
    raise AuthError({
                'code': 'invalid_header',
                'description': 'Unable to find the appropriate key.'
            }, 401)

def requires_auth(permission=''):
    def requires_auth_decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            # try:
            token = get_token_auth_header()
            payload = verify_decode_jwt(token)
            check_permissions(permission, payload)
            # except AuthError as error:
            #     abort(error.status_code, description=error.error)
            return f(payload, *args, **kwargs)
        return wrapper
    return requires_auth_decorator



