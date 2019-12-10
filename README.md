# Summary

This API implements Earthdata Login (EDL) authentication via JSON Web Tokens (JWT).  Web applications requiring EDL need only verify a JWT cookie to authenticate clients, and can forward un-authenticated clients to log in via a simple redirect.  This eliminates the need for applications to implement their own EDL redirect URI, and facilitates scalable, low-latency single-sign-on across applications on a shared domain.

# Related Documentation

[Earthdata Login OAuth/SSO Client Implementation](https://urs.earthdata.nasa.gov/sso_client_impl)

[Earthdata Login Integration](https://wiki.earthdata.nasa.gov/display/EL/Earthdata+Login+Integration)

[Introduction to JSON Web Tokens](https://jwt.io/introduction/)

# Endpoints

## /login

Implements an EDL redirect URI.  Validates a client's EDL session and vends a JWT session cookie.

This endpoint is not intended to be invoked directly by applications.  Rather, applications should forward clients to the  [/oauth/authorize](https://wiki.earthdata.nasa.gov/display/EL/API+Documentation#APIDocumentation-oauth-authorize) endpoint of the EDL API and provide this URL as the value for the `redirect_uri` parameter.

<urs_host>/oauth/authorize?response=code&state=<state>&redirect_uri=<apiHost>/login&client_id=<client_id>[&app_type=401]

code (required) - authorization code from the EDL server

state (required) - url to redirect to after successful login

```
cookie name
cookie duration
cookie payload
{
  "user-id": "myUserId",
  "groups": ["group1", "group2"],
  "exp": 12345
}
```

## /logout

Logs the user out by expiring their session cookie.

## /key

Returns the public key currently in use for validating jwt session cookies.

# Client Implementation

```
import jwt

def authenhandler(req):
    redirect_url = AUTH_URL + '&state=' + quote_plus(req.url)

    cookies = Cookie.get_cookies(req)
    if not cookies.has_key(COOKIE_NAME):
        util.redirect(req, redirect_url)

    token = cookies[COOKIE_NAME].value
    try:
        payload = jwt.decode(token, PUBLIC_KEY)
    except (jwt.DecodeError, jwt.ExpiredSignatureError):
        util.redirect(req, redirect_url)

    req.user = payload.get('user-id')
    return apache.OK
```
