# Standard library
import datetime as dt
import logging
import os.path
from urllib.parse import urlencode
# Third party
import requests


class TokenRequestError(Exception):
    pass


class GoogleAuth(object):
    def __init__(self, client_id, client_secret, scopes, refresh_token_file=None):
        self.client_id = client_id
        self.client_secret = client_secret
        self.scopes = ' '.join(scopes)

        self.refresh_token_file = refresh_token_file
        if refresh_token_file and os.path.isfile(self.refresh_token_file):
            with open(self.refresh_token_file) as file:
                self.refresh_token = file.read()
        else:
            self.refresh_token = None

        self.access_token = None
        self.token_expiry = None

        # Get latest OAUTH2 endpoints from Google instead of hard-coding.
        oauth_params = requests.get('https://accounts.google.com/.well-known/openid-configuration').json()
        self.authorize_url = oauth_params.get('authorization_endpoint')
        self.token_url = oauth_params.get('token_endpoint')
        self.userinfo_url = oauth_params.get('userinfo_endpoint')

    def authenticate(self):
        """Get access token. Note that Google access tokens expire in 3600 seconds."""
        if not self.refresh_token:
            # If no refresh token is found in config file, then need to start
            # new authorization flow and get access token that way.
            # Note: Google has limit of 25 refresh tokens per user account per
            # client. When limit reached, creating a new token automatically
            # invalidates the oldest token without warning.
            # (Limit does not apply to service accounts.)
            # https://developers.google.com/accounts/docs/OAuth2#expiration
            logging.debug('No refresh token, generating new token.')
            auth_code = self.authorisation_request()
            self.token_request(auth_code)
        elif (self.access_token is None) or (dt.datetime.now() > self.token_expiry):
            logging.debug('Using refresh token to generate new access token.')
            self.token_request()
        else:
            logging.debug('Access token is still valid - no need to regenerate.')
            return

    def authorisation_request(self):
        """Start authorisation flow to get new access + refresh token."""
        oauth2_login_url = '{0}?{1}'.format(
            self.authorize_url,
            urlencode(dict(
                client_id=self.client_id,
                scope=self.scopes,
                redirect_uri='urn:ietf:wg:oauth:2.0:oob',
                response_type='code',
                access_type='offline',
            ))
        )

        # 'urn:ietf:wg:oauth:2.0:oob' signals to the Google Authorization
        # Server that the authorization code should be returned in the
        # title bar of the browser, with the page text prompting the user
        # to copy the code and paste it in the application.

        print(oauth2_login_url)
        auth_code = input('Enter auth code from the above link:')
        return auth_code

    def token_request(self, auth_code=None):
        """Make an access token request and get new token(s).
           If auth_code is passed then both access and refresh tokens will be
           requested, otherwise the existing refresh token is used to request
           an access token.

           Updates the following class variables:
            access_token
            refresh_token
            token_expiry
        """
        token_request_data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
        }
        if not auth_code:
            # Use existing refresh token to get new access token.
            token_request_data['refresh_token'] = self.refresh_token
            token_request_data['grant_type'] = 'refresh_token'
        else:
            # Request new access and refresh tokens.
            token_request_data['code'] = auth_code
            token_request_data['grant_type'] = 'authorization_code'
            token_request_data['redirect_uri'] = 'urn:ietf:wg:oauth:2.0:oob'
            token_request_data['access_type'] = 'offline'

        r = requests.post(self.token_url, data=token_request_data)
        if r.status_code == 200:
            values = r.json()
            self.access_token = values['access_token']
            self.token_expiry = dt.datetime.now() + dt.timedelta(seconds=int(values['expires_in']))
            logging.info('Access token expires on %s.', self.token_expiry.strftime('%Y/%m/%d %H:%M'))

            if auth_code:
                # Save refresh token for next login attempt or application startup.
                self.refresh_token = values['refresh_token']
                with open(self.refresh_token_file, 'w') as file:
                    file.write(self.refresh_token)
        else:
            # TODO
            raise TokenRequestError

    def get_email(self):
        """Get client's email address."""
        authorization_header = {'Authorization': 'Bearer %s' % self.access_token}
        r = requests.get(self.userinfo_url, headers=authorization_header)
        if r.status_code == 200:
            email = r.json()['email']
        else:
            # TODO
            raise Exception
        return email
