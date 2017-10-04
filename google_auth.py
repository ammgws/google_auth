# Standard library
import datetime as dt
import logging
import os.path
from urllib.parse import urlencode
# Third party imports
import requests


class GoogleAuth(object):
    def __init__(self, client_id, client_secret, scopes, refresh_token_file=None):
        self.client_id = client_id
        self.client_secret = client_secret
        self.scopes = ' '.join(scopes)

        self.refresh_token_file = refresh_token_file
        if os.path.isfile(self.refresh_token_file):
            with open(self.refresh_token_file, 'r') as file:
                    self.refresh_token = file.read()
        else:
            self.refresh_token = None

        self.access_token = None
        self.token_expiry = None

        # Get latest OAUTH2 info from Google
        oauth_params = requests.get('https://accounts.google.com/.well-known/openid-configuration').json()
        self.authorize_url = oauth_params.get('authorization_endpoint')
        self.token_url = oauth_params.get('token_endpoint')
        self.userinfo_url = oauth_params.get('userinfo_endpoint')

    def authenticate(self):
        """ Get access token. Note that Google access tokens expire in 3600 seconds."""
        # Authenticate with Google and get access token.
        if not self.refresh_token:
            # If no refresh token is found in config file, then need to start
            # new authorization flow and get access token that way.
            # Note: Google has limit of 25 refresh tokens per user account per
            # client. When limit reached, creating a new token automatically
            # invalidates the oldest token without warning.
            # (Limit does not apply to service accounts.)
            # https://developers.google.com/accounts/docs/OAuth2#expiration
            logging.debug('No refresh token in config file (val = %s of type %s). '
                          'Need to generate new token.',
                          self.refresh_token,
                          type(self.refresh_token))
            # Get authorisation code from user
            auth_code = self.authorisation_request()
            # Request access token using authorisation code
            self.token_request(auth_code)
            # Save refresh token for next login attempt or application startup
            self.config.set(self.service, 'refresh_token', self.refresh_token)
            with open(self.config_filepath, 'w') as file:
                self.config.write(file)
        elif (self.access_token is None) or (dt.datetime.now() > self.token_expiry):
            # Use existing refresh token to get new access token.
            logging.debug('Using refresh token to generate new access token.')
            # Request access token using existing refresh token
            self.token_request()
        else:
            # Access token is still valid, no need to generate new access token.
            logging.debug('Access token is still valid - no need to regenerate.')
            return

    def authorisation_request(self):
        """Start authorisation flow to get new access + refresh token."""

        # Start by getting authorization_code for given scope(s).
        oauth2_login_url = '{0}?{1}'.format(
            self.authorize_url,
            urlencode(dict(
                client_id=self.client_id,
                scope=self.oauth2_scope,
                redirect_uri='urn:ietf:wg:oauth:2.0:oob',
                response_type='code',
                access_type='offline',
            ))
        )

        # Print auth URL and wait for user to grant access and
        # input authentication code into the console.
        print(oauth2_login_url)
        auth_code = input("Enter auth code from the above link: ")
        return auth_code

    def token_request(self, auth_code=None):
        """Make an access token request and get new token(s).
           If auth_code is passed then both access and refresh tokens will be
           requested, otherwise the existing refresh token is used to request
           an access token.

           Update the following class variables:
            access_token
            refresh_token
            token_expiry
           """
        # Build request parameters. Order doesn't seem to matter, hence using dict.
        token_request_data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
        }
        if auth_code is None:
            # Use existing refresh token to get new access token.
            token_request_data['refresh_token'] = self.refresh_token
            token_request_data['grant_type'] = 'refresh_token'
        else:
            # Request new access and refresh token.
            token_request_data['code'] = auth_code
            token_request_data['grant_type'] = 'authorization_code'
            # 'urn:ietf:wg:oauth:2.0:oob' signals to the Google Authorization
            # Server that the authorization code should be returned in the
            # title bar of the browser, with the page text prompting the user
            # to copy the code and paste it in the application.
            token_request_data['redirect_uri'] = 'urn:ietf:wg:oauth:2.0:oob'
            token_request_data['access_type'] = 'offline'

        # Make token request to Google.
        resp = requests.post(self.token_url, data=token_request_data)
        # If request is successful then Google returns values as a JSON array
        values = resp.json()
        self.access_token = values['access_token']
        if auth_code:  # Need to save value of new refresh token
            self.refresh_token = values['refresh_token']
        self.token_expiry = dt.datetime.now() + dt.timedelta(seconds=int(values['expires_in']))
        logging.info('Access token expires on %s', self.token_expiry.strftime("%Y/%m/%d %H:%M"))

    def get_email(self):
        """Get client's email address."""
        authorization_header = {"Authorization": "Bearer %s" % self.access_token}
        resp = requests.get(self.userinfo_url, headers=authorization_header)
        # If request is successful then Google returns values as a JSON array
        values = resp.json()
        return values['email']
