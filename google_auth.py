# Standard library
import datetime as dt
import json
import logging
import os.path
from tempfile import mkstemp
from urllib.parse import urlencode

# Third party
import requests
import segno


class GoogleAuthException(Exception):
    """Base exception for GoogleAuth."""

    pass


class RequestError(GoogleAuthException):
    """A request error occurred."""

    pass


class Token(object):
    def __init__(self, access_token="", refresh_token="", **kwargs):
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.expiry = kwargs.get("expiry", None)
        self.file = kwargs.get("file", None)

    def __repr__(self):
        return "<{}({})>".format(
            self.__class__.__name__,
            "No token"
            if not self.access_token
            else "Expires {}".format(self.expiry_str),
        )

    @property
    def is_expired(self):
        return self.expiry is not None and dt.datetime.now() > self.expiry

    @property
    def expiry_str(self):
        return self.expiry.isoformat(sep=" ", timespec="seconds")

    @classmethod
    def from_file(cls, file):
        with open(file) as f:
            try:
                values = json.load(f)
            except json.decoder.JSONDecodeError:
                values = {
                    "access_token": "",
                    "refresh_token": "",
                    "expiry": None,
                }

        try:
            expiry_dt = dt.datetime.strptime(values["expiry"], "%Y-%m-%d %H:%M:%S")
        except TypeError:
            expiry_dt = None

        return cls(
            access_token=values["access_token"],
            refresh_token=values["refresh_token"],
            expiry=expiry_dt,
            file=file,
        )

    def reset(self):
        self.access_token = ""
        self.refresh_token = ""
        self.expiry = None

    def save_to_file(self):
        with open(self.file, "w") as f:
            json.dump(
                {
                    "access_token": self.access_token,
                    "refresh_token": self.refresh_token,
                    "expiry": self.expiry_str,
                },
                f,
            )


class GoogleAuth(object):
    """Helper class for getting OAUTH access tokens for Google services.

    :param client_id: OAuth 2.0 client ID obtained from Google API Console.
    :param client_secret: OAuth 2.0 client secret obtained from Google API Console.
    :param scopes: List of OAuth 2.0 scopes to access. See https://developers.google.com/identity/protocols/googlescopes.
    :param refresh_token_file (optional): Path to a file to write refresh token info. Must be writeable.
    :return: :class:`GoogleAuth <Authenticated>` object
    :rtype: google_auth.GoogleAuth

    Usage::

      >>> from google_auth import GoogleAuth
      >>> oauth = GoogleAuth(client_id, client_secret, ['https://www.googleapis.com/auth/userinfo.email',])
      >>> oauth.authenticate()
      <GoogleAuth(Authenticated: True. Expiry: 2017/10/09 19:29)>

    Google Reference Docs:
        https://developers.google.com/identity/protocols/OAuth2WebServer
    """

    def __init__(self, client_id, client_secret, scopes, token_file=None):
        self.client_id = client_id
        self.client_secret = client_secret

        # Allow a string to be passed instead of throwing an exception.
        if isinstance(scopes, str):
            self.scopes = scopes
        else:
            self.scopes = " ".join(scopes)

        if token_file and os.path.isfile(token_file):
            self.token_file = token_file
        elif token_file is None:
            self.token_file = mkstemp(prefix="token_")[1]
            logging.warning("Token will not persist across instances.")
        self.token = Token.from_file(self.token_file)

        # Get latest OAUTH2 endpoints from Google instead of hard-coding.
        self.oauth_params = requests.get(
            "https://accounts.google.com/.well-known/openid-configuration"
        ).json()

    def __repr__(self):
        return "<{}({}.{})>".format(
            self.__class__.__name__,
            "Authenticated" if self.authenticated else "Unauthenticated",
            " Expiry: {}".format(self.token.expiry.strftime("%Y/%m/%d %H:%M"))
            if self.token.expiry
            else "",
        )

    def authenticate(self):
        """Get access token.

        Note that Google access tokens expire in 3600 seconds.
        """
        if not self.token.refresh_token:
            # If no refresh token exists then need to start new authorization flow and get access token that way.
            # Note: Google has limit of 50 refresh tokens per user account per client.
            # When limit reached, creating a new token automatically invalidates the oldest token without warning.
            # https://developers.google.com/accounts/docs/OAuth2#expiration
            logging.debug("No refresh token, generating new token.")
            url = self.generate_auth_url()
            auth_code = self.prompt(url)
            self._token_request(auth_code)
        elif not self.authenticated:
            logging.debug("Using refresh token to generate new access token.")
            self._token_request()
        else:
            logging.debug("Access token is still valid - no need to regenerate.")
            return

    @property
    def authenticated(self):
        return self.token.access_token and not self.token.is_expired

    @property
    def access_token(self):
        return self.token.access_token

    @property
    def refresh_token(self):
        return self.token.refresh_token

    @property
    def token_expiry(self):
        return self.token.expiry

    @staticmethod
    def prompt(url):
        """Override this method to provide custom prompts."""
        print(url)
        qr = segno.make(url).terminal()
        auth_code = input("Enter auth code from the above link:")
        return auth_code

    def generate_auth_url(self):
        """Generate an authorisation URL."""
        url = "{0}?{1}".format(
            self.oauth_params.get("authorization_endpoint"),
            urlencode(
                dict(
                    client_id=self.client_id,
                    scope=self.scopes,
                    redirect_uri="urn:ietf:wg:oauth:2.0:oob",
                    response_type="code",
                    access_type="offline",
                )
            ),
        )

        # 'urn:ietf:wg:oauth:2.0:oob' signals to the Google Authorization
        # Server that the authorization code should be returned in the
        # title bar of the browser, with the page text prompting the user
        # to copy the code and paste it in the application.

        return url

    def _token_request(self, auth_code=None):
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
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }
        if not auth_code:
            logging.info("Using existing refresh token to get new access token.")
            token_request_data["refresh_token"] = self.token.refresh_token
            token_request_data["grant_type"] = "refresh_token"
        else:
            logging.info("Requesting new access and refresh tokens.")
            token_request_data["code"] = auth_code
            token_request_data["grant_type"] = "authorization_code"
            token_request_data["redirect_uri"] = "urn:ietf:wg:oauth:2.0:oob"
            token_request_data["access_type"] = "offline"

        r = requests.post(
            self.oauth_params.get("token_endpoint"), data=token_request_data
        )
        if r.status_code == 200:
            values = r.json()
            self.token.access_token = values["access_token"]
            self.token.expiry = dt.datetime.now() + dt.timedelta(
                seconds=int(values["expires_in"])
            )
            logging.info(
                "Access token expires on %s.",
                self.token.expiry.strftime("%Y/%m/%d %H:%M"),
            )

            if auth_code:
                # Save refresh token for next login attempt or application startup.
                self.token.refresh_token = values["refresh_token"]

            # Update with new refresh token or access token info
            self.token.save_to_file()
        else:
            # TODO
            logging.error(r.content)
            raise RequestError

    def revoke_token(self):
        r = requests.get(
            self.oauth_params.get("revocation_endpoint"),
            params={"token": self.token.access_token},
        )
        if r.status_code == 200:
            self.token.reset()
            self.token.save_to_file()
        else:
            # TODO
            pass

    def get_email(self):
        """Get client's email address."""
        if self.authenticated:
            authorization_header = {
                "Authorization": "Bearer %s" % self.token.access_token
            }
            r = requests.get(
                self.oauth_params.get("userinfo_endpoint"), headers=authorization_header
            )
            if r.status_code == 200:
                email = r.json()["email"]
            else:
                # TODO
                logging.error(r.content)
                raise Exception
        else:
            email = None
        return email
