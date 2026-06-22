import json
import jwt
import uuid
import logging
import base64
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
import urllib.parse as urlparse
from urllib.parse import urlencode

import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives._serialization import Encoding, PublicFormat
from jwt.algorithms import RSAAlgorithm

from .utils import generate_pkce_challenge

logger = logging.getLogger(__name__)


class FHIRAuth:
    """Superclass to handle authorization flow and state."""

    auth_type = "none"
    auth_classes = {}

    @classmethod
    def register(cls):
        """Register this class to handle authorization types of the given
        type."""
        if not cls.auth_type:
            raise Exception(f"Class {cls} does not specify the auth_type it supports")
        if cls.auth_type not in FHIRAuth.auth_classes:
            FHIRAuth.auth_classes[cls.auth_type] = cls
        elif FHIRAuth.auth_classes[cls.auth_type] != cls:
            raise Exception(
                f'Class {FHIRAuth.auth_classes[cls.auth_type]} is already registered for authorization type "{cls.auth_type}"'
            )

    @classmethod
    def from_capability_security(cls, security, state=None):
        """Supply a capabilitystatement.rest.security statement and this
        method will figure out which type of security should be instantiated.

        :param security: A CapabilityStatementRestSecurity instance
        :param state: A settings/state dictionary
        :returns: A FHIRAuth instance or subclass thereof
        """
        auth_type = None

        # look for OAuth2 URLs in SMART security extensions
        if security is not None and security.extension is not None:
            for e in security.extension:
                if (
                    "http://fhir-registry.smarthealthit.org/StructureDefinition/oauth-uris"
                    == e.url
                ):
                    if e.extension is not None:
                        for ee in e.extension:
                            if "token" == ee.url:
                                state["token_uri"] = ee.valueUri
                            elif "authorize" == ee.url:
                                state["authorize_uri"] = ee.valueUri
                            elif "register" == ee.url:
                                state["registration_uri"] = ee.valueUri
                        break
                    else:
                        logger.warning(
                            "SMART AUTH: invalid `http://fhir-registry.smarthealthit.org/StructureDefinition/oauth-uris` extension: needs to include sub-extensions to define OAuth2 endpoints but there are none"
                        )

                # fallback to old extension URLs
                elif (
                    "http://fhir-registry.smarthealthit.org/StructureDefinition/oauth-uris#register"
                    == e.url
                ):
                    state["registration_uri"] = e.valueUri
                elif (
                    "http://fhir-registry.smarthealthit.org/StructureDefinition/oauth-uris#authorize"
                    == e.url
                ):
                    state["authorize_uri"] = e.valueUri
                elif (
                    "http://fhir-registry.smarthealthit.org/StructureDefinition/oauth-uris#token"
                    == e.url
                ):
                    state["token_uri"] = e.valueUri

            if "authorize_uri" in state or (
                "token_uri" in state and "jwt_token" in state
            ):
                auth_type = "oauth2"

        # Fallback: if CapabilityStatement had no security block (or no OAuth
        # extensions), try .well-known/smart-configuration before giving up.
        # Some FHIR servers (e.g. Elevance Health) don't advertise OAuth in
        # their CapabilityStatement but do support it via .well-known.
        if auth_type is None and state and state.get("aud"):
            auth_type = cls._try_well_known_discovery(state)

        return cls.create(auth_type, state=state)

    @classmethod
    def _try_well_known_discovery(cls, state):
        """Try to discover OAuth endpoints from .well-known/smart-configuration.

        Called as a fallback when the CapabilityStatement has no security block.
        Some FHIR servers (e.g. Elevance Health) advertise OAuth via
        .well-known but not in their CapabilityStatement.

        :param state: A settings/state dictionary (must contain 'aud')
        :returns: 'oauth2' if discovery succeeds, None otherwise

        Note: This uses requests.get() directly rather than server.session
        because no server instance is available at this point in the flow.
        This means the request won't inherit proxy, cert bundle, or retry
        config from the server session.
        """
        aud = state["aud"]
        well_known_url = aud.rstrip("/") + "/.well-known/smart-configuration"

        try:
            resp = requests.get(
                well_known_url,
                headers={"Accept": "application/json"},
                timeout=10,
            )
            resp.raise_for_status()
            wk = resp.json()
        except Exception as e:
            logger.info(f"SMART AUTH: .well-known discovery failed for {aud}: {e}")
            return None

        authorize_uri = wk.get("authorization_endpoint")
        token_uri = wk.get("token_endpoint")

        if authorize_uri and token_uri:
            state["authorize_uri"] = authorize_uri
            state["token_uri"] = token_uri
            if "registration_endpoint" in wk:
                state["registration_uri"] = wk["registration_endpoint"]
            # Cache the full .well-known response so _authorize_params()
            # can reuse it for PKCE discovery without a second fetch.
            state["well_known_config"] = wk
            logger.info(f"SMART AUTH: Discovered OAuth endpoints via .well-known for {aud}")
            return "oauth2"

        logger.debug(f"SMART AUTH: .well-known for {aud} missing authorize/token endpoints")
        return None

    @classmethod
    def create(cls, auth_type, state=None):
        """Factory method to create the correct subclass for the given
        authorization type."""
        if not auth_type:
            auth_type = "none"
        if auth_type in FHIRAuth.auth_classes:
            klass = FHIRAuth.auth_classes[auth_type]
            return klass(state=state)
        raise Exception(f'No class registered for authorization type "{auth_type}"')

    def __init__(self, state=None):
        self.app_id = None
        if state is not None:
            self.from_state(state)

    @property
    def ready(self):
        """Indicates whether the authorization part is ready to make
        resource requests."""
        return True

    def reset(self):
        pass

    def can_sign_headers(self):
        return False

    def authorize_uri(self, server):
        """Return the authorize URL to use, if any."""
        return None

    def handle_callback(self, url, server):
        """Return the launch context."""
        raise Exception(f"{self} cannot handle callback URL")

    def reauthorize(self):
        """Perform a re-authorization of some form.

        :returns: The launch context dictionary or None on failure
        """
        return None

    def registration(self, server):
        return None
    
    # MARK: State

    @property
    def state(self):
        return {
            "app_id": self.app_id,
        }

    def from_state(self, state):
        """Update ivars from given state information."""
        assert state
        self.app_id = state.get("app_id") or self.app_id


class FHIROAuth2Auth(FHIRAuth):
    """OAuth2 handling class for FHIR servers."""

    auth_type = "oauth2"

    def __init__(self, state=None):
        self.aud = None
        self._registration_uri = None
        self._authorize_uri = None
        self._redirect_uri = None
        self._token_uri = None

        self.auth_state = None
        self.app_secret = None
        self.access_token = None
        self.refresh_token = None
        self.expires_at = None
        self.refresh_expires_in = None
        self.jwt_token = None

        self.key_id = None
        self.client_id = None
        self.private_key = None
        self.public_key = None

        self.code_verifier = None
        self.code_challenge = None
        self._well_known_config = None

        super(FHIROAuth2Auth, self).__init__(state=state)

    @property
    def ready(self):
        if self.expires_at and self.expires_at < datetime.now():
            self.reset()
        return True if self.access_token else False

    def reset(self):
        super(FHIROAuth2Auth, self).reset()
        self.access_token = None
        self.auth_state = None
        self.code_verifier = None

    # MARK: Signing/Authorizing Request Headers

    def can_sign_headers(self):
        return True if self.access_token is not None else False

    def signed_headers(self, headers):
        """Returns updated HTTP request headers, if possible, raises if there
        is no access_token.
        """
        if not self.can_sign_headers():
            raise Exception("Cannot sign headers since I have no access token")

        if headers is None:
            headers = {}
        headers["Authorization"] = f"Bearer {self.access_token}"

        return headers

    # MARK: OAuth2 Flow

    def authorize_uri(self, server):
        """The URL to authorize against. The `server` param is supplied so
        that the server can be informed of state changes that need to be
        stored.
        """
        auth_params = self._authorize_params(server)
        logger.debug(
            f"SMART AUTH: Will use parameters for `authorize_uri`: {auth_params}"
        )

        # the authorize uri may have params, make sure to not lose them
        parts = list(urlparse.urlsplit(self._authorize_uri))
        if len(parts[3]) > 0:
            args = urlparse.parse_qs(parts[3])
            args.update(auth_params)
            auth_params = args
        parts[3] = urlencode(auth_params, doseq=True)

        return urlparse.urlunsplit(parts)
    
    def _supports_pkce_s256(self, smart_configuration):
        return (smart_configuration 
            and 'code_challenge_methods_supported' in smart_configuration
            and 'S256' in smart_configuration['code_challenge_methods_supported'])

    
    def _authorize_params(self, server):
        """The URL parameters to use when requesting a token code."""
        if server is None:
            raise Exception("Cannot create an authorize-uri without server instance")
        if self.auth_state is None:
            self.auth_state = str(uuid.uuid4())
            server.should_save_state()

        params = {
            "response_type": "code",
            "client_id": self.app_id,
            "redirect_uri": self._redirect_uri,
            "scope": server.desired_scope,
            "aud": self.aud,
            "state": self.auth_state,
        }
        if server.launch_token is not None:
            params['launch'] = server.launch_token

        # Use cached .well-known config from discovery if available,
        # otherwise fetch it fresh.
        if self._well_known_config is not None:
            smart_configuration = self._well_known_config
        else:
            try:
                smart_configuration_url = self.aud
                if self.aud.endswith('/'):
                    smart_configuration_url = self.aud[:-1]

                smart_configuration_url += '/.well-known/smart-configuration'
                response = server.request_data(smart_configuration_url)

                smart_configuration = json.loads(response.decode('utf-8'))
            except (ValueError, json.JSONDecodeError) as e:
                logger.warning(f"Failed to parse SMART configuration: {e}")
                smart_configuration = None
            except Exception as e:
                logger.warning(f"Failed to fetch SMART configuration: {e}")
                smart_configuration = None

        if self._supports_pkce_s256(smart_configuration):
            challenge = generate_pkce_challenge()

            self.code_verifier = challenge['code_verifier']
            self.code_challenge = challenge['code_challenge']

            params['code_challenge'] = challenge['code_challenge']
            params['code_challenge_method'] = 'S256'

        server.should_save_state()

        return params

    def handle_callback(self, url, server):
        """Verify OAuth2 callback URL and exchange the code, if everything
        goes well, for an access token.

        :param str url: The callback/redirect URL to handle
        :param server: The Server instance to use
        :returns: The launch context dictionary
        """
        logger.debug("SMART AUTH: Handling callback URL")
        if url is None:
            raise Exception("No callback URL received")
        try:
            args = dict(urlparse.parse_qsl(urlparse.urlsplit(url)[3]))
        except Exception as e:
            raise Exception(f"Invalid callback URL: {e}")

        # verify response
        err = self.extract_oauth_error(args)
        if err is not None:
            raise Exception(err)

        stt = args.get("state")
        if stt is None or self.auth_state != stt:
            raise Exception(
                f"Invalid state, will not use this code. Have: {stt}, want: {self.auth_state}"
            )

        code = args.get("code")
        if code is None:
            raise Exception("Did not receive a code, only have: {0}".format(', '.join(args.keys())))

        stored_state = server.load_state(auth_state=stt)
        if stored_state is not None:
            self.from_state(stored_state)
        # exchange code for token
        exchange = self._code_exchange_params(code)
        return self._request_access_token(server, exchange)

    def _code_exchange_params(self, code):
        """These parameters are used by to exchange the given code for an
        access token.
        """
        params = {
            # 'client_id': self.app_id,         # Its being dynamically added only for epic
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': self._redirect_uri,
            'state': self.auth_state,
        }

        if self.code_verifier is not None:
            params['code_verifier'] = self.code_verifier

        return params

    def _request_access_token(self, server, params):
        """Requests an access token from the instance's server via a form POST
        request, remembers the token (and patient id if there is one) or
        raises an Exception.

        :returns: A dictionary with launch params
        """
        if server is None:
            raise Exception("I need a server to request an access token")

        logger.debug(f"SMART AUTH: Requesting access token from {self._token_uri}")
        auth = None
        if self.app_secret:
            auth = (self.app_id, self.app_secret)
        ret_params = server.post_as_form(self._token_uri, params, auth).json()

        processed_params = self._handle_token_params(ret_params)

        refresh_token = params.get('refresh_token')
        if not self.refresh_token and refresh_token:
            self.refresh_token = refresh_token

        logger.debug("SMART AUTH: Received access token: {0}, refresh token: {1}"
                     .format(self.access_token is not None, self.refresh_token is not None))

        return processed_params
    
    def _request_access_token_with_client_id(self, server, token_expiry_seconds=300):
        now_in_seconds = int(datetime.now(timezone.utc).timestamp())

        future_time_expiry = token_expiry_seconds

        claim = {
            'iss': self.client_id,
            'sub': self.client_id,
            "aud": self._token_uri,
            'jti': str(uuid.uuid4()),
            'exp': now_in_seconds + future_time_expiry,
            'nbf': now_in_seconds,
            'iat': now_in_seconds,
        }

        jwt_headers = {
            "alg": "RS384",
            "typ": "JWT",
            "kid": self.key_id,
        }

        signed_jwt = jwt.encode(
            headers=jwt_headers,
            payload=claim,
            key=self.private_key,
            algorithm="RS384"
        )

        # Prepare the access token request
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
        }
        payload = {
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "client_id": self.client_id,
            "assertion": signed_jwt,
        }
        if server.desired_scope:
            payload["scope"] = server.desired_scope

        res = server.session.post(self._token_uri, headers=headers, data=payload)
        server.raise_for_status(res)

        ret_params = res.json()

        processed_params = self._handle_token_params(ret_params)

        logger.debug("SMART AUTH: Received access token: {0}".format(self.access_token is not None))

        return processed_params

    def _handle_token_params(self, ret_params):
        self.access_token = ret_params.get('access_token')
        if self.access_token is None:
            raise Exception("No access token received")
        del ret_params['access_token']

        if 'expires_in' in ret_params:
            expires_in = int(ret_params['expires_in'])
            self.expires_at = datetime.now() + timedelta(seconds=expires_in)
            del ret_params['expires_in']

        if 'refresh_expires_in' in ret_params:
            self.refresh_expires_in = int(ret_params['refresh_expires_in'])
            del ret_params['refresh_expires_in']

        # The refresh token issued by the authorization server. If present, the
        # app should discard any previous refresh_token associated with this
        # launch, replacing it with this new value.
        if 'refresh_token' in ret_params:
            refresh_token = ret_params.get('refresh_token')
            if refresh_token is not None:
                self.refresh_token = refresh_token
            del ret_params['refresh_token']

        return ret_params

    
    # MARK: Authorization

    def authorize(self, server):
        """Perform authorization on behalf of a system.

        :param server: The Server instance to use
        """
        logger.debug("SMART AUTH: Get access token")
        token_params = self._token_params(server)
        return self._request_access_token(server, token_params)

    def _token_params(self, server):
        """The URL parameters to use when requesting access token."""
        if server is None:
            raise Exception("Cannot get token params without server instance")

        params = {
            "grant_type": "client_credentials",
            "scope": server.desired_scope,
        }

        if self.jwt_token:
            params["client_assertion_type"] = (
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            )
            params["client_assertion"] = self.jwt_token
        return params

    # MARK: Reauthorization

    def reauthorize(self, server):
        """Perform reauthorization.

        :param server: The Server instance to use
        :returns: The launch context dictionary, or None on failure
        """
        if self.refresh_token is not None:
            logger.debug("SMART AUTH: Refreshing token using refresh token")
            reauth = self._reauthorize_params()
            return self._request_access_token(server, reauth)

        if self.client_id is not None:
            logger.debug("SMART AUTH: Refreshing token using dynamic client id")
            return self._request_access_token_with_client_id(server)

        logger.debug("SMART AUTH: Cannot reauthorize without refresh token")
        return None
    
    def _reauthorize_params(self):
        """Parameters to be used in a reauthorize request."""
        if self.refresh_token is None:
            raise Exception(
                "Cannot produce reauthorize parameters without refresh token"
            )
        return {
            # 'client_id': self.app_id,         # Its being dynamically added only for epic
            #'client_secret': None,             # we don't use it
            "grant_type": "refresh_token",
            "refresh_token": self.refresh_token,
        }

    def registration(self, server):
        if self.public_key is None:
            raise ValueError("Public key must be set before registration")

        public_key_pem = self.public_key.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo,  # Standard format
        )
        alg = RSAAlgorithm(hashes.SHA384)
        key = alg.prepare_key(public_key_pem)

        # Export the public key in JWK format
        public_key_jwk = json.loads(RSAAlgorithm.to_jwk(key))

        # Prepare the registration request
        request_body = {
            "software_id": self.app_id,
            "jwks": {
                "keys": [dict(
                    **public_key_jwk,
                    kid=self.key_id
                )],
            },
        }

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.access_token}",
        }
        res = server.session.post(self._registration_uri, headers=headers, json=request_body)
        server.raise_for_status(res)
        return res.json()
    
    
    # MARK: State

    @property
    def state(self):
        s = super(FHIROAuth2Auth, self).state
        s["aud"] = self.aud
        s["registration_uri"] = self._registration_uri
        s["authorize_uri"] = self._authorize_uri
        s["redirect_uri"] = self._redirect_uri
        s["token_uri"] = self._token_uri
        if self.auth_state is not None:
            s["auth_state"] = self.auth_state
        if self.app_secret is not None:
            s["app_secret"] = self.app_secret
        if self.access_token is not None:
            s["access_token"] = self.access_token
        if self.refresh_token is not None:
            s['refresh_token'] = self.refresh_token

        if self.code_verifier is not None:
            s['code_verifier'] = self.code_verifier
        if self.code_challenge is not None:
            s['code_challenge'] = self.code_challenge

        return s
    
    def from_state(self, state):
        """ Update ivars from given state information.
        """
        super(FHIROAuth2Auth, self).from_state(state)
        self.aud = state.get('aud') or self.aud
        self._registration_uri = state.get('registration_uri') or self._registration_uri
        self._authorize_uri = state.get('authorize_uri') or self._authorize_uri
        self._redirect_uri = state.get('redirect_uri') or self._redirect_uri
        self._token_uri = state.get('token_uri') or self._token_uri
        self.auth_state = state.get('auth_state') or self.auth_state
        self.app_secret = state.get('app_secret') or self.app_secret
        
        self.access_token = state.get('access_token') or self.access_token
        self.refresh_token = state.get('refresh_token') or self.refresh_token
        self.jwt_token = state.get('jwt_token') or self.jwt_token

        self.key_id = state.get('key_id') or self.key_id
        self.client_id = state.get('client_id') or self.client_id
        self.private_key = state.get('private_key') or self.private_key
        self.public_key = state.get('public_key') or self.public_key

        self.code_verifier = state.get('code_verifier') or self.code_verifier
        self.code_challenge = state.get('code_challenge') or self.code_challenge
        # _well_known_config is a transient in-memory cache populated at
        # initial creation via from_capability_security(). It is intentionally
        # NOT included in the state property (write side) so it won't be
        # serialized/persisted. On deserialization it will be None, and
        # _authorize_params() will fall back to fetching .well-known fresh.
        self._well_known_config = state.get('well_known_config') or self._well_known_config

    # MARK: Utilities

    def extract_oauth_error(self, args):
        """Check if an argument dictionary contains OAuth error information."""
        # "error_description" is optional, we prefer it if it's present
        if "error_description" in args:
            return args["error_description"].replace("+", " ")

        # the "error" response is required if there are errors, look for it
        if "error" in args:
            err_code = args["error"]
            if "invalid_request" == err_code:
                return "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed."
            if "unauthorized_client" == err_code:
                return "The client is not authorized to request an access token using this method."
            if "access_denied" == err_code:
                return "The resource owner or authorization server denied the request."
            if "unsupported_response_type" == err_code:
                return "The authorization server does not support obtaining an access token using this method."
            if "invalid_scope" == err_code:
                return "The requested scope is invalid, unknown, or malformed."
            if "server_error" == err_code:
                return "The authorization server encountered an unexpected condition that prevented it from fulfilling the request."
            if "temporarily_unavailable" == err_code:
                return "The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server."
            return f"Authorization error: {err_code}."

        return None


# register classes
FHIRAuth.register()
FHIROAuth2Auth.register()
