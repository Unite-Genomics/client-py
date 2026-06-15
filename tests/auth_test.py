import json
import unittest
from unittest.mock import MagicMock, patch

from fhirclient.auth import FHIRAuth, FHIROAuth2Auth


class TestWellKnownDiscovery(unittest.TestCase):
    """Tests for .well-known/smart-configuration fallback discovery."""

    def _make_state(self, aud="https://fhir.example.com/api/v1/fhir"):
        return {
            "aud": aud,
            "app_id": "test-client-id",
            "app_secret": None,
            "redirect_uri": "https://example.com/callback",
            "jwt_token": None,
        }

    def _well_known_response(self, authorize=True, token=True, registration=False):
        wk = {}
        if authorize:
            wk["authorization_endpoint"] = "https://fhir.example.com/oauth2/authorize"
        if token:
            wk["token_endpoint"] = "https://fhir.example.com/oauth2/token"
        if registration:
            wk["registration_endpoint"] = "https://fhir.example.com/oauth2/register"
        wk["code_challenge_methods_supported"] = ["S256"]
        return wk

    @patch("fhirclient.auth._requests_lib.get")
    def test_discovery_creates_oauth2_when_security_is_none(self, mock_get):
        """When CapabilityStatement has no security, .well-known should be tried
        and FHIROAuth2Auth should be created."""
        mock_resp = MagicMock()
        mock_resp.json.return_value = self._well_known_response()
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        state = self._make_state()
        auth = FHIRAuth.from_capability_security(None, state)

        self.assertIsInstance(auth, FHIROAuth2Auth)
        self.assertEqual(state["authorize_uri"], "https://fhir.example.com/oauth2/authorize")
        self.assertEqual(state["token_uri"], "https://fhir.example.com/oauth2/token")
        mock_get.assert_called_once()

    @patch("fhirclient.auth._requests_lib.get")
    def test_discovery_includes_registration_uri(self, mock_get):
        """registration_endpoint from .well-known should be stored in state."""
        mock_resp = MagicMock()
        mock_resp.json.return_value = self._well_known_response(registration=True)
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        state = self._make_state()
        auth = FHIRAuth.from_capability_security(None, state)

        self.assertIsInstance(auth, FHIROAuth2Auth)
        self.assertEqual(state["registration_uri"], "https://fhir.example.com/oauth2/register")

    @patch("fhirclient.auth._requests_lib.get")
    def test_discovery_falls_back_to_basic_on_network_error(self, mock_get):
        """Network errors should not raise — fall back to basic FHIRAuth."""
        mock_get.side_effect = Exception("Connection refused")

        state = self._make_state()
        auth = FHIRAuth.from_capability_security(None, state)

        self.assertNotIsInstance(auth, FHIROAuth2Auth)
        self.assertEqual(auth.auth_type, "none")

    @patch("fhirclient.auth._requests_lib.get")
    def test_discovery_falls_back_when_missing_endpoints(self, mock_get):
        """If .well-known response lacks authorize or token, fall back."""
        mock_resp = MagicMock()
        mock_resp.json.return_value = self._well_known_response(authorize=True, token=False)
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        state = self._make_state()
        auth = FHIRAuth.from_capability_security(None, state)

        self.assertNotIsInstance(auth, FHIROAuth2Auth)

    @patch("fhirclient.auth._requests_lib.get")
    def test_discovery_falls_back_on_http_error(self, mock_get):
        """HTTP 404 from .well-known should not raise — fall back."""
        import requests

        mock_get.side_effect = requests.HTTPError("404 Not Found")

        state = self._make_state()
        auth = FHIRAuth.from_capability_security(None, state)

        self.assertNotIsInstance(auth, FHIROAuth2Auth)

    @patch("fhirclient.auth._requests_lib.get")
    def test_discovery_caches_well_known_config(self, mock_get):
        """The .well-known response should be cached in state for reuse."""
        wk = self._well_known_response()
        mock_resp = MagicMock()
        mock_resp.json.return_value = wk
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        state = self._make_state()
        FHIRAuth.from_capability_security(None, state)

        self.assertEqual(state["well_known_config"], wk)

    @patch("fhirclient.auth._requests_lib.get")
    def test_discovery_not_called_when_security_has_oauth(self, mock_get):
        """When CapabilityStatement has OAuth extensions, .well-known should NOT be fetched."""
        security = MagicMock()
        ext_inner = MagicMock()
        ext_inner.url = "token"
        ext_inner.valueUri = "https://fhir.example.com/oauth2/token"
        ext_inner2 = MagicMock()
        ext_inner2.url = "authorize"
        ext_inner2.valueUri = "https://fhir.example.com/oauth2/authorize"

        ext = MagicMock()
        ext.url = "http://fhir-registry.smarthealthit.org/StructureDefinition/oauth-uris"
        ext.extension = [ext_inner, ext_inner2]
        security.extension = [ext]

        state = self._make_state()
        auth = FHIRAuth.from_capability_security(security, state)

        self.assertIsInstance(auth, FHIROAuth2Auth)
        mock_get.assert_not_called()

    def test_discovery_skipped_when_no_aud(self):
        """If state has no aud, .well-known should not be attempted."""
        state = {"app_id": "test"}
        auth = FHIRAuth.from_capability_security(None, state)

        self.assertNotIsInstance(auth, FHIROAuth2Auth)

    @patch("fhirclient.auth._requests_lib.get")
    def test_discovery_strips_trailing_slash_from_aud(self, mock_get):
        """Trailing slash on aud should not produce double-slash in .well-known URL."""
        mock_resp = MagicMock()
        mock_resp.json.return_value = self._well_known_response()
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        state = self._make_state(aud="https://fhir.example.com/api/v1/fhir/")
        FHIRAuth.from_capability_security(None, state)

        called_url = mock_get.call_args[0][0]
        self.assertEqual(
            called_url,
            "https://fhir.example.com/api/v1/fhir/.well-known/smart-configuration",
        )
        self.assertNotIn("//.", called_url)


class TestWellKnownCacheInAuthorizeParams(unittest.TestCase):
    """Tests that cached .well-known config is reused in _authorize_params."""

    @patch("fhirclient.auth._requests_lib.get")
    def test_cached_config_prevents_second_fetch(self, mock_get):
        """When _well_known_config is set, _authorize_params should not re-fetch."""
        wk = {
            "authorization_endpoint": "https://fhir.example.com/oauth2/authorize",
            "token_endpoint": "https://fhir.example.com/oauth2/token",
            "code_challenge_methods_supported": ["S256"],
        }
        mock_resp = MagicMock()
        mock_resp.json.return_value = wk
        mock_resp.raise_for_status = MagicMock()
        mock_get.return_value = mock_resp

        state = self._make_state()
        auth = FHIRAuth.from_capability_security(None, state)

        # Reset mock to track only _authorize_params calls
        mock_get.reset_mock()

        server = MagicMock()
        server.desired_scope = "patient/*.read"
        server.launch_token = None

        auth._authorize_params(server)

        # .well-known should NOT have been fetched again
        mock_get.assert_not_called()
        server.request_data.assert_not_called()

    def _make_state(self, aud="https://fhir.example.com/api/v1/fhir"):
        return {
            "aud": aud,
            "app_id": "test-client-id",
            "app_secret": None,
            "redirect_uri": "https://example.com/callback",
            "jwt_token": None,
        }


if __name__ == "__main__":
    unittest.main()
