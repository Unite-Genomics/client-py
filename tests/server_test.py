import base64
import hashlib
import io
import json
import os
import shutil
import tempfile
import unittest
from urllib.parse import urlparse, parse_qs, urlencode

import requests
import responses

from fhirclient import server


class TestServer(unittest.TestCase):

    @staticmethod
    def copy_metadata(filename: str, tmpdir: str) -> None:
        shutil.copyfile(
            os.path.join(os.path.dirname(__file__), 'data', filename),
            os.path.join(tmpdir, 'metadata')
        )

    @staticmethod
    def create_server() -> server.FHIRServer:
        return server.FHIRServer(None, state={
            'base_uri': "https://example.invalid/",
            "auth_type": "oauth2",
            "auth": {
                "aud": "https://example.invalid/",
                "registration_uri": "https://example.invalid/o2/registration",
                "authorize_uri": "https://example.invalid/o2/authorize",
                "redirect_uri": "https://example.invalid/o2/redirect",
                "token_uri": "https://example.invalid/o2/token",
                "auth_state": "931f4c31-73e2-4c04-bf6b-b7c9800312ea",
                "app_secret": "my-secret",
                "access_token": "my-access-token",
                "refresh_token": "my-refresh-token",
            },
        })

    def testValidCapabilityStatement(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            self.copy_metadata('test_metadata_valid.json', tmpdir)
            mock = MockServer(tmpdir)
            mock.get_capability()
        
        self.assertIsNotNone(mock.auth._registration_uri)
        self.assertIsNotNone(mock.auth._authorize_uri)
        self.assertIsNotNone(mock.auth._token_uri)
    
    def testStateConservation(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            self.copy_metadata('test_metadata_valid.json', tmpdir)
            mock = MockServer(tmpdir)
            self.assertIsNotNone(mock.capabilityStatement)
        
        fhir = server.FHIRServer(None, state=mock.state)
        self.assertIsNotNone(fhir.auth._registration_uri)
        self.assertIsNotNone(fhir.auth._authorize_uri)
        self.assertIsNotNone(fhir.auth._token_uri)
    
    def testInvalidCapabilityStatement(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            self.copy_metadata('test_metadata_invalid.json', tmpdir)
            mock = MockServer(tmpdir)
            try:
                mock.get_capability()
                self.assertTrue(False, "Must have thrown exception")
            except Exception as e:
                self.assertEqual(4, len(e.errors))
                self.assertEqual("date:", str(e.errors[0])[:5])
                self.assertEqual("format:", str(e.errors[1])[:7])
                self.assertEqual("rest.0:", str(e.errors[2])[:7])
                self.assertEqual("operation.1:", str(e.errors[2].errors[0])[:12])
                self.assertEqual("definition:", str(e.errors[2].errors[0].errors[0])[:11])
                self.assertEqual("Wrong type <class 'dict'>", str(e.errors[2].errors[0].errors[0].errors[0])[:25])
                self.assertEqual("security:", str(e.errors[2].errors[1])[:9])
                self.assertEqual("service.0:", str(e.errors[2].errors[1].errors[0])[:10])
                self.assertEqual("coding.0:", str(e.errors[2].errors[1].errors[0].errors[0])[:9])
                self.assertEqual("Superfluous entry \"systems\"", str(e.errors[2].errors[1].errors[0].errors[0].errors[0])[:27])
                self.assertEqual("Superfluous entry \"formats\"", str(e.errors[3])[:27])

    @responses.activate
    def testRequestJson(self):
        fhir = self.create_server()
        fhir.prepare()

        bin1 = {"resourceType": "Binary", "id": "bin1"}
        mock = responses.add("GET", f"{fhir.base_uri}Binary/bin1", json=bin1)

        resp = fhir.request_json("Binary/bin1")
        self.assertEqual(resp, bin1)
        self.assertEqual(mock.calls[0].request.headers["Accept"], "application/fhir+json")
        self.assertEqual(mock.calls[0].request.headers["Accept-Charset"], "UTF-8")
        self.assertEqual(mock.calls[0].request.headers["Authorization"], "Bearer my-access-token")

        resp = fhir.request_json("Binary/bin1", nosign=True)
        self.assertEqual(resp, bin1)
        self.assertEqual(mock.calls[1].request.headers["Accept"], "application/fhir+json")
        self.assertEqual(mock.calls[1].request.headers["Accept-Charset"], "UTF-8")
        self.assertNotIn("Authorization", mock.calls[1].request.headers)

        self.assertEqual(mock.call_count, 2)

    @responses.activate
    def testDeleteJson(self):
        fhir = self.create_server()
        fhir.prepare()

        mock = responses.add("DELETE", f"{fhir.base_uri}Binary/bin1")

        resp = fhir.delete_json("Binary/bin1")
        self.assertIsInstance(resp, requests.Response)
        self.assertEqual(mock.calls[0].request.headers["Accept"], "application/fhir+json")
        self.assertEqual(mock.calls[0].request.headers["Accept-Charset"], "UTF-8")
        self.assertEqual(mock.calls[0].request.headers["Authorization"], "Bearer my-access-token")

        resp = fhir.delete_json("Binary/bin1", nosign=True)
        self.assertIsInstance(resp, requests.Response)
        self.assertEqual(mock.calls[1].request.headers["Accept"], "application/fhir+json")
        self.assertEqual(mock.calls[1].request.headers["Accept-Charset"], "UTF-8")
        self.assertNotIn("Authorization", mock.calls[1].request.headers)

        self.assertEqual(mock.call_count, 2)

    @responses.activate
    def test_pkce(self):
        fhir = self.create_server()
        state = fhir.state
        assert state["auth"].get("code_verifier") is None
        assert fhir.auth.code_verifier is None
        uri = fhir.authorize_uri
        assert fhir.auth.code_verifier is not None
        state = fhir.state
        assert state["auth"]["code_verifier"] == fhir.auth.code_verifier

        authorize_args = parse_qs(urlparse(uri).query)
        assert "code_challenge_method" in authorize_args
        assert authorize_args["code_challenge_method"][0] == "S256"
        assert "code_challenge" in authorize_args

        # check hash
        verifier_hash = hashlib.sha256(fhir.auth.code_verifier.encode()).digest()
        b64_hash = base64.urlsafe_b64encode(verifier_hash).decode().rstrip("=")
        assert authorize_args["code_challenge"][0] == b64_hash

        # check oauth callback
        mock = responses.add(
            "POST",
            fhir.auth._token_uri,
            json={
                "access_token": "xyz",
            },
        )

        callback_url = f"https://example.org/callback?" + urlencode(
            dict(code="abc123", state=fhir.auth.auth_state)
        )
        fhir.handle_callback(callback_url)
        assert mock.call_count == 1
        token_call = mock.calls[0]
        params = parse_qs(token_call.request.body)
        assert params["code"][0] == "abc123"
        assert params["code_verifier"][0] == fhir.auth.code_verifier


class MockServer(server.FHIRServer):
    """ Reads local files.
    """
    
    def __init__(self, tmpdir: str):
        super().__init__(None, base_uri='https://fhir.smarthealthit.org')
        self.directory = tmpdir
    
    def request_json(self, path, nosign=False):
        assert path
        with io.open(os.path.join(self.directory, path), encoding='utf-8') as handle:
            return json.load(handle)
