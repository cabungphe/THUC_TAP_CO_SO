import io
import json
import unittest
import urllib.error
from unittest.mock import MagicMock, patch

from agent2.llm import LLMError, OpenAICompatibleClient


class LLMClientTests(unittest.TestCase):
    def setUp(self):
        self.client = OpenAICompatibleClient('test-key', 'https://api.cerebras.ai/v1', 'qwen-3.8-27b')

    @patch('agent2.llm.urllib.request.urlopen')
    def test_cloudflare_error_is_actionable_without_html(self, urlopen):
        urlopen.side_effect = urllib.error.HTTPError(
            'https://api.cerebras.ai/v1/chat/completions', 403, 'Forbidden',
            {'Content-Type': 'text/html', 'CF-Ray': 'test-ray-HKG'},
            io.BytesIO(b'<!DOCTYPE html><html><title>Attention Required! | Cloudflare</title></html>'),
        )
        with self.assertRaises(LLMError) as caught:
            self.client.complete([{'role': 'user', 'content': 'Reply OK.'}])
        message = str(caught.exception)
        self.assertIn('Cloudflare', message)
        self.assertIn('test-ray-HKG', message)
        self.assertIn('request content', message)
        self.assertNotIn('<html', message)
        self.assertEqual(urlopen.call_count, 1)

    @patch('agent2.llm.urllib.request.urlopen')
    def test_api_error_redacts_key(self, urlopen):
        urlopen.side_effect = urllib.error.HTTPError(
            'https://api.cerebras.ai/v1/chat/completions', 401, 'Unauthorized',
            {'Content-Type': 'application/json'}, io.BytesIO(b'{"message":"Invalid test-key"}'),
        )
        with self.assertRaises(LLMError) as caught:
            self.client.complete([{'role': 'user', 'content': 'Reply OK.'}])
        self.assertIn('401', str(caught.exception))
        self.assertNotIn('test-key', str(caught.exception))
        self.assertTrue(caught.exception.__suppress_context__)
        self.assertNotIn('test-key', repr(self.client))

    @patch('agent2.llm.urllib.request.urlopen')
    def test_network_error_redacts_key_in_exception(self, urlopen):
        urlopen.side_effect = urllib.error.URLError('Bearer test-key connection failed')
        with self.assertRaises(LLMError) as caught:
            self.client.complete([{'role': 'user', 'content': 'Reply OK.'}])
        self.assertNotIn('test-key', str(caught.exception))
        self.assertTrue(caught.exception.__suppress_context__)

    @patch('agent2.llm.urllib.request.urlopen')
    def test_connection_probe_uses_configured_model(self, urlopen):
        response = MagicMock()
        response.read.return_value = b'{"choices":[{"message":{"content":"OK"}}]}'
        urlopen.return_value.__enter__.return_value = response
        self.assertEqual(self.client.complete([{'role': 'user', 'content': 'Reply with OK only.'}]), 'OK')
        request = urlopen.call_args.args[0]
        self.assertEqual(request.full_url, 'https://api.cerebras.ai/v1/chat/completions')
        self.assertEqual(json.loads(request.data)['model'], 'qwen-3.8-27b')
