import unittest
from unittest.mock import patch, Mock
import json
import requests
from webhook_alerter import WebhookAlerter

class TestWebhookAlerter(unittest.TestCase):
    @patch('webhook_alerter.requests.post')
    def test_send_alert_success(self, mock_post):
        # Setup mock
        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        # Initialize alerter
        alerter = WebhookAlerter()
        
        # Test data
        severity = "HIGH"
        attack = "Flood"
        source = "192.168.1.100"
        details = {"packet_count": 500}

        # Call send_alert
        alerter.send_alert(severity, attack, source, details)

        # Assertions
        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args
        
        # Check URL
        self.assertEqual(args[0], alerter.webhook_url)
        
        # Check Headers
        self.assertIn('X-Auth-Key', kwargs['headers'])
        self.assertEqual(kwargs['headers']['X-Auth-Key'], alerter.auth_token)
        
        # Check JSON payload
        payload = kwargs['json']
        self.assertEqual(payload['severity'], severity)
        self.assertEqual(payload['attack'], attack)
        self.assertEqual(payload['source'], source)
        self.assertEqual(payload['details'], details)
        self.assertEqual(payload['message'], "") # Default empty message
        self.assertEqual(payload['packet_rate'], 500) # Extracted from packet_count

    @patch('webhook_alerter.requests.post')
    def test_send_alert_retry(self, mock_post):
        # Setup mock to fail first then succeed
        mock_post.side_effect = [
            requests.exceptions.ConnectionError("Connection failed"),
            Mock(status_code=200)
        ]
        
        alerter = WebhookAlerter()
        alerter.retry_delay = 0.1 # Speed up test
        
        alerter.send_alert("LOW", "Test", "1.1.1.1")
        
        self.assertEqual(mock_post.call_count, 2)

if __name__ == '__main__':
    unittest.main()
