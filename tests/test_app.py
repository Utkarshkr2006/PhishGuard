"""
PhishGuard 2.0 - Flask Application Integration Tests
Module: tests/test_app.py

Verifies Flask web endpoints, input validation, template rendering,
risk level output, error handling, and offline execution.
"""

import os
import sys
import pytest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.append(BASE_DIR)

from app import app

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_home_page_get(client):
    """Test 1: GET / returns 200 and renders analysis submission form."""
    response = client.get('/')
    assert response.status_code == 200
    assert b'PhishGuard' in response.data
    assert b'URL Threat Inspector' in response.data

def test_analyze_benign_url(client):
    """Test 2: POST /analyze with benign URL returns LOW risk level."""
    response = client.post('/analyze', data={'url': 'https://www.wikipedia.org'})
    assert response.status_code == 200
    html = response.data.decode('utf-8')
    assert 'LOW' in html
    assert 'wikipedia.org' in html
    assert 'Model signal' in html
    assert 'Traceback' not in html

def test_analyze_suspicious_url(client):
    """Test 3: POST /analyze with suspicious IP URL returns CRITICAL risk level."""
    response = client.post('/analyze', data={'url': 'http://192.168.1.100/admin/login'})
    assert response.status_code == 200
    html = response.data.decode('utf-8')
    assert 'CRITICAL' in html
    assert '192.168.1.100' in html
    assert 'IP address used directly as the domain' in html
    assert 'Traceback' not in html

def test_analyze_empty_url(client):
    """Test 4: POST /analyze with empty URL returns 400 validation error."""
    response = client.post('/analyze', data={'url': ''})
    assert response.status_code == 400
    html = response.data.decode('utf-8')
    assert 'Please enter a valid, non-empty URL string' in html

def test_analyze_whitespace_url(client):
    """Test 5: POST /analyze with whitespace-only URL returns 400 validation error."""
    response = client.post('/analyze', data={'url': '   \t\n  '})
    assert response.status_code == 400
    html = response.data.decode('utf-8')
    assert 'Please enter a valid, non-empty URL string' in html

def test_analyze_excessive_length_url(client):
    """Test 6: POST /analyze with >2048 length URL returns 400 validation error."""
    long_url = "https://example.com/" + ("a" * 2100)
    response = client.post('/analyze', data={'url': long_url})
    assert response.status_code == 400
    html = response.data.decode('utf-8')
    assert 'exceeds maximum length' in html

def test_debug_mode_is_disabled():
    """Test 7 (Security): Verify Flask debug mode is disabled by default."""
    assert app.config['DEBUG'] is False
    assert app.debug is False

def test_jinja_autoescape_prevents_xss(client):
    """Test 8 (Security): Verify submitted URLs with HTML tags are properly escaped."""
    xss_payload = 'https://example.com/<script>alert("xss")</script>'
    response = client.post('/analyze', data={'url': xss_payload})
    assert response.status_code == 200
    html = response.data.decode('utf-8')
    # Unescaped script tag should NOT be present in HTML body
    assert '<script>alert("xss")</script>' not in html
    # HTML-escaped version should be present
    assert '&lt;script&gt;alert(' in html or '&#34;xss&#34;' in html or '&quot;xss&quot;' in html

def test_internal_error_does_not_leak_stack_trace(client, monkeypatch):
    """Test 9 (Security): Verify 500 errors return a generic message without stack traces."""
    def mock_predict_failure(url):
        raise RuntimeError("SecretModelError: failed at /confidential/code/model.pkl")

    import app as app_module
    monkeypatch.setattr(app_module, 'predict_url', mock_predict_failure)

    response = client.post('/analyze', data={'url': 'https://example.com'})
    assert response.status_code == 500
    html = response.data.decode('utf-8')
    assert 'An internal analysis error occurred. Please try again.' in html
    assert 'SecretModelError' not in html
    assert '/confidential/code' not in html
    assert 'Traceback' not in html

if __name__ == '__main__':
    pytest.main(['-v', __file__])

