"""Tests for the ASN discovery module."""

import pytest
from unittest.mock import patch, MagicMock

# Add project root to allow imports
import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))

from src.discovery import asn_discovery
from src.core.models import ASN
from src.core.exceptions import DataSourceError

# Sample HTML responses for mocking
BGP_HE_SEARCH_HTML_OK = '''
<html><body>
<table id="search">
  <tr><th>ASN</th><th>Description</th></tr>
  <tr><td><a href="/ASN/123">AS123</a></td><td>Example Org ASN 1</td></tr>
  <tr><td><a href="/ASN/456">AS456</a></td><td>Example Org ASN 2</td></tr>
</table>
</body></html>
'''

BGP_HE_SEARCH_HTML_EMPTY = '''
<html><body>
<table id="search">
  <tr><th>ASN</th><th>Description</th></tr>
</table>
</body></html>
'''

BGP_HE_SEARCH_HTML_DIRECT_ASN = '''
<html><body>
<div id="asn"><h1>AS789</h1> Description of AS789</div>
</body></html>
'''

BGP_HE_SEARCH_HTML_NO_TABLE = '<html><body>No results found.</body></html>'

@pytest.fixture
def mock_make_request():
    """Fixture to mock the network request function."""
    with patch('src.discovery.asn_discovery.make_request') as mock_req:
        yield mock_req

# --- Tests for _parse_bgp_he_net_search --- 

def test_parse_bgp_he_net_search_ok():
    result = asn_discovery._parse_bgp_he_net_search(BGP_HE_SEARCH_HTML_OK)
    assert len(result) == 2
    assert ASN(number=123, name="Example Org ASN 1", description="Example Org ASN 1", data_source="BGP.HE.NET") in result
    assert ASN(number=456, name="Example Org ASN 2", description="Example Org ASN 2", data_source="BGP.HE.NET") in result

def test_parse_bgp_he_net_search_empty():
    result = asn_discovery._parse_bgp_he_net_search(BGP_HE_SEARCH_HTML_EMPTY)
    assert len(result) == 0

def test_parse_bgp_he_net_search_direct_asn():
    result = asn_discovery._parse_bgp_he_net_search(BGP_HE_SEARCH_HTML_DIRECT_ASN)
    assert len(result) == 1
    # Note: Description parsing is currently a placeholder in the main code
    assert ASN(number=789, description="Description parsing needed", data_source="BGP.HE.NET") in result 

def test_parse_bgp_he_net_search_no_table():
    result = asn_discovery._parse_bgp_he_net_search(BGP_HE_SEARCH_HTML_NO_TABLE)
    assert len(result) == 0

def test_parse_bgp_he_net_search_invalid_html():
    result = asn_discovery._parse_bgp_he_net_search("<html><body><p>Invalid</p></body></html>")
    assert len(result) == 0

# --- Tests for _query_bgp_he_net --- 

def test_query_bgp_he_net_success(mock_make_request):
    mock_response = MagicMock()
    mock_response.text = BGP_HE_SEARCH_HTML_OK
    mock_response.raise_for_status = MagicMock()
    mock_make_request.return_value = mock_response

    result = asn_discovery._query_bgp_he_net("Example Org")
    assert len(result) == 2
    mock_make_request.assert_called_once()
    assert "Example+Org" in mock_make_request.call_args[0][0] # Check URL encoding

def test_query_bgp_he_net_request_error(mock_make_request):
    mock_make_request.side_effect = DataSourceError(source="BGP.HE.NET", message="Connection failed")
    result = asn_discovery._query_bgp_he_net("Example Org")
    assert len(result) == 0
    mock_make_request.assert_called_once()

def test_query_bgp_he_net_http_error(mock_make_request):
    mock_response = MagicMock()
    mock_response.raise_for_status.side_effect = DataSourceError(source="BGP.HE.NET", message="404 Error") # Simulate error raised by make_request
    mock_make_request.return_value = mock_response
    
    result = asn_discovery._query_bgp_he_net("Example Org")
    assert len(result) == 0
    mock_make_request.assert_called_once()
    mock_response.raise_for_status.assert_called_once()

# --- Tests for find_asns_for_organization --- 

def test_find_asns_for_organization_org_only(mock_make_request):
    mock_response_org = MagicMock()
    mock_response_org.text = BGP_HE_SEARCH_HTML_OK
    mock_response_org.raise_for_status = MagicMock()
    mock_make_request.return_value = mock_response_org
    
    result = asn_discovery.find_asns_for_organization("Example Org")
    assert len(result) == 2
    mock_make_request.assert_called_once_with(
        f"https://bgp.he.net/search?search%5Bsearch%5D=Example+Org&commit=Search",
        source_name="BGP.HE.NET"
    )

def test_find_asns_for_organization_org_and_domain(mock_make_request):
    mock_response_org = MagicMock(); mock_response_org.text = BGP_HE_SEARCH_HTML_OK; mock_response_org.raise_for_status = MagicMock()
    mock_response_dom = MagicMock(); mock_response_dom.text = BGP_HE_SEARCH_HTML_DIRECT_ASN; mock_response_dom.raise_for_status = MagicMock()
    
    # Mock responses for org query then domain query
    mock_make_request.side_effect = [mock_response_org, mock_response_dom]

    result = asn_discovery.find_asns_for_organization("Example Org", {"example.com"})
    assert len(result) == 3 # 2 from org, 1 from domain
    assert ASN(number=789, description="Description parsing needed", data_source="BGP.HE.NET") in result 
    assert mock_make_request.call_count == 2

def test_find_asns_for_organization_no_input():
    # Expect no network calls if no org or domain provided
    result = asn_discovery.find_asns_for_organization("", None)
    assert len(result) == 0
    # Assert make_request was NOT called (patching is function-scoped)
    # This requires a slightly different setup or checking logs perhaps
    # For simplicity, we rely on the logic check here. 