"""
Test suite for WATR protocol
"""

import pytest
from watr.scapy_layers import WATRHeader, WATRPayload
from scapy.all import *

def test_watr_header_creation():
    """Test WATRHeader packet creation"""
    header = WATRHeader(type=0x1234, length=8)
    assert header.type == 0x1234
    assert header.length == 8

def test_watr_packet_with_payload():
    """Test complete WATR packet with payload"""
    packet = WATRHeader(type=0x1) / WATRPayload(data="Hello WATR")
    
    # Build the packet
    built = bytes(packet)
    assert len(built) > 8  # Header + payload
    
    # Parse it back
    parsed = WATRHeader(built)
    assert parsed.type == 0x1

def test_watr_length_auto_calculation():
    """Test automatic length calculation"""
    packet = WATRHeader(type=0x1) / WATRPayload(data="test")
    built = bytes(packet)
    
    # Length should be auto-calculated
    parsed = WATRHeader(built)
    assert parsed.length == 4  # len("test")

if __name__ == "__main__":
    pytest.main([__file__])