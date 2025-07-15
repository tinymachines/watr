"""
Scapy layers for WATR custom protocol
"""

import struct
try:
    from scapy.packet import Packet
    from scapy.fields import XIntField, StrField
    from scapy.layers.l2 import Ether
except ImportError:
    # Fallback if scapy not available
    print("Warning: Scapy not available. Install scapy for full functionality.")

class WATRHeader(Packet):
    """WATR Protocol Header"""
    name = "WATRHeader"
    fields_desc = [
        XIntField("type", 0),
        XIntField("length", 0),
    ]
    
    def post_build(self, pkt, pay):
        if self.length == 0 and pay:
            self.length = len(pay)
            pkt = pkt[:4] + struct.pack("!I", self.length) + pkt[8:]
        return pkt + pay

class WATRPayload(Packet):
    """WATR Protocol Payload"""
    name = "WATRPayload"
    fields_desc = [
        StrField("data", "")
    ]

# Bind layers
try:
    from scapy.packet import bind_layers
    bind_layers(WATRHeader, WATRPayload)
except (ImportError, NameError):
    pass