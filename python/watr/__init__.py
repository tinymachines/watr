"""
WATR - Custom Protocol Package

A Python package for custom protocol development using Scapy and C++ bindings.
"""

try:
    from .watr_core import Protocol
except ImportError:
    # Fallback if C++ module not built
    class Protocol:
        def __init__(self):
            raise RuntimeError("C++ module not available. Run cmake build first.")

__version__ = "1.0.0"
__all__ = ["Protocol"]