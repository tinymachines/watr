"""
Basic tests for WATR package
"""

import pytest

def test_watr_import():
    """Test that watr package can be imported"""
    try:
        import watr
        assert watr.__version__ == "1.0.0"
        print("✓ WATR package imported successfully")
    except ImportError as e:
        pytest.skip(f"WATR package not available: {e}")

def test_protocol_fallback():
    """Test Protocol class fallback behavior"""
    import watr
    
    # Should raise RuntimeError since C++ module not built
    with pytest.raises(RuntimeError, match="C\\+\\+ module not available"):
        watr.Protocol()
    print("✓ Protocol fallback working correctly")

if __name__ == "__main__":
    test_watr_import()
    test_protocol_fallback()
    print("✓ All basic tests passed!")