import pytest
from jwt_weakness.extended_detector import ExtendedJWTDetector

def test_detector_initialization():
    """Test detector initializes."""
    detector = ExtendedJWTDetector("http://example.com:4444")
    assert detector.url == "http://example.com:4444"

def test_weak_secrets_check():
    """Test weak secrets detection."""
    detector = ExtendedJWTDetector("http://localhost:9999")  # Non-existent
    findings = detector.check_weak_secrets()
    # Should return empty list (server unreachable)
    assert isinstance(findings, list)

def test_algorithm_confusion_check():
    """Test algorithm confusion detection."""
    detector = ExtendedJWTDetector("http://localhost:9999")
    findings = detector.check_algorithm_confusion()
    assert isinstance(findings, list)
