import unittest
from pathlib import Path

from deep_tests.security_model import BoundaryViolation, normalize_relative_path, redact, validate_outbound_url


class CounterpartTipSecurityHardeningTests(unittest.TestCase):
    def test_mixed_and_double_encoded_traversal_is_rejected(self) -> None:
        for value in ("safe/%2e%2e/secret", "safe/%252e%252e/secret", "%2e%2e%2fsecret"):
            with self.subTest(value=value), self.assertRaises(BoundaryViolation):
                normalize_relative_path(value)

    def test_ssrf_authority_confusion_is_rejected(self) -> None:
        allowed = {"api.example.test"}
        for value in ("//api.example.test/path", "https://api.example.test@attacker.invalid/path", "https://api.example.test.attacker.invalid/path"):
            with self.subTest(value=value), self.assertRaises(BoundaryViolation):
                validate_outbound_url(value, allowed)

    def test_redaction_is_idempotent(self) -> None:
        secret = "gh" + "p_" + "A" * 32
        once = redact(f"Authorization: Bearer opaque {secret}")
        self.assertEqual(once, redact(once))
        self.assertNotIn(secret, once)

    def test_zed_pkg_test_script_keeps_discovery_and_verifier(self) -> None:
        text = Path(".zpkg.toml").read_text()
        self.assertIn("unittest discover", text)
        self.assertIn("verify_repository.py", text)


if __name__ == "__main__":
    unittest.main()
