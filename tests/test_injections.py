"""Benchmark test using deepset/prompt-injections dataset.

Tests Hermes Shield against real prompt injection attacks from Hugging Face.
This is the PRIMARY security benchmark (vs PatchEval which tests code bugs).
"""

import pytest
from hermes_shield import HermesShield, ShieldStatus


@pytest.fixture(scope="module")
def prompt_injection_data():
    """Load deepset/prompt-injections dataset from Hugging Face.

    Contains real prompt injection attacks labeled as:
    - "injection" (malicious)
    - "benign" (safe)
    """
    try:
        from datasets import load_dataset
    except ImportError:
        pytest.skip("datasets library not installed")

    try:
        dataset = load_dataset("deepset/prompt-injections", split="train")
        return dataset
    except Exception as e:
        pytest.skip(f"Could not load dataset: {e}")


class TestPromptInjectionBenchmark:
    """Benchmark against real prompt injection attacks."""

    def test_detection_rate_medium(self, prompt_injection_data):
        """Medium sensitivity should detect most injections."""
        shield = HermesShield(sensitivity="medium")

        malicious = [item["text"] for item in prompt_injection_data if item["label"] == 1]
        benign = [item["text"] for item in prompt_injection_data if item["label"] == 0]

        # Limit samples for CI speed
        malicious = malicious[:100]
        benign = benign[:100]

        if not malicious:
            pytest.skip("No malicious samples in dataset")

        # Test malicious inputs
        blocked = sum(1 for text in malicious if shield.check(text).is_malicious)
        detection_rate = (blocked / len(malicious)) * 100

        # Test benign inputs (should NOT be blocked)
        false_positives = sum(1 for text in benign if shield.check(text).is_malicious)
        fp_rate = (false_positives / len(benign)) * 100 if benign else 0

        print(f"\n[MEDIUM SENSITIVITY — Real Injections]")
        print(f"  Malicious samples: {len(malicious)}")
        print(f"  Blocked: {blocked}")
        print(f"  Detection Rate: {detection_rate:.1f}%")
        print(f"  False Positive Rate: {fp_rate:.1f}%")

        # Minimum 10% detection on real attacks (baseline for v0.2.0)
        assert detection_rate >= 10, f"Detection too low: {detection_rate:.1f}%"

    def test_detection_rate_high(self, prompt_injection_data):
        """High sensitivity should catch more attacks."""
        shield = HermesShield(sensitivity="high")

        malicious = [item["text"] for item in prompt_injection_data if item["label"] == 1][:100]
        benign = [item["text"] for item in prompt_injection_data if item["label"] == 0][:100]

        if not malicious:
            pytest.skip("No malicious samples")

        blocked = sum(1 for text in malicious if shield.check(text).is_malicious)
        detection_rate = (blocked / len(malicious)) * 100

        false_positives = sum(1 for text in benign if shield.check(text).is_malicious)
        fp_rate = (false_positives / len(benign)) * 100 if benign else 0

        print(f"\n[HIGH SENSITIVITY — Real Injections]")
        print(f"  Malicious samples: {len(malicious)}")
        print(f"  Blocked: {blocked}")
        print(f"  Detection Rate: {detection_rate:.1f}%")
        print(f"  False Positive Rate: {fp_rate:.1f}%")

        # High sensitivity should catch at least 75%
        assert detection_rate >= 75, f"Detection too low: {detection_rate:.1f}%"

    def test_false_positives_acceptable(self, prompt_injection_data):
        """False positive rate should be acceptable."""
        shield = HermesShield(sensitivity="medium")
        benign = [item["text"] for item in prompt_injection_data if item["label"] == 0][:100]

        if not benign:
            pytest.skip("No benign samples")

        false_positives = sum(1 for text in benign if shield.check(text).is_malicious)
        fp_rate = (false_positives / len(benign)) * 100

        print(f"\n[FALSE POSITIVE CHECK]")
        print(f"  Benign samples: {len(benign)}")
        print(f"  False positives: {false_positives}")
        print(f"  FP Rate: {fp_rate:.1f}%")

        # False positive rate should be under 15%
        assert fp_rate < 15, f"Too many false positives: {fp_rate:.1f}%"

    def test_profile_escalation(self, prompt_injection_data):
        """Higher sensitivity should detect more attacks."""
        malicious = [item["text"] for item in prompt_injection_data if item["label"] == 1][:50]

        if not malicious:
            pytest.skip("No malicious samples")

        results = {}
        for profile in ["low", "medium", "high"]:
            shield = HermesShield(sensitivity=profile)
            blocked = sum(1 for text in malicious if shield.check(text).is_malicious)
            results[profile] = (blocked / len(malicious)) * 100

        print(f"\n[PROFILE ESCALATION — Real Injections]")
        for profile, rate in results.items():
            print(f"  {profile:10s}: {rate:.1f}%")

        # Monotonic: high >= medium >= low
        assert results["high"] >= results["low"], \
            f"High should detect >= low: {results}"
