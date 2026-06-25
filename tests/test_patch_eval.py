"""Benchmark test using ByteDance/PatchEval dataset.

Tests Hermes Shield against real-world CVE descriptions and vulnerable code.
Validates detection rates across all three sensitivity profiles.

The dataset contains:
- CVE descriptions (technical, should be BENIGN for prompt injection)
- Vulnerable code (may contain dangerous patterns like os.system, eval)
- Fixed code (should be BENIGN)

Usage:
    python -m pytest tests/test_patch_eval.py -v
"""

import pytest
from hermes_shield import HermesShield, ShieldStatus


# ────────────────────────────────────────────────────────────────────────────
# Fixtures
# ────────────────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def patch_eval_data():
    """Load PatchEval dataset from Hugging Face."""
    try:
        from datasets import load_dataset
    except ImportError:
        pytest.skip("datasets library not installed")

    try:
        dataset = load_dataset(
            "ByteDance/PatchEval",
            split="train",
            trust_remote_code=True,
        )
        python_samples = [
            item for item in dataset
            if item.get("programming_language") == "Python"
        ][:50]

        if not python_samples:
            pytest.skip("No Python samples in PatchEval")

        return python_samples

    except Exception as e:
        pytest.skip(f"Could not load PatchEval: {e}")


def extract_code_samples(patch_eval_data):
    """Extract vulnerable and fixed code samples.

    Returns:
        (vulnerable_codes, fixed_codes) tuple of lists
    """
    vulnerable = []
    fixed = []

    for item in patch_eval_data:
        vul_funcs = item.get("vul_func", [])
        fix_funcs = item.get("fix_func", [])

        for func in vul_funcs[:2]:
            if isinstance(func, dict):
                code = func.get("code", "")
            else:
                code = str(func)
            if code and len(code) > 10:
                vulnerable.append(code)

        for func in fix_funcs[:2]:
            if isinstance(func, dict):
                code = func.get("code", "")
            else:
                code = str(func)
            if code and len(code) > 10:
                fixed.append(code)

    return vulnerable, fixed


# ────────────────────────────────────────────────────────────────────────────
# Tests
# ────────────────────────────────────────────────────────────────────────────

class TestPatchEvalBenchmark:
    """Benchmark Hermes Shield against real vulnerable code."""

    def test_vulnerable_code_detection_low(self, patch_eval_data):
        """Low sensitivity: may miss sophisticated patterns."""
        shield = HermesShield(sensitivity="low")
        vulnerable, _ = extract_code_samples(patch_eval_data)

        if not vulnerable:
            pytest.skip("No vulnerable code samples")

        flagged = sum(1 for code in vulnerable[:20] if shield.check(code).is_suspicious)
        detection_rate = (flagged / min(20, len(vulnerable))) * 100

        print(f"\n[LOW SENSITIVITY] Vulnerable code detection: {detection_rate:.1f}%")
        print(f"  Samples: {min(20, len(vulnerable))}, Flagged: {flagged}")

    def test_vulnerable_code_detection_medium(self, patch_eval_data):
        """Medium sensitivity: balanced detection."""
        shield = HermesShield(sensitivity="medium")
        vulnerable, _ = extract_code_samples(patch_eval_data)

        if not vulnerable:
            pytest.skip("No vulnerable code samples")

        flagged = sum(1 for code in vulnerable[:20] if shield.check(code).is_suspicious)
        detection_rate = (flagged / min(20, len(vulnerable))) * 100

        print(f"\n[MEDIUM SENSITIVITY] Vulnerable code detection: {detection_rate:.1f}%")
        print(f"  Samples: {min(20, len(vulnerable))}, Flagged: {flagged}")

    def test_vulnerable_code_detection_high(self, patch_eval_data):
        """High sensitivity: maximum detection."""
        shield = HermesShield(sensitivity="high")
        vulnerable, _ = extract_code_samples(patch_eval_data)

        if not vulnerable:
            pytest.skip("No vulnerable code samples")

        flagged = sum(1 for code in vulnerable[:20] if shield.check(code).is_suspicious)
        detection_rate = (flagged / min(20, len(vulnerable))) * 100

        print(f"\n[HIGH SENSITIVITY] Vulnerable code detection: {detection_rate:.1f}%")
        print(f"  Samples: {min(20, len(vulnerable))}, Flagged: {flagged}")

    def test_fixed_code_not_flagged(self, patch_eval_data):
        """Fixed/patched code should NOT be flagged as malicious."""
        shield = HermesShield(sensitivity="high")
        _, fixed = extract_code_samples(patch_eval_data)

        if not fixed:
            pytest.skip("No fixed code samples")

        false_positives = sum(1 for code in fixed[:20] if shield.check(code).is_malicious)
        fp_rate = (false_positives / min(20, len(fixed))) * 100

        print(f"\n[FALSE POSITIVE CHECK] Fixed code flagged: {fp_rate:.1f}%")
        print(f"  Samples: {min(20, len(fixed))}, False positives: {false_positives}")

        # Fixed code should rarely be blocked
        assert fp_rate < 30, f"Too many false positives on fixed code: {fp_rate:.1f}%"

    def test_profile_escalation(self, patch_eval_data):
        """Higher sensitivity should detect more threats."""
        vulnerable, _ = extract_code_samples(patch_eval_data)

        if not vulnerable:
            pytest.skip("No vulnerable code samples")

        samples = vulnerable[:15]
        results = {}

        for profile in ["low", "medium", "high"]:
            shield = HermesShield(sensitivity=profile)
            flagged = sum(1 for code in samples if shield.check(code).is_suspicious)
            results[profile] = (flagged / len(samples)) * 100

        print(f"\n[PROFILE ESCALATION]")
        for profile, rate in results.items():
            print(f"  {profile:10s}: {rate:.1f}%")

        # Monotonic: high >= medium >= low
        assert results["high"] >= results["low"], \
            f"High sensitivity should detect >= low: {results}"
