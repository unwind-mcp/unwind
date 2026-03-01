"""Tests for Cognitive Load Offset — ERT calculation."""

import unittest

from cadence.engine.cognitive_load import CognitiveLoadResult, compute_ert


class TestCognitiveLoad(unittest.TestCase):
    """Test ERT computation with cognitive load offset."""

    def test_below_threshold_no_adjustment(self):
        result = compute_ert(300.0, last_out_tokens=100, token_threshold=200)
        self.assertEqual(result.ert_seconds, 300.0)
        self.assertEqual(result.load_multiplier, 1.0)

    def test_at_threshold_no_adjustment(self):
        result = compute_ert(300.0, last_out_tokens=200, token_threshold=200)
        self.assertEqual(result.ert_seconds, 300.0)
        self.assertEqual(result.load_multiplier, 1.0)

    def test_2x_threshold(self):
        """400 tokens / 200 threshold → log2(2) = 1 → multiplier 2.0."""
        result = compute_ert(300.0, last_out_tokens=400, token_threshold=200)
        self.assertAlmostEqual(result.load_multiplier, 2.0, places=3)
        self.assertAlmostEqual(result.ert_seconds, 600.0, places=0)

    def test_4x_threshold(self):
        """800 tokens / 200 threshold → log2(4) = 2 → multiplier 3.0."""
        result = compute_ert(300.0, last_out_tokens=800, token_threshold=200)
        self.assertAlmostEqual(result.load_multiplier, 3.0, places=3)
        self.assertAlmostEqual(result.ert_seconds, 900.0, places=0)

    def test_8x_threshold(self):
        """1600 tokens / 200 threshold → log2(8) = 3 → multiplier 4.0."""
        result = compute_ert(300.0, last_out_tokens=1600, token_threshold=200)
        self.assertAlmostEqual(result.load_multiplier, 4.0, places=3)
        self.assertAlmostEqual(result.ert_seconds, 1200.0, places=0)

    def test_zero_tokens(self):
        result = compute_ert(300.0, last_out_tokens=0, token_threshold=200)
        self.assertEqual(result.ert_seconds, 300.0)
        self.assertEqual(result.load_multiplier, 1.0)

    def test_zero_threshold_no_crash(self):
        result = compute_ert(300.0, last_out_tokens=500, token_threshold=0)
        self.assertEqual(result.ert_seconds, 300.0)
        self.assertEqual(result.load_multiplier, 1.0)

    def test_result_fields(self):
        result = compute_ert(120.0, last_out_tokens=400, token_threshold=200)
        self.assertEqual(result.base_ema_seconds, 120.0)
        self.assertEqual(result.last_out_tokens, 400)
        self.assertIsInstance(result, CognitiveLoadResult)


if __name__ == "__main__":
    unittest.main()
