"""Tests for Immutable Policy Source — hash-checked config loading.

Source: SENTINEL merged list § ADD NOW #3
Verifies config loading, hash verification, boundary enforcement,
reload rejection on tamper, and hash rotation.
"""

import json
import tempfile
import unittest
from pathlib import Path

from unwind.enforcement.policy_source import (
    ImmutablePolicySource,
    PolicyLoadResult,
    CONFIG_FILENAME,
    HASH_FILENAME,
)


class TestInitialLoad(unittest.TestCase):
    """Test first-time config loading."""

    def test_load_with_config_file(self):
        """Config file present → loads and records birth hash."""
        tmp = Path(tempfile.mkdtemp())
        unwind_home = tmp / ".unwind"
        unwind_home.mkdir()
        workspace = tmp / "workspace"
        workspace.mkdir()

        config_data = {"mode": "enforce", "max_tokens": 1000}
        (unwind_home / CONFIG_FILENAME).write_text(json.dumps(config_data))

        source = ImmutablePolicySource(unwind_home=unwind_home)
        result = source.initial_load(workspace_root=workspace)

        self.assertTrue(result.success)
        self.assertEqual(result.config_data, config_data)
        self.assertFalse(result.was_default)
        self.assertTrue(len(result.hash_hex) == 64)  # SHA-256 hex
        self.assertTrue((unwind_home / HASH_FILENAME).exists())
        self.assertIsNotNone(source.birth_hash)

    def test_load_no_config_file(self):
        """No config file → uses defaults, no hash file."""
        tmp = Path(tempfile.mkdtemp())
        unwind_home = tmp / ".unwind"
        unwind_home.mkdir()
        workspace = tmp / "workspace"
        workspace.mkdir()

        source = ImmutablePolicySource(unwind_home=unwind_home)
        result = source.initial_load(workspace_root=workspace)

        self.assertTrue(result.success)
        self.assertTrue(result.was_default)
        self.assertEqual(result.config_data, {})
        self.assertTrue(source.is_loaded)

    def test_load_invalid_json(self):
        """Invalid JSON → fails gracefully."""
        tmp = Path(tempfile.mkdtemp())
        unwind_home = tmp / ".unwind"
        unwind_home.mkdir()
        workspace = tmp / "workspace"
        workspace.mkdir()

        (unwind_home / CONFIG_FILENAME).write_text("not valid json {{{{")

        source = ImmutablePolicySource(unwind_home=unwind_home)
        result = source.initial_load(workspace_root=workspace)

        self.assertFalse(result.success)
        self.assertIn("PARSE_ERROR", result.error)

    def test_load_non_object_json(self):
        """JSON that is not an object → fails."""
        tmp = Path(tempfile.mkdtemp())
        unwind_home = tmp / ".unwind"
        unwind_home.mkdir()
        workspace = tmp / "workspace"
        workspace.mkdir()

        (unwind_home / CONFIG_FILENAME).write_text(json.dumps([1, 2, 3]))

        source = ImmutablePolicySource(unwind_home=unwind_home)
        result = source.initial_load(workspace_root=workspace)

        self.assertFalse(result.success)
        self.assertIn("INVALID", result.error)


class TestBoundaryEnforcement(unittest.TestCase):
    """Test that config inside workspace is rejected."""

    def test_config_inside_workspace_blocked(self):
        """Config file inside workspace directory → boundary violation."""
        tmp = Path(tempfile.mkdtemp())
        workspace = tmp / "workspace"
        workspace.mkdir()
        # Put unwind_home INSIDE workspace
        unwind_home = workspace / ".unwind"
        unwind_home.mkdir()

        config_data = {"mode": "enforce"}
        (unwind_home / CONFIG_FILENAME).write_text(json.dumps(config_data))

        source = ImmutablePolicySource(unwind_home=unwind_home)
        result = source.initial_load(workspace_root=workspace)

        self.assertFalse(result.success)
        self.assertIn("BOUNDARY_VIOLATION", result.error)

    def test_config_outside_workspace_ok(self):
        """Config file outside workspace → passes boundary check."""
        tmp = Path(tempfile.mkdtemp())
        unwind_home = tmp / ".unwind"
        unwind_home.mkdir()
        workspace = tmp / "workspace"
        workspace.mkdir()

        config_data = {"mode": "shadow"}
        (unwind_home / CONFIG_FILENAME).write_text(json.dumps(config_data))

        source = ImmutablePolicySource(unwind_home=unwind_home)
        result = source.initial_load(workspace_root=workspace)

        self.assertTrue(result.success)


class TestHashVerification(unittest.TestCase):
    """Test hash verification on subsequent loads."""

    def _setup_with_config(self):
        tmp = Path(tempfile.mkdtemp())
        unwind_home = tmp / ".unwind"
        unwind_home.mkdir()
        workspace = tmp / "workspace"
        workspace.mkdir()

        config_data = {"mode": "enforce", "version": 1}
        config_path = unwind_home / CONFIG_FILENAME
        config_path.write_text(json.dumps(config_data))

        return tmp, unwind_home, workspace, config_path

    def test_unchanged_config_reloads(self):
        """Restart with unchanged config → hash matches, loads OK."""
        _, unwind_home, workspace, _ = self._setup_with_config()

        # First load — records hash
        source1 = ImmutablePolicySource(unwind_home=unwind_home)
        result1 = source1.initial_load(workspace_root=workspace)
        self.assertTrue(result1.success)

        # Second load (simulating restart) — verifies hash
        source2 = ImmutablePolicySource(unwind_home=unwind_home)
        result2 = source2.initial_load(workspace_root=workspace)
        self.assertTrue(result2.success)

    def test_tampered_config_rejected(self):
        """Config changed without hash rotation → rejected."""
        _, unwind_home, workspace, config_path = self._setup_with_config()

        # First load — records hash
        source1 = ImmutablePolicySource(unwind_home=unwind_home)
        result1 = source1.initial_load(workspace_root=workspace)
        self.assertTrue(result1.success)

        # Tamper with config
        config_path.write_text(json.dumps({"mode": "off", "hacked": True}))

        # Second load — should reject
        source2 = ImmutablePolicySource(unwind_home=unwind_home)
        result2 = source2.initial_load(workspace_root=workspace)
        self.assertFalse(result2.success)
        self.assertIn("HASH_MISMATCH", result2.error)


class TestReload(unittest.TestCase):
    """Test runtime reload behavior."""

    def _setup_loaded_source(self):
        tmp = Path(tempfile.mkdtemp())
        unwind_home = tmp / ".unwind"
        unwind_home.mkdir()
        workspace = tmp / "workspace"
        workspace.mkdir()

        config_data = {"mode": "enforce"}
        config_path = unwind_home / CONFIG_FILENAME
        config_path.write_text(json.dumps(config_data))

        source = ImmutablePolicySource(unwind_home=unwind_home)
        source.initial_load(workspace_root=workspace)
        return source, config_path

    def test_reload_unchanged(self):
        """Reload with unchanged config succeeds."""
        source, _ = self._setup_loaded_source()
        result = source.reload()
        self.assertTrue(result.success)

    def test_reload_tampered_rejected(self):
        """Reload after config tamper is rejected, keeps old config."""
        source, config_path = self._setup_loaded_source()

        # Tamper
        config_path.write_text(json.dumps({"mode": "off"}))

        result = source.reload()
        self.assertFalse(result.success)
        self.assertIn("RELOAD_REJECTED", result.error)
        # Should keep old config
        self.assertEqual(source.current_config, {"mode": "enforce"})

    def test_reload_before_initial_load_fails(self):
        """Reload without initial_load should fail."""
        tmp = Path(tempfile.mkdtemp())
        source = ImmutablePolicySource(unwind_home=tmp)
        result = source.reload()
        self.assertFalse(result.success)
        self.assertIn("NOT_INITIALIZED", result.error)

    def test_reload_config_deleted(self):
        """Reload when config file was deleted should fail."""
        source, config_path = self._setup_loaded_source()
        config_path.unlink()

        result = source.reload()
        self.assertFalse(result.success)
        self.assertIn("FILE_MISSING", result.error)


class TestHashRotation(unittest.TestCase):
    """Test operator-initiated hash rotation."""

    def test_rotate_accepts_new_config(self):
        """After rotation, changed config is accepted."""
        tmp = Path(tempfile.mkdtemp())
        unwind_home = tmp / ".unwind"
        unwind_home.mkdir()
        workspace = tmp / "workspace"
        workspace.mkdir()

        config_path = unwind_home / CONFIG_FILENAME
        config_path.write_text(json.dumps({"version": 1}))

        source = ImmutablePolicySource(unwind_home=unwind_home)
        source.initial_load(workspace_root=workspace)
        old_hash = source.birth_hash

        # Change config
        config_path.write_text(json.dumps({"version": 2}))

        # Rotate hash
        result = source.rotate_hash()
        self.assertTrue(result.success)
        self.assertNotEqual(source.birth_hash, old_hash)
        self.assertEqual(source.current_config, {"version": 2})

        # Now reload should work
        result2 = source.reload()
        self.assertTrue(result2.success)


class TestConfigAccess(unittest.TestCase):
    """Test config value access helpers."""

    def test_get_existing_key(self):
        tmp = Path(tempfile.mkdtemp())
        unwind_home = tmp / ".unwind"
        unwind_home.mkdir()
        workspace = tmp / "workspace"
        workspace.mkdir()

        config_path = unwind_home / CONFIG_FILENAME
        config_path.write_text(json.dumps({"mode": "enforce", "timeout": 500}))

        source = ImmutablePolicySource(unwind_home=unwind_home)
        source.initial_load(workspace_root=workspace)

        self.assertEqual(source.get("mode"), "enforce")
        self.assertEqual(source.get("timeout"), 500)

    def test_get_missing_key_default(self):
        tmp = Path(tempfile.mkdtemp())
        unwind_home = tmp / ".unwind"
        unwind_home.mkdir()
        workspace = tmp / "workspace"
        workspace.mkdir()

        source = ImmutablePolicySource(unwind_home=unwind_home)
        source.initial_load(workspace_root=workspace)

        self.assertIsNone(source.get("nonexistent"))
        self.assertEqual(source.get("nonexistent", 42), 42)

    def test_get_section(self):
        tmp = Path(tempfile.mkdtemp())
        unwind_home = tmp / ".unwind"
        unwind_home.mkdir()
        workspace = tmp / "workspace"
        workspace.mkdir()

        config_path = unwind_home / CONFIG_FILENAME
        config_path.write_text(json.dumps({
            "enforcement": {"strict": True, "mode": "enforce"}
        }))

        source = ImmutablePolicySource(unwind_home=unwind_home)
        source.initial_load(workspace_root=workspace)

        section = source.get_section("enforcement")
        self.assertEqual(section, {"strict": True, "mode": "enforce"})

        # Missing section returns empty dict
        self.assertEqual(source.get_section("nonexistent"), {})


if __name__ == "__main__":
    unittest.main()
