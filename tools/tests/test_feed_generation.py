# SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
# SPDX-License-Identifier: GPL-3.0-or-later

import errno
import hashlib
import importlib.util
import json
import os
import stat
import sys
import tempfile
import unittest
import unittest.mock
from dataclasses import replace
from importlib.machinery import SourceFileLoader
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "feed_generation.py"
SPEC = importlib.util.spec_from_loader("feed_generation_tests", SourceFileLoader("feed_generation_tests", str(MODULE_PATH)))
feed_generation = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules["feed_generation_tests"] = feed_generation
SPEC.loader.exec_module(feed_generation)


class FeedGenerationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.cache = self.root / "cache"
        self.runtime = self.root / "runtime"
        self.cache.mkdir(mode=0o700)
        self.runtime.mkdir(mode=0o700)
        self.specs = (
            feed_generation.FeedClassSpec("nasl", "openvas/plugins", "openvas/plugins", ("plugin_feed_info.inc", "LICENSE")),
            feed_generation.FeedClassSpec("notus", "notus", "notus", ("advisories/sha256sums", "advisories/sha256sums.asc", "products/sha256sums", "products/sha256sums.asc")),
            feed_generation.FeedClassSpec("scap", "gvm/scap-data", "gvm/scap-data", ("COPYING",)),
            feed_generation.FeedClassSpec("cert", "gvm/cert-data", "gvm/cert-data", ("COPYING.CERT-BUND", "COPYING.DFN-CERT", "feed.xml")),
            feed_generation.FeedClassSpec("gvmd", "gvm/data-objects/gvmd/22.04", "gvm/data-objects/gvmd/22.04", ("LICENSE", "scan-configs", "report-formats", "port-lists")),
        )
        self._write("openvas/plugins/plugin_feed_info.inc", b"feed-version\n")
        self._write("openvas/plugins/LICENSE", b"license\n")
        self._write("notus/advisories/sha256sums", b"hash  advisory.json\n")
        self._write("notus/advisories/sha256sums.asc", b"signature\n")
        self._write("notus/advisories/advisory.json", b"{}\n")
        self._write("notus/products/sha256sums", b"hash  product.json\n")
        self._write("notus/products/sha256sums.asc", b"signature\n")
        self._write("notus/products/product.json", b"{}\n")
        self._write("gvm/scap-data/COPYING", b"copying\n")
        self._write("gvm/scap-data/data.xml", b"<data/>\n")
        self._write("gvm/cert-data/COPYING.CERT-BUND", b"bund\n")
        self._write("gvm/cert-data/COPYING.DFN-CERT", b"dfn\n")
        self._write("gvm/cert-data/feed.xml", b"<feed/>\n")
        self._write("gvm/data-objects/gvmd/22.04/LICENSE", b"license\n")
        self._write("gvm/data-objects/gvmd/22.04/scan-configs/config.xml", b"<config/>\n")
        self._write("gvm/data-objects/gvmd/22.04/report-formats/format.xml", b"<format/>\n")
        self._write("gvm/data-objects/gvmd/22.04/port-lists/list.xml", b"<list/>\n")

    def tearDown(self):
        self.temporary.cleanup()

    def _write(self, relative, payload):
        path = self.cache / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        return path

    def _stage(self):
        return feed_generation.stage_generation(self.cache, self.runtime, "22.04", self.specs)

    def _generation_path(self, result):
        return Path(result["path"])

    def _make_generation_writable(self, generation):
        for path in sorted(generation.rglob("*"), key=lambda item: len(item.parts)):
            if path.is_dir():
                path.chmod(0o755)
            else:
                path.chmod(0o644)
        generation.chmod(0o755)

    def _reseal_generation(self, generation):
        for path in sorted(generation.rglob("*"), key=lambda item: len(item.parts), reverse=True):
            path.chmod(0o500 if path.is_dir() else 0o444)
        generation.chmod(0o500)

    def test_stage_copies_all_five_classes_and_does_not_activate(self):
        target = self.root / "existing-current"
        target.mkdir()
        store = self.runtime / "feed-store"
        store.mkdir(mode=0o700)
        (store / "current").symlink_to(target)

        result = self._stage()

        self.assertTrue(result["verified"])
        self.assertEqual(result["class_count"], 5)
        self.assertFalse(result["current_pointer_changed"])
        self.assertEqual((store / "current").resolve(), target)
        generation = self._generation_path(result)
        self.assertTrue((generation / "openvas/plugins/plugin_feed_info.inc").is_file())
        self.assertTrue((generation / "notus/advisories/advisory.json").is_file())
        self.assertTrue((generation / "gvm/scap-data/COPYING").is_file())
        self.assertTrue((generation / "gvm/cert-data/feed.xml").is_file())
        self.assertTrue((generation / "gvm/data-objects/gvmd/22.04/scan-configs/config.xml").is_file())
        self.assertEqual(stat.S_IMODE(generation.stat().st_mode), 0o500)

    def test_generation_identifier_is_deterministic_and_duplicate_is_reused(self):
        first = self._stage()
        second = self._stage()
        self.assertEqual(first["generation_id"], second["generation_id"])
        self.assertFalse(first["reused"])
        self.assertTrue(second["reused"])
        state = feed_generation.generation_state(self.runtime, "22.04", self.specs)
        self.assertEqual(state["generation_count"], 1)
        self.assertEqual(state["invalid_entries"], [])

    def test_selection_is_atomic_verified_and_reports_previous_generation(self):
        first = self._stage()
        selected_first = feed_generation.select_generation(
            self.runtime,
            first["generation_id"],
            "22.04",
            self.specs,
        )
        self.assertIsNone(selected_first["previous_generation_id"])
        self.assertEqual(selected_first["current_generation_id"], first["generation_id"])
        self.assertEqual(
            os.readlink(self.runtime / "feed-store/current"),
            f"generations/{first['generation_id']}",
        )

        self._write("gvm/scap-data/data.xml", b"<second/>\n")
        second = self._stage()
        selected_second = feed_generation.select_generation(
            self.runtime,
            second["generation_id"],
            "22.04",
            self.specs,
        )
        self.assertEqual(selected_second["previous_generation_id"], first["generation_id"])
        self.assertEqual(selected_second["current_generation_id"], second["generation_id"])
        current = feed_generation.read_current_generation(self.runtime, "22.04", self.specs)
        self.assertEqual(current["generation_id"], second["generation_id"])
        state = feed_generation.generation_state(self.runtime, "22.04", self.specs)
        self.assertEqual(state["current_generation_id"], second["generation_id"])
        self.assertIsNone(state["current_error"])

    def test_selection_rejects_invalid_or_tampered_generation(self):
        with self.assertRaisesRegex(feed_generation.FeedGenerationError, "identifier"):
            feed_generation.select_generation(self.runtime, "../escape", "22.04", self.specs)

        staged = self._stage()
        generation = self._generation_path(staged)
        self._make_generation_writable(generation)
        (generation / "gvm/cert-data/feed.xml").write_bytes(b"tampered\n")
        self._reseal_generation(generation)
        with self.assertRaises(feed_generation.FeedGenerationError):
            feed_generation.select_generation(
                self.runtime,
                staged["generation_id"],
                "22.04",
                self.specs,
            )
        self.assertFalse((self.runtime / "feed-store/current").exists())

    def test_current_selector_rejects_unsafe_target_and_clear_is_identity_gated(self):
        staged = self._stage()
        store = self.runtime / "feed-store"
        (store / "current").symlink_to("../outside")
        with self.assertRaisesRegex(feed_generation.FeedGenerationError, "target is invalid"):
            feed_generation.read_current_generation(self.runtime, "22.04", self.specs)
        (store / "current").unlink()

        feed_generation.select_generation(
            self.runtime,
            staged["generation_id"],
            "22.04",
            self.specs,
        )
        with self.assertRaisesRegex(feed_generation.FeedGenerationError, "differs"):
            feed_generation.clear_current_generation(self.runtime, "f" * 64)
        feed_generation.clear_current_generation(self.runtime, staged["generation_id"])
        self.assertIsNone(feed_generation.read_current_generation(self.runtime, "22.04", self.specs))
        self.assertFalse((store / "current").exists())

    def test_failed_post_selection_verification_restores_prior_selector(self):
        first = self._stage()
        feed_generation.select_generation(
            self.runtime,
            first["generation_id"],
            "22.04",
            self.specs,
        )
        self._write("gvm/scap-data/data.xml", b"<second/>\n")
        second = self._stage()

        with unittest.mock.patch.object(
            feed_generation,
            "read_current_generation",
            side_effect=feed_generation.FeedGenerationError("forced post-select failure"),
        ):
            with self.assertRaisesRegex(feed_generation.FeedGenerationError, "prior selector was restored"):
                feed_generation.select_generation(
                    self.runtime,
                    second["generation_id"],
                    "22.04",
                    self.specs,
                )

        current = feed_generation.read_current_generation(self.runtime, "22.04", self.specs)
        self.assertEqual(current["generation_id"], first["generation_id"])

    def test_selector_fsync_failure_restores_prior_selector(self):
        first = self._stage()
        feed_generation.select_generation(
            self.runtime,
            first["generation_id"],
            "22.04",
            self.specs,
        )
        self._write("gvm/scap-data/data.xml", b"<second/>\n")
        second = self._stage()
        original_fsync = os.fsync
        failed = False

        def fail_once(descriptor):
            nonlocal failed
            target = os.readlink(f"/proc/self/fd/{descriptor}")
            if not failed and target.endswith("/feed-store"):
                failed = True
                raise OSError(errno.EIO, "forced selector fsync failure")
            original_fsync(descriptor)

        with unittest.mock.patch.object(
            feed_generation.os, "fsync", side_effect=fail_once
        ):
            with self.assertRaisesRegex(
                feed_generation.FeedGenerationError, "prior selector was restored"
            ):
                feed_generation.select_generation(
                    self.runtime,
                    second["generation_id"],
                    "22.04",
                    self.specs,
                )

        self.assertTrue(failed)
        current = feed_generation.read_current_generation(
            self.runtime, "22.04", self.specs
        )
        self.assertEqual(current["generation_id"], first["generation_id"])

    def test_first_selector_fsync_failure_clears_selector(self):
        staged = self._stage()
        original_fsync = os.fsync
        failed = False

        def fail_once(descriptor):
            nonlocal failed
            target = os.readlink(f"/proc/self/fd/{descriptor}")
            if not failed and target.endswith("/feed-store"):
                failed = True
                raise OSError(errno.EIO, "forced selector fsync failure")
            original_fsync(descriptor)

        with unittest.mock.patch.object(
            feed_generation.os, "fsync", side_effect=fail_once
        ):
            with self.assertRaisesRegex(
                feed_generation.FeedGenerationError, "prior selector was restored"
            ):
                feed_generation.select_generation(
                    self.runtime,
                    staged["generation_id"],
                    "22.04",
                    self.specs,
                )

        self.assertTrue(failed)
        self.assertIsNone(
            feed_generation.read_current_generation(
                self.runtime, "22.04", self.specs
            )
        )

    def test_payload_change_produces_a_different_generation_identifier(self):
        first = self._stage()
        path = self.cache / "gvm/scap-data/data.xml"
        path.write_bytes(b"<changed/>\n")
        second = self._stage()
        self.assertNotEqual(first["generation_id"], second["generation_id"])

    def test_wrong_release_or_partial_class_contract_is_rejected(self):
        self._stage()
        wrong_release = feed_generation.generation_state(self.runtime, "99.99", self.specs)
        partial = feed_generation.generation_state(self.runtime, "22.04", self.specs[:-1])
        self.assertEqual(wrong_release["generation_count"], 0)
        self.assertIn("release", wrong_release["invalid_entries"][0]["error"])
        self.assertEqual(partial["generation_count"], 0)
        self.assertIn("configured contract", partial["invalid_entries"][0]["error"])

    def test_state_on_missing_store_is_read_only(self):
        state = feed_generation.generation_state(self.runtime, "22.04", self.specs)
        self.assertFalse(state["store_exists"])
        self.assertFalse((self.runtime / "feed-store").exists())

    def test_state_rejects_an_empty_non_private_store(self):
        root = self.runtime / "feed-store/generations"
        root.mkdir(parents=True, mode=0o700)
        root.chmod(0o755)
        with self.assertRaisesRegex(feed_generation.FeedGenerationError, "not private"):
            feed_generation.generation_state(self.runtime, "22.04", self.specs)

    def test_missing_marker_fails_before_generation_installation(self):
        (self.cache / "gvm/scap-data/COPYING").unlink()
        with self.assertRaisesRegex(feed_generation.FeedGenerationError, "missing marker"):
            self._stage()
        generations = self.runtime / "feed-store/generations"
        self.assertEqual([path.name for path in generations.iterdir() if not path.name.startswith(".stage")], [])

    def test_nested_directory_order_is_canonical(self):
        self._write("openvas/plugins/a/child/file.nasl", b"nested\n")
        self._write("openvas/plugins/a-z/file.nasl", b"sibling\n")
        result = self._stage()
        self.assertTrue(result["verified"])

    def test_symlink_special_file_and_hardlink_are_rejected(self):
        cases = ("symlink", "fifo", "hardlink")
        for case in cases:
            with self.subTest(case=case):
                extra = self.cache / "openvas/plugins" / f"bad-{case}"
                if case == "symlink":
                    extra.symlink_to("LICENSE")
                elif case == "fifo":
                    os.mkfifo(extra)
                else:
                    os.link(self.cache / "openvas/plugins/LICENSE", extra)
                with self.assertRaises(feed_generation.FeedGenerationError):
                    self._stage()
                extra.unlink()

    def test_path_depth_limit_is_enforced(self):
        deep = self.cache / "openvas/plugins"
        for index in range(65):
            deep /= f"d{index}"
        deep.mkdir(parents=True)
        (deep / "file").write_text("data", encoding="utf-8")
        with self.assertRaisesRegex(feed_generation.FeedGenerationError, "maximum depth"):
            self._stage()

    def test_directory_count_limit_is_enforced_without_unbounded_listing(self):
        self._write("openvas/plugins/one/file", b"one\n")
        self._write("openvas/plugins/two/file", b"two\n")
        limits = feed_generation.FeedGenerationLimits(max_directories=1)
        with self.assertRaisesRegex(feed_generation.FeedGenerationError, "directory-count|too many entries"):
            feed_generation.stage_generation(self.cache, self.runtime, "22.04", self.specs, limits=limits)

    def test_source_mutation_during_staging_fails_and_cleans_staging(self):
        original = feed_generation._copy_file
        mutated = False

        def copy_and_mutate(*args, **kwargs):
            nonlocal mutated
            result = original(*args, **kwargs)
            if not mutated:
                mutated = True
                path = self.cache / "gvm/cert-data/feed.xml"
                path.write_bytes(b"<changed/>\n")
            return result

        with unittest.mock.patch.object(feed_generation, "_copy_file", side_effect=copy_and_mutate):
            with self.assertRaisesRegex(feed_generation.FeedGenerationError, "changed"):
                self._stage()
        root = self.runtime / "feed-store/generations"
        self.assertFalse(any(path.name.startswith(".staging-") for path in root.iterdir()))

    def test_post_install_verification_failure_removes_installed_generation(self):
        original = feed_generation.verify_generation
        calls = 0

        def fail_after_install(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise feed_generation.FeedGenerationError("forced post-install failure")
            return original(*args, **kwargs)

        with unittest.mock.patch.object(
            feed_generation,
            "verify_generation",
            side_effect=fail_after_install,
        ):
            with self.assertRaisesRegex(feed_generation.FeedGenerationError, "forced post-install"):
                self._stage()
        root = self.runtime / "feed-store/generations"
        self.assertEqual([path.name for path in root.iterdir() if path.name != ".stage.lock"], [])

    def test_signed_checksum_contract_covers_the_exact_class_payload(self):
        manifest_path = self.cache / "openvas/plugins/sha256sums"
        signature_path = self.cache / "openvas/plugins/sha256sums.asc"
        rows = []
        for name in ("LICENSE", "plugin_feed_info.inc"):
            digest = hashlib.sha256((self.cache / "openvas/plugins" / name).read_bytes()).hexdigest()
            rows.append(f"{digest}  {name}\n")
        manifest_path.write_text("".join(rows), encoding="utf-8")
        signature_path.write_text("fixture signature\n", encoding="utf-8")
        signed_nasl = replace(
            self.specs[0],
            signed_manifests=(("sha256sums", "sha256sums.asc"),),
            signing_key_fingerprint="A" * 40,
        )
        specs = (signed_nasl, *self.specs[1:])
        provenance = (
            {
                "class": "nasl",
                "checksums_path": "sha256sums",
                "signature_path": "sha256sums.asc",
                "checksums_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
                "signature_sha256": hashlib.sha256(signature_path.read_bytes()).hexdigest(),
                "signing_key_fingerprint": "A" * 40,
            },
        )
        result = feed_generation.stage_generation(self.cache, self.runtime, "22.04", specs, provenance)
        self.assertTrue(result["verified"])

        self._write("openvas/plugins/unsigned.nasl", b"not covered\n")
        with self.assertRaisesRegex(feed_generation.FeedGenerationError, "exact nasl payload"):
            feed_generation.stage_generation(self.cache, self.runtime, "22.04", specs, provenance)
        root = self.runtime / "feed-store/generations"
        self.assertFalse(any(path.name.startswith(".staging-") for path in root.iterdir()))

    def test_final_directory_fsync_failure_cleans_staging(self):
        original_fsync = feed_generation.os.fsync
        calls = 0

        def fail_first_fsync(descriptor):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise OSError(errno.EIO, "fsync failed")
            return original_fsync(descriptor)

        with unittest.mock.patch.object(feed_generation.os, "fsync", side_effect=fail_first_fsync):
            with self.assertRaises(OSError):
                self._stage()
        root = self.runtime / "feed-store/generations"
        self.assertFalse(any(path.name.startswith(".staging-") for path in root.iterdir()))

    def test_syncfs_failure_cleans_staging(self):
        with unittest.mock.patch.object(feed_generation, "_sync_filesystem", side_effect=OSError(errno.EIO, "syncfs failed")):
            with self.assertRaises(OSError):
                self._stage()
        root = self.runtime / "feed-store/generations"
        self.assertFalse(any(path.name.startswith(".staging-") for path in root.iterdir()))

    def test_atomic_rename_failure_cleans_staging(self):
        removed = False
        durable_cleanup = False
        original_remove = feed_generation._remove_tree_at
        original_fsync = feed_generation.os.fsync

        def remove_and_mark(*args, **kwargs):
            nonlocal removed
            result = original_remove(*args, **kwargs)
            removed = True
            return result

        def fsync_and_mark(descriptor):
            nonlocal durable_cleanup
            if removed:
                durable_cleanup = True
            return original_fsync(descriptor)

        with unittest.mock.patch.object(feed_generation, "_rename_noreplace", side_effect=OSError(errno.EIO, "rename failed")), unittest.mock.patch.object(feed_generation, "_remove_tree_at", side_effect=remove_and_mark), unittest.mock.patch.object(feed_generation.os, "fsync", side_effect=fsync_and_mark):
            with self.assertRaises(OSError):
                self._stage()
        root = self.runtime / "feed-store/generations"
        self.assertFalse(any(path.name.startswith(".staging-") for path in root.iterdir()))
        self.assertTrue(durable_cleanup)

    def test_tampered_payload_is_reported_invalid(self):
        result = self._stage()
        generation = self._generation_path(result)
        self._make_generation_writable(generation)
        (generation / "gvm/cert-data/feed.xml").write_bytes(b"tampered\n")
        self._reseal_generation(generation)
        state = feed_generation.generation_state(self.runtime, "22.04", self.specs)
        self.assertEqual(state["generation_count"], 0)
        self.assertEqual(state["invalid_entries"][0]["name"], result["generation_id"])

    def test_permission_change_during_verification_is_detected(self):
        result = self._stage()
        generation = self._generation_path(result)
        original = feed_generation._read_manifest
        calls = 0

        def chmod_on_final_read(*args, **kwargs):
            nonlocal calls
            calls += 1
            manifest = original(*args, **kwargs)
            if calls == 2:
                generation.chmod(0o755)
            return manifest

        with unittest.mock.patch.object(feed_generation, "_read_manifest", side_effect=chmod_on_final_read):
            with self.assertRaisesRegex(feed_generation.FeedGenerationError, "permissions changed"):
                feed_generation.verify_generation(Path(result["path"]).parent, result["generation_id"], "22.04", self.specs)

    def test_permission_change_before_final_reopen_is_detected(self):
        result = self._stage()
        generation = self._generation_path(result)
        original = feed_generation._open_beneath
        generation_opens = 0

        def chmod_before_reopen(parent_fd, parts):
            nonlocal generation_opens
            if tuple(parts) == (result["generation_id"],):
                generation_opens += 1
                if generation_opens == 2:
                    generation.chmod(0o700)
            return original(parent_fd, parts)

        with unittest.mock.patch.object(feed_generation, "_open_beneath", side_effect=chmod_before_reopen):
            with self.assertRaisesRegex(feed_generation.FeedGenerationError, "directory changed"):
                feed_generation.verify_generation(Path(result["path"]).parent, result["generation_id"], "22.04", self.specs)

    def test_tampered_manifest_is_reported_invalid(self):
        result = self._stage()
        generation = self._generation_path(result)
        self._make_generation_writable(generation)
        manifest_path = generation / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["feed_release"] = "tampered"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        self._reseal_generation(generation)
        state = feed_generation.generation_state(self.runtime, "22.04", self.specs)
        self.assertEqual(state["generation_count"], 0)
        self.assertIn("release", state["invalid_entries"][0]["error"])

    def test_tampered_existing_duplicate_fails_closed_and_cleans_staging(self):
        result = self._stage()
        generation = self._generation_path(result)
        self._make_generation_writable(generation)
        (generation / "gvm/cert-data/feed.xml").write_bytes(b"tampered\n")
        self._reseal_generation(generation)
        with self.assertRaises(feed_generation.FeedGenerationError):
            self._stage()
        self.assertFalse(any(path.name.startswith(".staging-") for path in generation.parent.iterdir()))

    def test_state_reports_orphan_staging_without_following_it(self):
        result = self._stage()
        root = Path(result["path"]).parent
        orphan = root / ".staging-orphan"
        orphan.mkdir()
        (orphan / "escape").symlink_to(self.root)
        state = feed_generation.generation_state(self.runtime, "22.04", self.specs)
        self.assertEqual(state["orphan_staging"], [".staging-orphan"])

    def test_state_rejects_excess_store_entries(self):
        root = self.runtime / "feed-store/generations"
        root.mkdir(parents=True, mode=0o700)
        for index in range(feed_generation.MAX_GENERATION_STORE_ENTRIES + 1):
            (root / f"unexpected-{index}").touch()
        with self.assertRaisesRegex(feed_generation.FeedGenerationError, "too many entries"):
            feed_generation.generation_state(self.runtime, "22.04", self.specs)


if __name__ == "__main__":
    unittest.main()
