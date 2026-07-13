#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
# SPDX-License-Identifier: GPL-3.0-or-later
"""Build and verify immutable, content-addressed feed generations."""

from __future__ import annotations

import ctypes
import errno
import fcntl
import hashlib
import json
import os
import re
import secrets
import stat
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Sequence


SCHEMA_VERSION = 1
MANIFEST_NAME = "manifest.json"
COPY_CHUNK_SIZE = 1024 * 1024
MAX_MANIFEST_BYTES = 128 * 1024 * 1024
MAX_GENERATION_STORE_ENTRIES = 64
MAX_GENERATIONS = 32
MAX_STORE_ENTRY_NAME_BYTES = 128


class FeedGenerationError(RuntimeError):
    """Raised when a feed generation cannot be built or verified safely."""


@dataclass(frozen=True)
class FeedClassSpec:
    key: str
    source_rel: str
    runtime_rel: str
    markers: tuple[str, ...]
    signed_manifests: tuple[tuple[str, str], ...] = ()
    signing_key_fingerprint: str | None = None
    unsigned_metadata: tuple[str, ...] = ()


@dataclass(frozen=True)
class FeedGenerationLimits:
    max_files: int = 250_000
    max_directories: int = 250_000
    max_total_bytes: int = 32 * 1024**3
    max_file_bytes: int = 8 * 1024**3
    max_path_bytes: int = 4096
    max_depth: int = 64


@dataclass(frozen=True)
class EntrySnapshot:
    path: str
    kind: str
    size: int
    mode: int
    device: int
    inode: int
    mtime_ns: int
    ctime_ns: int
    links: int

    @classmethod
    def from_stat(cls, path: str, kind: str, value: os.stat_result) -> "EntrySnapshot":
        return cls(path, kind, value.st_size, stat.S_IMODE(value.st_mode), value.st_dev,
                   value.st_ino, value.st_mtime_ns, value.st_ctime_ns, value.st_nlink)


@dataclass(frozen=True)
class Inventory:
    files: tuple[EntrySnapshot, ...]
    directories: tuple[EntrySnapshot, ...]
    total_bytes: int


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _safe_parts(value: str) -> tuple[str, ...]:
    path = PurePosixPath(value)
    parts = path.parts
    if path.is_absolute() or not parts or any(part in {"", ".", ".."} for part in parts):
        raise FeedGenerationError(f"unsafe relative path: {value!r}")
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise FeedGenerationError(f"path is not valid UTF-8: {value!r}") from error
    return parts


def _validated_parts(value: str, limits: FeedGenerationLimits) -> tuple[str, ...]:
    parts = _safe_parts(value)
    if len(parts) > limits.max_depth:
        raise FeedGenerationError(f"path exceeds maximum depth {limits.max_depth}: {value}")
    if len(value.encode("utf-8")) > limits.max_path_bytes:
        raise FeedGenerationError(f"path exceeds maximum length {limits.max_path_bytes}: {value}")
    return parts


def _open_absolute_dir(path: Path) -> int:
    absolute = Path(os.path.abspath(path))
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptor = os.open("/", flags)
    try:
        for part in absolute.parts[1:]:
            before = os.stat(part, dir_fd=descriptor, follow_symlinks=False)
            if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
                raise FeedGenerationError(f"directory path component is unsafe: {absolute}")
            child = os.open(part, flags, dir_fd=descriptor)
            after = os.fstat(child)
            if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                os.close(child)
                raise FeedGenerationError(f"directory changed while opening: {absolute}")
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_beneath(parent_fd: int, parts: Sequence[str]) -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptor = os.dup(parent_fd)
    try:
        for part in parts:
            if part in {"", ".", ".."} or "/" in part:
                raise FeedGenerationError(f"unsafe path component: {part!r}")
            before = os.stat(part, dir_fd=descriptor, follow_symlinks=False)
            if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
                raise FeedGenerationError(f"path component is not a real directory: {part}")
            child = os.open(part, flags, dir_fd=descriptor)
            after = os.fstat(child)
            if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                os.close(child)
                raise FeedGenerationError(f"directory changed while opening: {part}")
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _ensure_dir(parent_fd: int, name: str) -> int:
    try:
        os.mkdir(name, mode=0o700, dir_fd=parent_fd)
    except FileExistsError:
        pass
    descriptor = _open_beneath(parent_fd, (name,))
    if os.fstat(descriptor).st_uid != os.getuid():
        os.close(descriptor)
        raise FeedGenerationError(f"directory is not owned by current user: {name}")
    return descriptor


def _ensure_path(parent_fd: int, parts: Sequence[str]) -> int:
    descriptor = os.dup(parent_fd)
    try:
        for part in parts:
            child = _ensure_dir(descriptor, part)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _snapshot_identity(entry: EntrySnapshot) -> tuple[Any, ...]:
    return (entry.path, entry.kind, entry.size, entry.device, entry.inode,
            entry.mtime_ns, entry.ctime_ns, entry.links)


def _inventory_identity(inventory: Inventory) -> tuple[tuple[Any, ...], ...]:
    return tuple(_snapshot_identity(entry) for entry in (*inventory.directories, *inventory.files))


def _inventory(directory_fd: int, limits: FeedGenerationLimits,
               *, skip_root: frozenset[str] = frozenset()) -> Inventory:
    files: list[EntrySnapshot] = []
    directories: list[EntrySnapshot] = []
    total_bytes = 0

    def walk(current_fd: int, parts: tuple[str, ...]) -> None:
        nonlocal total_bytes
        names: list[str] = []
        with os.scandir(current_fd) as entries:
            for entry in entries:
                names.append(entry.name)
                if len(names) > limits.max_files + limits.max_directories + len(skip_root):
                    raise FeedGenerationError("feed directory contains too many entries")
        for name in sorted(names):
            if not name or name in {".", ".."} or "/" in name or "\x00" in name:
                raise FeedGenerationError(f"unsafe directory entry: {name!r}")
            try:
                name.encode("utf-8", errors="strict")
            except UnicodeEncodeError as error:
                raise FeedGenerationError(f"directory entry is not valid UTF-8: {name!r}") from error
            if not parts and name in skip_root:
                continue
            child_parts = (*parts, name)
            relative = "/".join(child_parts)
            _validated_parts(relative, limits)
            before = os.stat(name, dir_fd=current_fd, follow_symlinks=False)
            if stat.S_ISLNK(before.st_mode):
                raise FeedGenerationError(f"feed tree contains a symbolic link: {relative}")
            if stat.S_ISREG(before.st_mode):
                if before.st_nlink != 1:
                    raise FeedGenerationError(f"feed tree contains a multiply linked file: {relative}")
                if before.st_size > limits.max_file_bytes:
                    raise FeedGenerationError(f"feed file exceeds size limit: {relative}")
                total_bytes += before.st_size
                if total_bytes > limits.max_total_bytes:
                    raise FeedGenerationError("feed tree exceeds total-byte limit")
                files.append(EntrySnapshot.from_stat(relative, "file", before))
                if len(files) > limits.max_files:
                    raise FeedGenerationError("feed tree exceeds file-count limit")
                continue
            if not stat.S_ISDIR(before.st_mode):
                raise FeedGenerationError(f"feed tree contains a special file: {relative}")
            child = _open_beneath(current_fd, (name,))
            try:
                directories.append(EntrySnapshot.from_stat(relative, "directory", os.fstat(child)))
                if len(directories) > limits.max_directories:
                    raise FeedGenerationError("feed tree exceeds directory-count limit")
                walk(child, child_parts)
            finally:
                os.close(child)

    walk(directory_fd, ())
    return Inventory(tuple(files), tuple(directories), total_bytes)


def _class_inventory(cache_fd: int, spec: FeedClassSpec,
                     limits: FeedGenerationLimits) -> Inventory:
    source_fd = _open_beneath(cache_fd, _validated_parts(spec.source_rel, limits))
    try:
        inventory = _inventory(source_fd, limits)
    finally:
        os.close(source_fd)
    if not inventory.files:
        raise FeedGenerationError(f"{spec.key} feed class is empty")
    available = {entry.path for entry in (*inventory.directories, *inventory.files)}
    for marker in spec.markers:
        normalized = "/".join(_validated_parts(marker, limits))
        if normalized not in available:
            raise FeedGenerationError(f"{spec.key} feed class is missing marker: {marker}")
    return inventory


def _copy_file(source_root_fd: int, destination_root_fd: int,
               source_path: str, destination_path: str,
               expected: EntrySnapshot) -> tuple[int, str]:
    source_parts = _safe_parts(source_path)
    destination_parts = _safe_parts(destination_path)
    source_parent = _open_beneath(source_root_fd, source_parts[:-1])
    destination_parent = _open_beneath(destination_root_fd, destination_parts[:-1])
    input_fd = output_fd = -1
    try:
        before = os.stat(source_parts[-1], dir_fd=source_parent, follow_symlinks=False)
        if _snapshot_identity(EntrySnapshot.from_stat(expected.path, "file", before)) != _snapshot_identity(expected):
            raise FeedGenerationError(f"source file changed before copy: {source_path}")
        input_fd = os.open(source_parts[-1], os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                           dir_fd=source_parent)
        if _snapshot_identity(EntrySnapshot.from_stat(expected.path, "file", os.fstat(input_fd))) != _snapshot_identity(expected):
            raise FeedGenerationError(f"source file changed while opening: {source_path}")
        output_fd = os.open(destination_parts[-1],
                            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                            0o600, dir_fd=destination_parent)
        digest = hashlib.sha256()
        copied = 0
        while True:
            chunk = os.read(input_fd, COPY_CHUNK_SIZE)
            if not chunk:
                break
            copied += len(chunk)
            if copied > expected.size:
                raise FeedGenerationError(f"source file grew while copying: {source_path}")
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(output_fd, view)
                if written <= 0:
                    raise FeedGenerationError(f"short write while copying: {destination_path}")
                view = view[written:]
        after = os.fstat(input_fd)
        if copied != expected.size or _snapshot_identity(EntrySnapshot.from_stat(expected.path, "file", after)) != _snapshot_identity(expected):
            raise FeedGenerationError(f"source file changed while copying: {source_path}")
        return copied, digest.hexdigest()
    finally:
        if output_fd >= 0:
            os.close(output_fd)
        if input_fd >= 0:
            os.close(input_fd)
        os.close(destination_parent)
        os.close(source_parent)


def _write_manifest(generation_fd: int, manifest: dict[str, Any]) -> None:
    payload = _canonical_json(manifest) + b"\n"
    if len(payload) > MAX_MANIFEST_BYTES:
        raise FeedGenerationError("generation manifest exceeds size limit")
    descriptor = os.open(MANIFEST_NAME,
                         os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                         0o600, dir_fd=generation_fd)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise FeedGenerationError("short write while writing generation manifest")
            view = view[written:]
    finally:
        os.close(descriptor)


def _seal_tree(directory_fd: int) -> None:
    for name in sorted(os.listdir(directory_fd)):
        value = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if stat.S_ISLNK(value.st_mode):
            raise FeedGenerationError(f"symbolic link appeared while sealing: {name}")
        if stat.S_ISREG(value.st_mode):
            descriptor = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                                 dir_fd=directory_fd)
            try:
                os.fchmod(descriptor, 0o444)
            finally:
                os.close(descriptor)
            continue
        if not stat.S_ISDIR(value.st_mode):
            raise FeedGenerationError(f"special file appeared while sealing: {name}")
        child = _open_beneath(directory_fd, (name,))
        try:
            _seal_tree(child)
        finally:
            os.close(child)
    os.fchmod(directory_fd, 0o500)


def _sync_filesystem(descriptor: int) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    syncfs = getattr(libc, "syncfs", None)
    if syncfs is None:
        raise FeedGenerationError("syncfs is required for durable feed generation staging")
    syncfs.argtypes = [ctypes.c_int]
    syncfs.restype = ctypes.c_int
    if syncfs(descriptor) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def _remove_tree_at(parent_fd: int, name: str,
                    expected_identity: tuple[int, int] | None = None) -> None:
    value = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if expected_identity is not None and (value.st_dev, value.st_ino) != expected_identity:
        raise FeedGenerationError(f"refusing to remove a replaced tree: {name}")
    if not stat.S_ISDIR(value.st_mode) or stat.S_ISLNK(value.st_mode):
        os.unlink(name, dir_fd=parent_fd)
        return
    child = _open_beneath(parent_fd, (name,))
    try:
        if expected_identity is not None:
            opened = os.fstat(child)
            if (opened.st_dev, opened.st_ino) != expected_identity:
                raise FeedGenerationError(f"refusing to remove a replaced tree: {name}")
        os.fchmod(child, 0o700)
        for entry in os.listdir(child):
            _remove_tree_at(child, entry)
    finally:
        os.close(child)
    os.rmdir(name, dir_fd=parent_fd)


def _rename_noreplace(parent_fd: int, source: str, destination: str) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise FeedGenerationError("renameat2 is required for atomic generation installation")
    renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    renameat2.restype = ctypes.c_int
    if renameat2(parent_fd, os.fsencode(source), parent_fd, os.fsencode(destination), 1) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), destination)


def _read_manifest(generation_fd: int) -> dict[str, Any]:
    before = os.stat(MANIFEST_NAME, dir_fd=generation_fd, follow_symlinks=False)
    if (stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1 or before.st_size > MAX_MANIFEST_BYTES
            or stat.S_IMODE(before.st_mode) & 0o222):
        raise FeedGenerationError("generation manifest is unsafe")
    descriptor = os.open(MANIFEST_NAME, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                         dir_fd=generation_fd)
    try:
        opened = os.fstat(descriptor)
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise FeedGenerationError("generation manifest changed while opening")
        payload = bytearray()
        while True:
            chunk = os.read(descriptor, COPY_CHUNK_SIZE)
            if not chunk:
                break
            payload.extend(chunk)
            if len(payload) > MAX_MANIFEST_BYTES:
                raise FeedGenerationError("generation manifest exceeds size limit")
        final = os.fstat(descriptor)
        if (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) != (final.st_size, final.st_mtime_ns, final.st_ctime_ns):
            raise FeedGenerationError("generation manifest changed while reading")
    finally:
        os.close(descriptor)
    try:
        parsed = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise FeedGenerationError("generation manifest is not valid JSON") from error
    if not isinstance(parsed, dict):
        raise FeedGenerationError("generation manifest root is not an object")
    return parsed


def _hash_file_at(root_fd: int, path: str, expected_size: int) -> str:
    parts = _safe_parts(path)
    parent = _open_beneath(root_fd, parts[:-1])
    descriptor = -1
    try:
        before = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
        if (stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1 or before.st_size != expected_size
                or stat.S_IMODE(before.st_mode) & 0o222):
            raise FeedGenerationError(f"generation file metadata is invalid: {path}")
        descriptor = os.open(parts[-1], os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                             dir_fd=parent)
        opened = os.fstat(descriptor)
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise FeedGenerationError(f"generation file changed while opening: {path}")
        digest = hashlib.sha256()
        read_bytes = 0
        while True:
            chunk = os.read(descriptor, COPY_CHUNK_SIZE)
            if not chunk:
                break
            read_bytes += len(chunk)
            digest.update(chunk)
        final = os.fstat(descriptor)
        if read_bytes != expected_size or (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) != (final.st_size, final.st_mtime_ns, final.st_ctime_ns):
            raise FeedGenerationError(f"generation file changed while hashing: {path}")
        return digest.hexdigest()
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent)


def _read_file_at(root_fd: int, path: str, expected_size: int) -> bytes:
    parts = _safe_parts(path)
    parent = _open_beneath(root_fd, parts[:-1])
    descriptor = -1
    try:
        before = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
        if (stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1 or before.st_size != expected_size
                or stat.S_IMODE(before.st_mode) & 0o222):
            raise FeedGenerationError(f"generation file metadata is invalid: {path}")
        descriptor = os.open(parts[-1], os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                             dir_fd=parent)
        opened = os.fstat(descriptor)
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise FeedGenerationError(f"generation file changed while opening: {path}")
        payload = bytearray()
        while len(payload) < expected_size:
            chunk = os.read(descriptor, min(COPY_CHUNK_SIZE, expected_size - len(payload)))
            if not chunk:
                raise FeedGenerationError(f"generation file was truncated while reading: {path}")
            payload.extend(chunk)
        if os.read(descriptor, 1):
            raise FeedGenerationError(f"generation file grew while reading: {path}")
        final = os.fstat(descriptor)
        if (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) != (final.st_size, final.st_mtime_ns, final.st_ctime_ns):
            raise FeedGenerationError(f"generation file changed while reading: {path}")
        return bytes(payload)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent)


def _parse_sha256sums(payload: bytes, manifest_path: str,
                      limits: FeedGenerationLimits) -> dict[str, str]:
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise FeedGenerationError(f"signed checksum manifest is not UTF-8: {manifest_path}") from error
    checksums: dict[str, str] = {}
    parent = PurePosixPath(manifest_path).parent
    for line_number, line in enumerate(text.splitlines(), 1):
        if not line:
            continue
        match = re.fullmatch(r"([0-9a-fA-F]{64}) [ *]([^\\].*)", line)
        if match is None:
            raise FeedGenerationError(f"invalid signed checksum row in {manifest_path}:{line_number}")
        listed = "/".join(_validated_parts(match.group(2), limits))
        path = "/".join(part for part in (str(parent) if str(parent) != "." else "", listed) if part)
        _validated_parts(path, limits)
        if path in checksums:
            raise FeedGenerationError(f"duplicate signed checksum path in {manifest_path}: {path}")
        checksums[path] = match.group(1).lower()
        if len(checksums) > limits.max_files:
            raise FeedGenerationError(f"signed checksum manifest exceeds file-count limit: {manifest_path}")
    if not checksums:
        raise FeedGenerationError(f"signed checksum manifest is empty: {manifest_path}")
    return checksums


def _is_digest(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(char in "0123456789abcdef" for char in value)


def _manifest_content(manifest: dict[str, Any]) -> dict[str, Any]:
    return {key: manifest.get(key) for key in ("schema_version", "feed_release", "classes", "files", "signature_provenance")}


def verify_generation(generations_root: Path, generation_id: str,
                      expected_feed_release: str,
                      expected_classes: Sequence[FeedClassSpec],
                      limits: FeedGenerationLimits = FeedGenerationLimits(),
                      *, directory_name: str | None = None) -> dict[str, Any]:
    if not _is_digest(generation_id):
        raise FeedGenerationError(f"invalid generation identifier: {generation_id!r}")
    root_fd = _open_absolute_dir(generations_root)
    generation_fd = -1
    entry_name = directory_name or generation_id
    if "/" in entry_name or entry_name in {"", ".", ".."}:
        raise FeedGenerationError("unsafe generation directory name")
    try:
        store_stat = os.fstat(root_fd)
        if store_stat.st_uid != os.getuid() or stat.S_IMODE(store_stat.st_mode) & 0o077:
            raise FeedGenerationError("feed generation store is not private and user-owned")
        generation_fd = _open_beneath(root_fd, (entry_name,))
        generation_stat = os.fstat(generation_fd)
        if generation_stat.st_uid != os.getuid() or stat.S_IMODE(generation_stat.st_mode) & 0o222:
            raise FeedGenerationError("generation root is writable")
        initial_inventory = _inventory(generation_fd, limits)
        manifest = _read_manifest(generation_fd)
        if set(manifest) != {"schema_version", "feed_release", "classes", "files", "signature_provenance", "generation_id", "created_at", "source_snapshot"}:
            raise FeedGenerationError("generation manifest has unexpected or missing fields")
        if manifest.get("schema_version") != SCHEMA_VERSION:
            raise FeedGenerationError("unsupported generation manifest schema")
        if manifest.get("feed_release") != expected_feed_release:
            raise FeedGenerationError("generation feed release differs from the configured release")
        if manifest.get("generation_id") != generation_id:
            raise FeedGenerationError("generation directory and manifest identifiers differ")
        if hashlib.sha256(_canonical_json(_manifest_content(manifest))).hexdigest() != generation_id:
            raise FeedGenerationError("generation manifest content identifier is invalid")
        files = manifest.get("files")
        classes = manifest.get("classes")
        signature_provenance = manifest.get("signature_provenance")
        source_snapshot = manifest.get("source_snapshot")
        if (not isinstance(manifest.get("feed_release"), str)
                or not isinstance(manifest.get("created_at"), str)
                or not isinstance(files, list) or not isinstance(classes, list)
                or not isinstance(signature_provenance, list)
                or not isinstance(source_snapshot, dict)
                or set(source_snapshot) != {"class_count", "file_count", "byte_count"}):
            raise FeedGenerationError("generation manifest classes or files are invalid")
        expected_files: dict[str, tuple[int, str]] = {}
        expected_dirs: set[str] = set()
        expected_markers: set[str] = set()
        total_bytes = 0
        class_keys: set[str] = set()
        class_summaries: dict[str, tuple[int, int]] = {}
        class_runtime_parts: dict[str, tuple[str, ...]] = {}
        expected_specs = {spec.key: spec for spec in expected_classes}
        if not expected_specs or len(expected_specs) != len(expected_classes):
            raise FeedGenerationError("expected feed class contract is empty or duplicated")
        if len(classes) != len(expected_specs) or len(files) > limits.max_files:
            raise FeedGenerationError("generation manifest class or file count exceeds the configured contract")
        expected_signature_count = sum(len(spec.signed_manifests) for spec in expected_classes)
        if len(signature_provenance) != expected_signature_count:
            raise FeedGenerationError("generation signature provenance count differs from configuration")
        for row in classes:
            if not isinstance(row, dict) or set(row) != {"key", "source_rel", "runtime_rel", "markers", "signed_manifests", "signing_key_fingerprint", "unsigned_metadata", "file_count", "byte_count", "directories"}:
                raise FeedGenerationError("generation manifest has invalid class row")
            key, source_rel, runtime_rel = row["key"], row["source_rel"], row["runtime_rel"]
            markers, signed_manifests, signing_fingerprint = row["markers"], row["signed_manifests"], row["signing_key_fingerprint"]
            unsigned_metadata = row["unsigned_metadata"]
            directories = row["directories"]
            if (not isinstance(key, str) or key in class_keys or not isinstance(source_rel, str)
                    or not isinstance(runtime_rel, str) or not isinstance(markers, list)
                    or not isinstance(signed_manifests, list)
                    or not isinstance(unsigned_metadata, list)
                    or not isinstance(directories, list)):
                raise FeedGenerationError("generation manifest class metadata is invalid")
            if len(directories) > limits.max_directories:
                raise FeedGenerationError("generation manifest class exceeds directory-count limit")
            class_keys.add(key)
            expected_spec = expected_specs.get(key)
            if expected_spec is None:
                raise FeedGenerationError(f"generation contains unexpected feed class: {key}")
            manifest_pairs = tuple((item.get("checksums"), item.get("signature")) for item in signed_manifests if isinstance(item, dict) and set(item) == {"checksums", "signature"})
            if (source_rel, runtime_rel, tuple(markers), manifest_pairs, signing_fingerprint, tuple(unsigned_metadata)) != (
                expected_spec.source_rel,
                expected_spec.runtime_rel,
                expected_spec.markers,
                expected_spec.signed_manifests,
                expected_spec.signing_key_fingerprint,
                expected_spec.unsigned_metadata,
            ):
                raise FeedGenerationError(f"generation feed class contract differs from configuration: {key}")
            _validated_parts(source_rel, limits)
            runtime_parts = _validated_parts(runtime_rel, limits)
            class_runtime_parts[key] = runtime_parts
            expected_dirs.update("/".join(runtime_parts[:i]) for i in range(1, len(runtime_parts) + 1))
            for marker in markers:
                if not isinstance(marker, str):
                    raise FeedGenerationError("generation manifest class marker is invalid")
                expected_markers.add("/".join((*runtime_parts, *_validated_parts(marker, limits))))
            if directories != sorted(set(directories)):
                raise FeedGenerationError("generation manifest class directories are not unique and sorted")
            for relative in directories:
                if not isinstance(relative, str):
                    raise FeedGenerationError("generation manifest class directory is invalid")
                full_parts = (*runtime_parts, *_validated_parts(relative, limits))
                full = "/".join(full_parts)
                _validated_parts(full, limits)
                expected_dirs.update("/".join(full_parts[:i]) for i in range(1, len(full_parts) + 1))
            count, byte_count = row.get("file_count"), row.get("byte_count")
            if (not isinstance(count, int) or isinstance(count, bool) or count < 0
                    or not isinstance(byte_count, int) or isinstance(byte_count, bool) or byte_count < 0):
                raise FeedGenerationError("generation manifest class summary is invalid")
            class_summaries[key] = (count, byte_count)
        if [row["key"] for row in classes] != sorted(class_keys):
            raise FeedGenerationError("generation manifest classes are not sorted")
        if class_keys != set(expected_specs):
            raise FeedGenerationError("generation does not contain the exact configured feed classes")
        runtime_roots = [parts for parts in class_runtime_parts.values()]
        if any(left != right and left[:len(right)] == right for left in runtime_roots for right in runtime_roots):
            raise FeedGenerationError("generation manifest class roots overlap")
        actual_summaries = {key: [0, 0] for key in class_keys}
        for row in files:
            if not isinstance(row, dict) or set(row) != {"class", "path", "runtime_path", "sha256", "size"}:
                raise FeedGenerationError("generation manifest has invalid file row")
            key, path, runtime_path, digest, size = (row[name] for name in ("class", "path", "runtime_path", "sha256", "size"))
            if key not in class_keys or not isinstance(path, str) or not isinstance(runtime_path, str) or not _is_digest(digest) or not isinstance(size, int) or isinstance(size, bool) or size < 0:
                raise FeedGenerationError("generation manifest file metadata is invalid")
            path_parts = _validated_parts(path, limits)
            parts = _validated_parts(runtime_path, limits)
            if parts != (*class_runtime_parts[key], *path_parts):
                raise FeedGenerationError(f"generation runtime path does not match its class: {runtime_path}")
            if runtime_path in expected_files or size > limits.max_file_bytes:
                raise FeedGenerationError(f"generation manifest repeats or exceeds file limit: {runtime_path}")
            expected_files[runtime_path] = (size, digest)
            expected_dirs.update("/".join(parts[:i]) for i in range(1, len(parts)))
            actual_summaries[key][0] += 1
            actual_summaries[key][1] += size
            total_bytes += size
        if [(row["class"], row["path"]) for row in files] != sorted((row["class"], row["path"]) for row in files):
            raise FeedGenerationError("generation manifest files are not sorted")
        if len(expected_files) > limits.max_files or total_bytes > limits.max_total_bytes:
            raise FeedGenerationError("generation manifest exceeds configured limits")
        if source_snapshot != {"class_count": len(classes), "file_count": len(expected_files), "byte_count": total_bytes}:
            raise FeedGenerationError("generation source snapshot differs from manifest content")
        if any(tuple(actual_summaries[key]) != class_summaries[key] for key in class_keys):
            raise FeedGenerationError("generation class summaries differ from file rows")
        provenance_by_pair: dict[tuple[str, str, str], dict[str, Any]] = {}
        for row in signature_provenance:
            required = {"class", "checksums_path", "signature_path", "checksums_sha256", "signature_sha256", "signing_key_fingerprint"}
            if not isinstance(row, dict) or set(row) != required:
                raise FeedGenerationError("generation signature provenance row is invalid")
            key = (row["class"], row["checksums_path"], row["signature_path"])
            if key in provenance_by_pair or row["class"] not in class_keys or not _is_digest(row["checksums_sha256"]) or not _is_digest(row["signature_sha256"]):
                raise FeedGenerationError("generation signature provenance metadata is invalid")
            expected_spec = expected_specs[row["class"]]
            if ((row["checksums_path"], row["signature_path"]) not in expected_spec.signed_manifests
                    or row["signing_key_fingerprint"] != expected_spec.signing_key_fingerprint):
                raise FeedGenerationError("generation signature provenance differs from configuration")
            provenance_by_pair[key] = row
        expected_pairs = {
            (spec.key, checksums, signature)
            for spec in expected_classes
            for checksums, signature in spec.signed_manifests
        }
        if set(provenance_by_pair) != expected_pairs:
            raise FeedGenerationError("generation signature provenance is incomplete")
        if signature_provenance != sorted(signature_provenance, key=lambda row: (row["class"], row["checksums_path"])):
            raise FeedGenerationError("generation signature provenance is not sorted")
        files_by_class: dict[str, dict[str, tuple[str, str, int]]] = {key: {} for key in class_keys}
        for row in files:
            files_by_class[row["class"]][row["path"]] = (row["runtime_path"], row["sha256"], row["size"])
        for spec in expected_classes:
            signed_targets: set[str] = set()
            signature_metadata_paths: set[str] = set()
            for checksums_path, signature_path in spec.signed_manifests:
                provenance = provenance_by_pair[(spec.key, checksums_path, signature_path)]
                for metadata_path, digest_field in ((checksums_path, "checksums_sha256"), (signature_path, "signature_sha256")):
                    metadata = files_by_class[spec.key].get(metadata_path)
                    if metadata is None or metadata[1] != provenance[digest_field]:
                        raise FeedGenerationError(f"signed provenance file differs from manifest: {spec.key}/{metadata_path}")
                    signature_metadata_paths.add(metadata_path)
                checksum_file = files_by_class[spec.key][checksums_path]
                checksums = _parse_sha256sums(_read_file_at(generation_fd, checksum_file[0], checksum_file[2]), checksums_path, limits)
                for signed_path, signed_digest in checksums.items():
                    target = files_by_class[spec.key].get(signed_path)
                    if target is None or target[1] != signed_digest:
                        raise FeedGenerationError(f"signed checksum does not match generation content: {spec.key}/{signed_path}")
                    signed_targets.add(signed_path)
            unsigned_metadata = set(spec.unsigned_metadata)
            if not unsigned_metadata.issubset(files_by_class[spec.key]):
                raise FeedGenerationError(f"configured unsigned {spec.key} metadata is missing")
            if spec.signed_manifests and set(files_by_class[spec.key]) - signature_metadata_paths - unsigned_metadata != signed_targets:
                raise FeedGenerationError(f"signed checksum manifests do not cover the exact {spec.key} payload")
        inventory = Inventory(
            tuple(entry for entry in initial_inventory.files if entry.path != MANIFEST_NAME),
            initial_inventory.directories,
            initial_inventory.total_bytes - next(entry.size for entry in initial_inventory.files if entry.path == MANIFEST_NAME),
        )
        if {entry.path for entry in inventory.files} != set(expected_files):
            raise FeedGenerationError("generation payload files differ from manifest")
        if {entry.path for entry in inventory.directories} != expected_dirs:
            raise FeedGenerationError("generation payload directories differ from manifest")
        if not expected_markers.issubset(set(expected_files) | expected_dirs):
            raise FeedGenerationError("generation payload is missing a required class marker")
        if any(entry.mode & 0o222 for entry in inventory.directories):
            raise FeedGenerationError("generation contains a writable directory")
        for path, (size, digest) in sorted(expected_files.items()):
            if _hash_file_at(generation_fd, path, size) != digest:
                raise FeedGenerationError(f"generation file digest differs from manifest: {path}")
        final_manifest = _read_manifest(generation_fd)
        final_inventory = _inventory(generation_fd, limits)
        if final_manifest != manifest or _inventory_identity(final_inventory) != _inventory_identity(initial_inventory):
            raise FeedGenerationError("generation changed while it was being verified")
        final_store_stat = os.fstat(root_fd)
        final_generation_stat = os.fstat(generation_fd)
        if ((final_store_stat.st_dev, final_store_stat.st_ino) != (store_stat.st_dev, store_stat.st_ino)
                or final_store_stat.st_uid != os.getuid()
                or stat.S_IMODE(final_store_stat.st_mode) & 0o077):
            raise FeedGenerationError("feed generation store permissions changed while verifying")
        if ((final_generation_stat.st_dev, final_generation_stat.st_ino) != (generation_stat.st_dev, generation_stat.st_ino)
                or final_generation_stat.st_uid != os.getuid()
                or stat.S_IMODE(final_generation_stat.st_mode) & 0o222):
            raise FeedGenerationError("generation permissions changed while verifying")
        reopened_store_fd = _open_absolute_dir(generations_root)
        try:
            reopened_store = os.fstat(reopened_store_fd)
            if ((reopened_store.st_dev, reopened_store.st_ino) != (store_stat.st_dev, store_stat.st_ino)
                    or reopened_store.st_uid != os.getuid()
                    or stat.S_IMODE(reopened_store.st_mode) & 0o077):
                raise FeedGenerationError("feed generation store path changed while verifying")
        finally:
            os.close(reopened_store_fd)
        parent_entry = os.stat(entry_name, dir_fd=root_fd, follow_symlinks=False)
        reopened_fd = _open_beneath(root_fd, (entry_name,))
        try:
            reopened = os.fstat(reopened_fd)
            if ((parent_entry.st_dev, parent_entry.st_ino) != (generation_stat.st_dev, generation_stat.st_ino)
                    or (reopened.st_dev, reopened.st_ino) != (generation_stat.st_dev, generation_stat.st_ino)
                    or reopened.st_uid != os.getuid()
                    or stat.S_IMODE(reopened.st_mode) & 0o222):
                raise FeedGenerationError("generation directory changed while it was being verified")
        finally:
            os.close(reopened_fd)
        return {"generation_id": generation_id, "feed_release": manifest.get("feed_release"),
                "file_count": len(expected_files), "byte_count": total_bytes,
                "class_count": len(classes), "created_at": manifest.get("created_at"),
                "verified": True}
    finally:
        if generation_fd >= 0:
            os.close(generation_fd)
        os.close(root_fd)


def _current_generation_id(store_fd: int) -> str | None:
    try:
        current = os.stat("current", dir_fd=store_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    if not stat.S_ISLNK(current.st_mode) or current.st_uid != os.getuid():
        raise FeedGenerationError("current feed generation selector is not a user-owned symlink")
    target = os.readlink("current", dir_fd=store_fd)
    parts = PurePosixPath(target).parts
    if PurePosixPath(target).is_absolute() or len(parts) != 2 or parts[0] != "generations" or not _is_digest(parts[1]):
        raise FeedGenerationError("current feed generation selector target is invalid")
    return parts[1]


def read_current_generation(runtime_root: Path, expected_feed_release: str,
                            expected_classes: Sequence[FeedClassSpec],
                            limits: FeedGenerationLimits = FeedGenerationLimits()) -> dict[str, Any] | None:
    store_root = runtime_root / "feed-store"
    try:
        store_fd = _open_absolute_dir(store_root)
    except FileNotFoundError:
        return None
    try:
        store = os.fstat(store_fd)
        if store.st_uid != os.getuid() or stat.S_IMODE(store.st_mode) & 0o077:
            raise FeedGenerationError("feed generation store is not private and user-owned")
        generation_id = _current_generation_id(store_fd)
        if generation_id is None:
            return None
        verified = verify_generation(
            store_root / "generations",
            generation_id,
            expected_feed_release,
            expected_classes,
            limits,
        )
        current = os.stat("current", dir_fd=store_fd, follow_symlinks=False)
        if not stat.S_ISLNK(current.st_mode) or current.st_uid != os.getuid() or _current_generation_id(store_fd) != generation_id:
            raise FeedGenerationError("current feed generation selector changed while verifying")
        return verified
    finally:
        os.close(store_fd)


def _replace_current_selector(store_fd: int, generation_id: str) -> None:
    temporary_name = f".current-{os.getpid()}-{secrets.token_hex(8)}"
    try:
        os.symlink(f"generations/{generation_id}", temporary_name, dir_fd=store_fd)
        temporary = os.stat(temporary_name, dir_fd=store_fd, follow_symlinks=False)
        if not stat.S_ISLNK(temporary.st_mode) or temporary.st_uid != os.getuid():
            raise FeedGenerationError("temporary feed generation selector is unsafe")
        os.replace(
            temporary_name,
            "current",
            src_dir_fd=store_fd,
            dst_dir_fd=store_fd,
        )
        temporary_name = ""
        os.fsync(store_fd)
    finally:
        if temporary_name:
            try:
                os.unlink(temporary_name, dir_fd=store_fd)
            except FileNotFoundError:
                pass


def select_generation(runtime_root: Path, generation_id: str,
                      expected_feed_release: str,
                      expected_classes: Sequence[FeedClassSpec],
                      limits: FeedGenerationLimits = FeedGenerationLimits()) -> dict[str, Any]:
    if not _is_digest(generation_id):
        raise FeedGenerationError("feed generation identifier is invalid")
    generations_fd, generations_root = _prepare_store(runtime_root)
    store_fd = lock_fd = -1
    try:
        store_fd = _open_absolute_dir(runtime_root / "feed-store")
        lock_fd = _lock_store(generations_fd)
        previous_generation_id = _current_generation_id(store_fd)
        if previous_generation_id is not None:
            verify_generation(
                generations_root,
                previous_generation_id,
                expected_feed_release,
                expected_classes,
                limits,
            )
        verified = verify_generation(
            generations_root,
            generation_id,
            expected_feed_release,
            expected_classes,
            limits,
        )
        try:
            _replace_current_selector(store_fd, generation_id)
            selected = read_current_generation(
                runtime_root,
                expected_feed_release,
                expected_classes,
                limits,
            )
            if selected is None or selected["generation_id"] != generation_id:
                raise FeedGenerationError("feed generation selector did not retain the requested generation")
        except (FeedGenerationError, OSError) as error:
            try:
                if previous_generation_id is None:
                    if _current_generation_id(store_fd) == generation_id:
                        os.unlink("current", dir_fd=store_fd)
                        os.fsync(store_fd)
                else:
                    _replace_current_selector(store_fd, previous_generation_id)
            except (FeedGenerationError, OSError) as restore_error:
                raise FeedGenerationError(
                    f"feed generation selection failed and prior selector restoration failed: {restore_error}"
                ) from error
            raise FeedGenerationError(
                f"feed generation selection failed; prior selector was restored: {error}"
            ) from error
        return {
            **verified,
            "previous_generation_id": previous_generation_id,
            "current_generation_id": generation_id,
        }
    finally:
        if lock_fd >= 0:
            os.close(lock_fd)
        if store_fd >= 0:
            os.close(store_fd)
        os.close(generations_fd)


def clear_current_generation(runtime_root: Path, expected_generation_id: str) -> None:
    if not _is_digest(expected_generation_id):
        raise FeedGenerationError("expected feed generation identifier is invalid")
    generations_fd, _generations_root = _prepare_store(runtime_root)
    store_fd = lock_fd = -1
    try:
        store_fd = _open_absolute_dir(runtime_root / "feed-store")
        lock_fd = _lock_store(generations_fd)
        if _current_generation_id(store_fd) != expected_generation_id:
            raise FeedGenerationError("current feed generation differs from the expected selector")
        os.unlink("current", dir_fd=store_fd)
        os.fsync(store_fd)
    finally:
        if lock_fd >= 0:
            os.close(lock_fd)
        if store_fd >= 0:
            os.close(store_fd)
        os.close(generations_fd)


def _prepare_store(runtime_root: Path) -> tuple[int, Path]:
    runtime_fd = _open_absolute_dir(runtime_root)
    store_fd = generations_fd = -1
    try:
        if os.fstat(runtime_fd).st_uid != os.getuid():
            raise FeedGenerationError("runtime root is not owned by the current user")
        store_fd = _ensure_dir(runtime_fd, "feed-store")
        generations_fd = _ensure_dir(store_fd, "generations")
        os.fchmod(store_fd, 0o700)
        os.fchmod(generations_fd, 0o700)
        return os.dup(generations_fd), runtime_root / "feed-store" / "generations"
    finally:
        if generations_fd >= 0:
            os.close(generations_fd)
        if store_fd >= 0:
            os.close(store_fd)
        os.close(runtime_fd)


def _lock_store(generations_fd: int) -> int:
    parent = os.fstat(generations_fd)
    if parent.st_uid != os.getuid() or stat.S_IMODE(parent.st_mode) & 0o077:
        raise FeedGenerationError("feed generation store must be private and user-owned")
    descriptor = os.open(".stage.lock", os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW,
                         0o600, dir_fd=generations_fd)
    value = os.fstat(descriptor)
    if not stat.S_ISREG(value.st_mode) or value.st_uid != os.getuid() or value.st_nlink != 1:
        os.close(descriptor)
        raise FeedGenerationError("feed generation lock file is unsafe")
    os.fchmod(descriptor, 0o600)
    fcntl.flock(descriptor, fcntl.LOCK_EX)
    return descriptor


def stage_generation(cache_root: Path, runtime_root: Path, feed_release: str,
                     classes: Sequence[FeedClassSpec],
                     signature_provenance: Sequence[dict[str, Any]] = (),
                     limits: FeedGenerationLimits = FeedGenerationLimits()) -> dict[str, Any]:
    if not classes or len({spec.key for spec in classes}) != len(classes):
        raise FeedGenerationError("feed class specification is empty or duplicated")
    cache_fd = generations_fd = -1
    lock_fd = staging_fd = -1
    staging_name: str | None = None
    staging_identity: tuple[int, int] | None = None
    try:
        cache_fd = _open_absolute_dir(cache_root)
        generations_fd, generations_root = _prepare_store(runtime_root)
        expected_signature_pairs = {
            (spec.key, checksums, signature)
            for spec in classes
            for checksums, signature in spec.signed_manifests
        }
        provided_signature_pairs: set[tuple[str, str, str]] = set()
        for row in signature_provenance:
            required = {"class", "checksums_path", "signature_path", "checksums_sha256", "signature_sha256", "signing_key_fingerprint"}
            if not isinstance(row, dict) or set(row) != required or not _is_digest(row["checksums_sha256"]) or not _is_digest(row["signature_sha256"]):
                raise FeedGenerationError("verified signature provenance is invalid")
            pair = (row["class"], row["checksums_path"], row["signature_path"])
            provided_signature_pairs.add(pair)
            spec = next((item for item in classes if item.key == row["class"]), None)
            if spec is None or pair[1:] not in spec.signed_manifests or row["signing_key_fingerprint"] != spec.signing_key_fingerprint:
                raise FeedGenerationError("verified signature provenance differs from configured feed classes")
        if provided_signature_pairs != expected_signature_pairs or len(provided_signature_pairs) != len(signature_provenance):
            raise FeedGenerationError("verified signature provenance is incomplete or duplicated")
        lock_fd = _lock_store(generations_fd)
        inventories = {spec.key: _class_inventory(cache_fd, spec, limits) for spec in classes}
        total_files = sum(len(item.files) for item in inventories.values())
        total_directories = sum(len(item.directories) for item in inventories.values())
        total_bytes = sum(item.total_bytes for item in inventories.values())
        if total_files > limits.max_files or total_directories > limits.max_directories or total_bytes > limits.max_total_bytes:
            raise FeedGenerationError("combined feed classes exceed configured limits")
        staging_name = f".staging-{os.getpid()}-{secrets.token_hex(8)}"
        os.mkdir(staging_name, mode=0o700, dir_fd=generations_fd)
        staging_fd = _open_beneath(generations_fd, (staging_name,))
        staging_stat = os.fstat(staging_fd)
        staging_identity = (staging_stat.st_dev, staging_stat.st_ino)
        manifest_files: list[dict[str, Any]] = []
        manifest_classes: list[dict[str, Any]] = []
        for spec in classes:
            inventory = inventories[spec.key]
            runtime_parts = _validated_parts(spec.runtime_rel, limits)
            descriptor = _ensure_path(staging_fd, runtime_parts)
            os.close(descriptor)
            for directory in inventory.directories:
                descriptor = _ensure_path(staging_fd, (*runtime_parts, *_safe_parts(directory.path)))
                os.close(descriptor)
            for source in inventory.files:
                source_path = "/".join((*_safe_parts(spec.source_rel), *_safe_parts(source.path)))
                runtime_path = "/".join((*runtime_parts, *_safe_parts(source.path)))
                copied, digest = _copy_file(cache_fd, staging_fd, source_path, runtime_path, source)
                manifest_files.append({"class": spec.key, "path": source.path,
                                       "runtime_path": runtime_path, "sha256": digest,
                                       "size": copied})
            manifest_classes.append({"key": spec.key, "source_rel": spec.source_rel,
                                     "runtime_rel": spec.runtime_rel,
                                     "markers": list(spec.markers),
                                     "signed_manifests": [{"checksums": checksums, "signature": signature} for checksums, signature in spec.signed_manifests],
                                     "signing_key_fingerprint": spec.signing_key_fingerprint,
                                     "unsigned_metadata": list(spec.unsigned_metadata),
                                     "file_count": len(inventory.files),
                                     "byte_count": inventory.total_bytes,
                                     "directories": sorted(entry.path for entry in inventory.directories)})
        for spec in classes:
            if _inventory_identity(_class_inventory(cache_fd, spec, limits)) != _inventory_identity(inventories[spec.key]):
                raise FeedGenerationError(f"{spec.key} feed class changed while staging")
        manifest_files.sort(key=lambda row: (row["class"], row["path"]))
        manifest_classes.sort(key=lambda row: row["key"])
        signature_rows = sorted((dict(row) for row in signature_provenance), key=lambda row: (row.get("class", ""), row.get("checksums_path", "")))
        content = {"schema_version": SCHEMA_VERSION, "feed_release": feed_release,
                   "classes": manifest_classes, "files": manifest_files,
                   "signature_provenance": signature_rows}
        generation_id = hashlib.sha256(_canonical_json(content)).hexdigest()
        _write_manifest(staging_fd, {**content, "generation_id": generation_id,
                                     "created_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
                                     "source_snapshot": {"class_count": len(classes),
                                                         "file_count": total_files,
                                                         "byte_count": total_bytes}})
        _seal_tree(staging_fd)
        _sync_filesystem(staging_fd)
        os.fsync(staging_fd)
        os.close(staging_fd)
        staging_fd = -1
        verify_generation(
            generations_root,
            generation_id,
            feed_release,
            classes,
            limits,
            directory_name=staging_name,
        )
        installed_name: str | None = None
        try:
            _rename_noreplace(generations_fd, staging_name, generation_id)
            installed_name = generation_id
            staging_name = None
            reused = False
        except OSError as error:
            if error.errno != errno.EEXIST:
                raise
            verify_generation(generations_root, generation_id, feed_release, classes, limits)
            _remove_tree_at(generations_fd, staging_name, staging_identity)
            staging_name = None
            reused = True
        os.fsync(generations_fd)
        verified = verify_generation(generations_root, generation_id, feed_release, classes, limits)
        installed_name = None
        return {**verified, "path": str(generations_root / generation_id),
                "reused": reused, "current_pointer_changed": False}
    finally:
        if staging_fd >= 0:
            os.close(staging_fd)
        if staging_name is not None:
            try:
                _remove_tree_at(generations_fd, staging_name, staging_identity)
                os.fsync(generations_fd)
                staging_name = None
            except FileNotFoundError:
                if "generation_id" in locals() and staging_identity is not None:
                    try:
                        _remove_tree_at(generations_fd, generation_id, staging_identity)
                        os.fsync(generations_fd)
                        staging_name = None
                        if "installed_name" in locals():
                            installed_name = None
                    except FileNotFoundError:
                        pass
            except Exception as error:
                raise FeedGenerationError(f"failed to remove incomplete staging generation {staging_name}: {error}") from error
        if "installed_name" in locals() and installed_name is not None:
            try:
                _remove_tree_at(generations_fd, installed_name, staging_identity)
                os.fsync(generations_fd)
            except Exception as error:
                raise FeedGenerationError(f"failed to remove invalid installed generation {installed_name}: {error}") from error
        if lock_fd >= 0:
            os.close(lock_fd)
        if generations_fd >= 0:
            os.close(generations_fd)
        if cache_fd >= 0:
            os.close(cache_fd)


def generation_state(runtime_root: Path, expected_feed_release: str,
                     expected_classes: Sequence[FeedClassSpec],
                     limits: FeedGenerationLimits = FeedGenerationLimits()) -> dict[str, Any]:
    generations_root = runtime_root / "feed-store" / "generations"
    current_exists = (runtime_root / "feed-store" / "current").is_symlink()
    current_generation_id: str | None = None
    current_error: str | None = None
    try:
        current = read_current_generation(runtime_root, expected_feed_release, expected_classes, limits)
        if current is not None:
            current_generation_id = current["generation_id"]
    except (FeedGenerationError, OSError) as error:
        current_error = str(error)
    try:
        generations_fd = _open_absolute_dir(generations_root)
    except FileNotFoundError:
        return {"generations_root": str(generations_root), "store_exists": False,
                "generations": [], "generation_count": 0, "orphan_staging": [],
                "invalid_entries": [], "current_pointer_exists": current_exists,
                "current_generation_id": current_generation_id,
                "current_error": current_error}
    try:
        store_stat = os.fstat(generations_fd)
        if store_stat.st_uid != os.getuid() or stat.S_IMODE(store_stat.st_mode) & 0o077:
            raise FeedGenerationError("feed generation store is not private and user-owned")
        generations: list[dict[str, Any]] = []
        orphan_staging: list[str] = []
        invalid_entries: list[dict[str, str]] = []
        names: list[str] = []
        with os.scandir(generations_fd) as entries:
            for entry in entries:
                name = entry.name
                if len(name.encode("utf-8", errors="surrogateescape")) > MAX_STORE_ENTRY_NAME_BYTES:
                    raise FeedGenerationError("feed generation store contains an overlong entry name")
                names.append(name)
                if len(names) > MAX_GENERATION_STORE_ENTRIES:
                    raise FeedGenerationError("feed generation store contains too many entries")
        generation_names = [name for name in names if _is_digest(name)]
        if len(generation_names) > MAX_GENERATIONS:
            raise FeedGenerationError("feed generation store contains too many generations")
        for name in sorted(names):
            if name == ".stage.lock":
                continue
            if name.startswith(".staging-"):
                orphan_staging.append(name)
                continue
            if not _is_digest(name):
                invalid_entries.append({"name": name, "error": "unexpected generation-store entry"})
                continue
            try:
                generations.append(verify_generation(generations_root, name, expected_feed_release, expected_classes, limits))
            except (FeedGenerationError, OSError) as error:
                invalid_entries.append({"name": name, "error": str(error)})
        return {"generations_root": str(generations_root), "store_exists": True,
                "generations": generations,
                "generation_count": len(generations), "orphan_staging": orphan_staging,
                "invalid_entries": invalid_entries,
                "current_pointer_exists": current_exists,
                "current_generation_id": current_generation_id,
                "current_error": current_error}
    finally:
        os.close(generations_fd)
