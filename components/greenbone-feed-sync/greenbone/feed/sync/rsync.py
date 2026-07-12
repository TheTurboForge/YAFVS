# SPDX-FileCopyrightText: 2022-2024 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

import asyncio
import ipaddress
import os
import re
import shlex
import signal
import stat
import tempfile
from collections.abc import Iterable
from pathlib import Path
from urllib.parse import SplitResult, urlsplit

from greenbone.feed.sync.errors import (
    ConfigError,
    GreenboneFeedSyncError,
    RsyncError,
)

RSYNC_PROCESS_GROUP_GRACE_SECONDS = 5.0
RSYNC_PROCESS_GROUP_POLL_SECONDS = 0.01


async def _wait_for_process(process: asyncio.subprocess.Process) -> bool:
    try:
        await asyncio.wait_for(
            process.wait(), timeout=RSYNC_PROCESS_GROUP_GRACE_SECONDS
        )
    except TimeoutError:
        return False
    return True


def _process_group_exists(pgid: int) -> bool:
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


async def _wait_for_process_group_empty(pgid: int) -> bool:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + RSYNC_PROCESS_GROUP_GRACE_SECONDS
    while _process_group_exists(pgid):
        remaining = deadline - loop.time()
        if remaining <= 0:
            return False
        await asyncio.sleep(min(RSYNC_PROCESS_GROUP_POLL_SECONDS, remaining))
    return True


async def _terminate_process_group(
    process: asyncio.subprocess.Process,
) -> None:
    pgid = process.pid
    try:
        os.killpg(pgid, signal.SIGTERM)
    except ProcessLookupError:
        pass

    parent_exited = await _wait_for_process(process)
    group_exists = _process_group_exists(pgid)
    if group_exists:
        # POSIX has no generation-bound process-group handle. Retaining the
        # session leader's PGID and placing this probe immediately before the
        # signal minimizes, but cannot eliminate, a theoretical PGID-reuse race.
        try:
            os.killpg(pgid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    if not parent_exited and not await _wait_for_process(process):
        raise GreenboneFeedSyncError(
            f"Could not reap cancelled rsync parent process {process.pid}."
        )
    if not await _wait_for_process_group_empty(pgid):
        raise GreenboneFeedSyncError(
            f"Cancelled rsync process group {pgid} is not empty."
        )


async def exec_rsync(*args: str) -> None:
    """
    Run rsync

    Argument:
        args: Arguments for rsync
    """
    process = await asyncio.create_subprocess_exec(
        "rsync",
        *args,
        stderr=asyncio.subprocess.PIPE,
        start_new_session=True,
    )
    try:
        _, stderr = await process.communicate()
    except BaseException:
        await asyncio.shield(_terminate_process_group(process))
        raise

    returncode = await process.wait()
    if returncode:
        raise RsyncError(returncode, args, stderr=stderr)


DEFAULT_RSYNC_URL = "rsync://feed.community.greenbone.net/community"
DEFAULT_RSYNC_COMPRESSION_LEVEL = 9
DEFAULT_RSYNC_TIMEOUT: int | None = (
    None  # in seconds. 0 means no timeout and None use rsync default
)
MAX_RSYNC_TIMEOUT = 86_400
DEFAULT_RSYNC_SSH_PORT = 24
COMMUNITY_RSYNC_HOST = "feed.community.greenbone.net"
COMMUNITY_RSYNC_PATH = "/community"
SSH_USERNAME_PATTERN = re.compile(r"[A-Za-z0-9_.-]+")
SSH_REMOTE_PATH_PATTERN = re.compile(r"/[A-Za-z0-9._~%+,/-]*")
SSH_HOST_LABEL_PATTERN = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
)
MAX_SSH_TRUST_FILE_SIZE = 16 * 1024 * 1024

PathLike = os.PathLike | str


def _safe_owner(metadata: os.stat_result) -> bool:
    return metadata.st_uid in (0, os.geteuid())


def _validate_parent(metadata: os.stat_result, path: Path) -> None:
    if not stat.S_ISDIR(metadata.st_mode):
        raise ConfigError(f"SSH trust path parent is not a directory: {path}.")
    if not _safe_owner(metadata):
        raise ConfigError(f"SSH trust path parent has an unsafe owner: {path}.")
    if metadata.st_mode & 0o022:
        # Sticky root-owned directories prevent non-owners from replacing
        # entries owned by the effective user.
        root_sticky = metadata.st_uid == 0 and bool(
            metadata.st_mode & stat.S_ISVTX
        )
        if not root_sticky:
            raise ConfigError(
                f"SSH trust path parent is group- or world-writable: {path}."
            )


def _open_trust_file(
    path: PathLike | None, *, label: str, private: bool = False
) -> int:
    if path is None:
        raise ConfigError(f"{label} is required for SSH feed transport.")

    candidate = Path(path).expanduser()
    if not candidate.is_absolute():
        raise ConfigError(f"{label} must use an absolute path.")
    if any(part in (".", "..") for part in candidate.parts):
        raise ConfigError(f"{label} must use a canonical absolute path.")
    if len(candidate.parts) < 2:
        raise ConfigError(f"{label} must name a file.")

    directory_flags = (
        os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW
    )
    file_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    directory_fd = os.open("/", directory_flags)
    current = Path("/")
    try:
        _validate_parent(os.fstat(directory_fd), current)
        for part in candidate.parts[1:-1]:
            next_fd = os.open(part, directory_flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
            current /= part
            _validate_parent(os.fstat(directory_fd), current)
        file_fd = os.open(candidate.parts[-1], file_flags, dir_fd=directory_fd)
    except OSError as error:
        raise ConfigError(f"{label} is not usable: {error}.") from error
    finally:
        os.close(directory_fd)

    metadata = os.fstat(file_fd)
    try:
        if not stat.S_ISREG(metadata.st_mode):
            raise ConfigError(f"{label} must be a regular file.")
        if not _safe_owner(metadata):
            raise ConfigError(f"{label} has an unsafe owner.")
        if not 0 < metadata.st_size <= MAX_SSH_TRUST_FILE_SIZE:
            raise ConfigError(
                f"{label} must be non-empty and at most "
                f"{MAX_SSH_TRUST_FILE_SIZE} bytes."
            )
        if not os.access(
            f"/proc/self/fd/{file_fd}",
            os.R_OK,
            effective_ids=True,
        ):
            raise ConfigError(
                f"{label} must be readable by the effective user."
            )
        if metadata.st_mode & 0o022:
            raise ConfigError(f"{label} must not be group- or world-writable.")
        if private and metadata.st_mode & 0o077:
            raise ConfigError(f"{label} must not be accessible by other users.")
    except BaseException:
        os.close(file_fd)
        raise
    return file_fd


def _copy_trust_file(source_fd: int, destination: Path, mode: int) -> None:
    output_fd = os.open(
        destination,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
        mode,
    )
    try:
        while chunk := os.read(source_fd, 64 * 1024):
            view = memoryview(chunk)
            while view:
                written = os.write(output_fd, view)
                view = view[written:]
        os.fsync(output_fd)
    finally:
        os.close(output_fd)


def _validate_hostname(hostname: str) -> None:
    try:
        ipaddress.ip_address(hostname)
        return
    except ValueError:
        pass

    labels = hostname.rstrip(".").split(".")
    if not labels or any(
        not SSH_HOST_LABEL_PATTERN.fullmatch(label) for label in labels
    ):
        raise ConfigError("SSH feed URL contains an invalid hostname.")


def _validate_remote_path(path: str) -> None:
    if not path or not SSH_REMOTE_PATH_PATTERN.fullmatch(path):
        raise ConfigError("SSH feed URL contains an unsafe remote path.")
    if any(part in (".", "..") for part in path.split("/")):
        raise ConfigError(
            "SSH feed URL remote path must not traverse directories."
        )


def _split_url(url: str) -> SplitResult:
    try:
        return urlsplit(url)
    except ValueError as error:
        raise ConfigError(f"Invalid feed URL: {error}.") from error


def _validate_community_rsync_url(parsed: SplitResult) -> str:
    try:
        port = parsed.port
    except ValueError as error:
        raise ConfigError(
            f"Community rsync URL has an invalid port: {error}."
        ) from error
    if (
        parsed.netloc != COMMUNITY_RSYNC_HOST
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.query
        or parsed.fragment
        or parsed.hostname != COMMUNITY_RSYNC_HOST
    ):
        raise ConfigError(
            "Only the Greenbone Community rsync endpoint is supported."
        )
    _validate_remote_path(parsed.path)
    if not (
        parsed.path == COMMUNITY_RSYNC_PATH
        or parsed.path.startswith(f"{COMMUNITY_RSYNC_PATH}/")
    ):
        raise ConfigError("Community rsync URL must remain below /community.")
    return f"rsync://{COMMUNITY_RSYNC_HOST}{parsed.path}"


class Rsync:
    """
    Class to sync the feed data via rsync

    Args:
        verbose: Enable verbose output
        private_subdir: A private directory to exclude from from the sync
        compression_level: Set an compression level explicitly.
            Default is 9 (highest).
        timeout: Set a specific timeout in seconds. Default timeout of rsync is
            used of not set explicitly. 0 for no timeout.
        ssh_key: SSH key for using ssh as rsync transport protocol.
        ssh_known_hosts: Pinned known-hosts file for SSH transport.
        exclude: An iterable of directories to exclude from the sync.

    """

    def __init__(
        self,
        *,
        verbose: bool = False,
        private_subdir: PathLike | None = None,
        compression_level: int | None = DEFAULT_RSYNC_COMPRESSION_LEVEL,
        timeout: int | None = DEFAULT_RSYNC_TIMEOUT,
        ssh_key: PathLike | None = None,
        ssh_known_hosts: PathLike | None = None,
        exclude: Iterable[PathLike] | None = None,
    ) -> None:
        self.verbose = verbose
        self.private_subdir = private_subdir
        self.compression_level = compression_level
        if timeout is not None and (
            isinstance(timeout, bool)
            or timeout < 0
            or timeout > MAX_RSYNC_TIMEOUT
        ):
            raise ConfigError(
                f"Rsync timeout must be between 0 and {MAX_RSYNC_TIMEOUT} seconds."
            )
        self.timeout = timeout
        self.exclude = exclude
        self._trust_directory: tempfile.TemporaryDirectory[str] | None = None
        self._ssh_key: Path | None = None
        self._ssh_known_hosts: Path | None = None
        if ssh_key is not None or ssh_known_hosts is not None:
            self._snapshot_trust_files(ssh_key, ssh_known_hosts)

    def _snapshot_trust_files(
        self,
        ssh_key: PathLike | None,
        ssh_known_hosts: PathLike | None,
    ) -> None:
        key_fd = _open_trust_file(
            ssh_key, label="SSH private key", private=True
        )
        try:
            known_hosts_fd = _open_trust_file(
                ssh_known_hosts, label="SSH known-hosts file"
            )
        except BaseException:
            os.close(key_fd)
            raise

        try:
            trust_directory = tempfile.TemporaryDirectory(
                prefix="greenbone-feed-sync-ssh-", dir="/tmp"
            )
        except BaseException:
            os.close(key_fd)
            os.close(known_hosts_fd)
            raise
        trust_root = Path(trust_directory.name)
        trust_root.chmod(0o700)
        key_snapshot = trust_root / "identity"
        known_hosts_snapshot = trust_root / "known_hosts"
        try:
            _copy_trust_file(key_fd, key_snapshot, 0o600)
            _copy_trust_file(known_hosts_fd, known_hosts_snapshot, 0o600)
        except BaseException:
            trust_directory.cleanup()
            raise
        finally:
            os.close(key_fd)
            os.close(known_hosts_fd)

        self._trust_directory = trust_directory
        self._ssh_key = key_snapshot
        self._ssh_known_hosts = known_hosts_snapshot

    def close(self) -> None:
        if self._trust_directory is not None:
            self._trust_directory.cleanup()
            self._trust_directory = None
            self._ssh_key = None
            self._ssh_known_hosts = None

    def _ssh_source_and_command(self, url: str) -> tuple[str, str]:
        parsed = _split_url(url)
        if parsed.scheme.lower() != "ssh":
            raise ConfigError("SSH feed URL must use the explicit ssh:// form.")
        if parsed.password is not None or parsed.query or parsed.fragment:
            raise ConfigError(
                "SSH feed URL must not contain a password, query, or fragment."
            )

        username = parsed.username
        if (
            not username
            or username.startswith("-")
            or not SSH_USERNAME_PATTERN.fullmatch(username)
        ):
            raise ConfigError("SSH feed URL contains an invalid username.")

        hostname = parsed.hostname
        if not hostname:
            raise ConfigError("SSH feed URL must contain a hostname.")
        _validate_hostname(hostname)
        _validate_remote_path(parsed.path)

        try:
            parsed_port = parsed.port
        except ValueError as error:
            raise ConfigError(
                f"SSH feed URL contains an invalid port: {error}."
            ) from error
        port = DEFAULT_RSYNC_SSH_PORT if parsed_port is None else parsed_port
        if port < 1:
            raise ConfigError("SSH feed URL port must be between 1 and 65535.")

        if self._ssh_key is None or self._ssh_known_hosts is None:
            raise ConfigError(
                "SSH private key and known-hosts files are required "
                "for SSH feed transport."
            )
        ssh_command = shlex.join(
            [
                "ssh",
                "-F",
                "/dev/null",
                "-o",
                "BatchMode=yes",
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                "GlobalKnownHostsFile=/dev/null",
                "-o",
                f"UserKnownHostsFile={self._ssh_known_hosts}",
                "-o",
                "UpdateHostKeys=no",
                "-o",
                "VerifyHostKeyDNS=no",
                "-o",
                "ProxyCommand=none",
                "-o",
                "ProxyJump=none",
                "-p",
                str(port),
                "-i",
                os.fspath(self._ssh_key),
            ]
        )
        display_hostname = f"[{hostname}]" if ":" in hostname else hostname
        remote = f"{username}@" if username else ""
        return f"{remote}{display_hostname}:{parsed.path}", ssh_command

    def _validated_source(self, url: str) -> tuple[str, list[str]]:
        parsed = _split_url(url)
        scheme = parsed.scheme.lower()
        if scheme == "rsync":
            return _validate_community_rsync_url(parsed), []
        if scheme == "ssh":
            source, command = self._ssh_source_and_command(url)
            return source, ["-e", command]
        raise ConfigError(
            "Feed URL must use the supported Community rsync:// endpoint "
            "or an explicit ssh:// URL."
        )

    def validate_url(self, url: str) -> None:
        self._validated_source(url)

    async def sync(self, url: str, destination: PathLike) -> None:
        """
        Sync data from a remote URL to a destination path

        Args:
            url: URL to sync
            destination: Path to store the downloaded data
        """
        url, rsync_ssh_options = self._validated_source(url)

        dest = Path(destination)
        dest.mkdir(parents=True, exist_ok=True)

        rsync_default_options = [
            "--links",
            "--times",
            "--omit-dir-times",
            "--recursive",
            "--progress",
        ]

        rsync_timeout = (
            [
                f"--timeout={self.timeout}",
            ]
            if self.timeout is not None
            else []
        )

        rsync_compress = (
            [
                f"--compress-level={self.compression_level}",
            ]
            if self.compression_level is not None
            else []
        )

        rsync_delete = [
            "--delete",
        ]

        rsync_chmod = [
            "--perms",
            "--chmod=Fugo+r,Fug+w,Dugo-s,Dugo+rx,Dug+w",
        ]

        rsync_links = [
            "--safe-links",
            "--hard-links",
        ]

        if self.private_subdir:
            rsync_delete.extend(["--exclude", os.fspath(self.private_subdir)])

        if self.exclude:
            for exclude in self.exclude:
                rsync_delete.extend(["--exclude", os.fspath(exclude)])

        rsync_verbose = ["-v"] if self.verbose else ["-q"]

        args = (
            rsync_default_options
            + rsync_ssh_options
            + rsync_timeout
            + rsync_verbose
            + rsync_compress
            + rsync_delete
            + rsync_chmod
            + rsync_links
            + ["--", url, str(dest.absolute())]
        )

        await exec_rsync(*args)
