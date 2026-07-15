# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Durable, claim-level result spooling for OSPD result delivery.

The spool intentionally knows nothing about Redis or OSP transport.  It makes
the hand-off durable: a claimed Redis source is staged once, exposed as exactly
one OSP batch, marked ACKING before Redis is acknowledged, and only then marked
ACKED.  This lets an integration recover safely at every process boundary.
"""

import hashlib
import json
import os
import sqlite3
import stat
import uuid

from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Mapping, Optional

MAX_RESULT_ROW_BYTES = 4 * 1024 * 1024
MAX_CLAIM_ROWS = 1000
MAX_CLAIM_BYTES = 16 * 1024 * 1024
MAX_SCAN_PENDING_ROWS = 10_000
MAX_SCAN_PENDING_BYTES = 64 * 1024 * 1024
MAX_SCAN_PENDING_CLAIMS = 1
MAX_GLOBAL_PENDING_ROWS = 100_000
MAX_GLOBAL_PENDING_BYTES = 512 * 1024 * 1024
MAX_GLOBAL_PENDING_CLAIMS = 128
MAX_INCOMPLETE_REASON_BYTES = 8192
DEFAULT_BUSY_TIMEOUT_MS = 5000
DEFAULT_ACKED_TOMBSTONES = 10_000


class ResultSpoolError(RuntimeError):
    """Base class for fail-closed result spool errors."""


class ResultSpoolValidationError(ResultSpoolError):
    """Raised when a caller supplies an invalid claim or state transition."""


class ResultSpoolCapacityError(ResultSpoolError):
    """Raised when admitting a claim would exceed a durable capacity bound."""


class ResultSpoolConflictError(ResultSpoolError):
    """Raised when a source claim is replayed with a different payload."""


class ResultSpoolStateError(ResultSpoolError):
    """Raised for an invalid or non-exact acknowledge transition."""


class ResultSpoolSerializationError(ResultSpoolError):
    """Raised when a result payload cannot be canonically serialized."""


class ResultSpoolCorruptionError(ResultSpoolError):
    """Raised when stored state is malformed or SQLite reports corruption."""


class ResultSpoolIOError(ResultSpoolError):
    """Raised for database and filesystem I/O failures."""


class ClaimState(str, Enum):
    """The durable hand-off states for one Redis source claim."""

    STAGED = 'STAGED'
    EXPOSED = 'EXPOSED'
    ACKING = 'ACKING'
    ACKED = 'ACKED'


@dataclass(frozen=True)
class SpoolLimits:
    """Admission and tombstone bounds; injectable for focused tests."""

    max_result_row_bytes: int = MAX_RESULT_ROW_BYTES
    max_claim_rows: int = MAX_CLAIM_ROWS
    max_claim_bytes: int = MAX_CLAIM_BYTES
    max_scan_pending_rows: int = MAX_SCAN_PENDING_ROWS
    max_scan_pending_bytes: int = MAX_SCAN_PENDING_BYTES
    max_scan_pending_claims: int = MAX_SCAN_PENDING_CLAIMS
    max_global_pending_rows: int = MAX_GLOBAL_PENDING_ROWS
    max_global_pending_bytes: int = MAX_GLOBAL_PENDING_BYTES
    max_global_pending_claims: int = MAX_GLOBAL_PENDING_CLAIMS
    max_acked_tombstones: int = DEFAULT_ACKED_TOMBSTONES


@dataclass(frozen=True)
class SpoolClaim:
    """A durable source claim and its one stable OSP batch."""

    scan_id: str
    redis_db: int
    source_claim_id: str
    osp_batch_id: str
    state: ClaimState
    results: List[Dict[str, Any]]
    count_dead: int
    count_total: Optional[int]
    count_excluded: Optional[int]
    incomplete_reason: Optional[str]
    digest: str


@dataclass(frozen=True)
class PendingScanState:
    """Recoverable aggregate state for one scan with pending claims."""

    scan_id: str
    pending_claims: int
    pending_rows: int
    pending_bytes: int
    count_dead: int
    count_total: Optional[int]
    count_excluded: Optional[int]


class ResultSpool:
    """SQLite-backed durable source-claim spool.

    Connections are opened per operation so the same lightweight object is
    safe to inherit into scanner processes and use from OSP request threads.
    Write transitions use ``BEGIN IMMEDIATE`` and SQLite's busy timeout.
    """

    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS scans (
        scan_id TEXT PRIMARY KEY,
        count_dead INTEGER NOT NULL DEFAULT 0,
        count_total INTEGER,
        count_excluded INTEGER
    );
    CREATE TABLE IF NOT EXISTS claims (
        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
        redis_db INTEGER NOT NULL,
        source_claim_id TEXT NOT NULL,
        osp_batch_id TEXT NOT NULL UNIQUE,
        state TEXT NOT NULL CHECK(state IN ('STAGED', 'EXPOSED', 'ACKING', 'ACKED')),
        payload_json TEXT,
        row_count INTEGER NOT NULL,
        payload_bytes INTEGER NOT NULL,
        count_dead INTEGER NOT NULL,
        count_total INTEGER,
        count_excluded INTEGER,
        incomplete_reason TEXT,
        digest TEXT NOT NULL,
        acked_sequence INTEGER,
        UNIQUE(redis_db, source_claim_id)
    );
    CREATE INDEX IF NOT EXISTS claims_pending_scan_sequence
        ON claims(scan_id, state, sequence);
    CREATE INDEX IF NOT EXISTS claims_acked_sequence
        ON claims(state, acked_sequence, sequence);
    CREATE UNIQUE INDEX IF NOT EXISTS claims_one_pending_per_scan
        ON claims(scan_id) WHERE state != 'ACKED';
    """

    def __init__(
        self,
        path: str,
        *,
        limits: Optional[SpoolLimits] = None,
        busy_timeout_ms: int = DEFAULT_BUSY_TIMEOUT_MS,
    ) -> None:
        self.path = Path(path)
        self.limits = limits or SpoolLimits()
        self._validate_limits(self.limits)
        if not isinstance(busy_timeout_ms, int) or busy_timeout_ms <= 0:
            raise ResultSpoolValidationError(
                'busy_timeout_ms must be a positive integer'
            )
        self._busy_timeout_ms = busy_timeout_ms
        self._prepare_path()
        connection = None
        try:
            connection = self._open_connection()
            journal = connection.execute('PRAGMA journal_mode = WAL')
            if journal.fetchone()[0].lower() != 'wal':
                raise ResultSpoolIOError('SQLite refused WAL journal mode')
            connection.execute('PRAGMA synchronous = FULL')
            connection.execute('PRAGMA trusted_schema = OFF')
            connection.execute('PRAGMA journal_size_limit = 16777216')
            if connection.execute('PRAGMA foreign_keys').fetchone()[0] != 1:
                raise ResultSpoolIOError(
                    'SQLite refused foreign key enforcement'
                )
            connection.executescript(self._SCHEMA)
            user_version = connection.execute('PRAGMA user_version').fetchone()[
                0
            ]
            if user_version == 0:
                connection.execute('PRAGMA user_version = 1')
            elif user_version != 1:
                raise ResultSpoolCorruptionError(
                    f'unsupported result spool schema version {user_version}'
                )
            self._secure_database_files()
            self._validate_stored_state(connection)
        except ResultSpoolError:
            raise
        except sqlite3.Error as exc:
            raise self._database_error(exc) from exc
        except OSError as exc:
            raise ResultSpoolIOError(str(exc)) from exc
        finally:
            if connection is not None:
                connection.close()

    def close(self) -> None:
        """Retained for context-manager compatibility; no connection is held."""

    def __enter__(self) -> 'ResultSpool':
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    def stage_claim(
        self,
        scan_id: str,
        redis_db: int,
        source_claim_id: str,
        results: Iterable[Mapping[str, Any]],
        *,
        count_dead: int = 0,
        count_total: Optional[int] = None,
        count_excluded: Optional[int] = None,
        incomplete_reason: Optional[str] = None,
    ) -> SpoolClaim:
        """Stage one Redis source claim, or return its exact durable replay."""
        self._validate_identity(scan_id, redis_db, source_claim_id)
        metadata = self._validate_metadata(
            count_dead, count_total, count_excluded, incomplete_reason
        )
        payload_json, normalized_rows = self._canonical_rows(results)
        payload_bytes = len(payload_json.encode('utf-8'))
        digest = self._digest(payload_json, metadata)

        with self._transaction() as connection:
            existing = connection.execute(
                'SELECT * FROM claims WHERE redis_db = ? AND source_claim_id = ?',
                (redis_db, source_claim_id),
            ).fetchone()
            if existing is not None:
                claim = self._claim_from_row(existing)
                if claim.scan_id != scan_id or claim.digest != digest:
                    raise ResultSpoolConflictError(
                        'source claim conflicts with its durable payload'
                    )
                return claim

            self._check_capacity(
                connection, scan_id, len(normalized_rows), payload_bytes
            )
            connection.execute(
                'INSERT OR IGNORE INTO scans '
                '(scan_id, count_dead, count_total, count_excluded) '
                'VALUES (?, 0, NULL, NULL)',
                (scan_id,),
            )
            connection.execute(
                'UPDATE scans SET count_dead = count_dead + ?, '
                'count_total = COALESCE(?, count_total), '
                'count_excluded = COALESCE(?, count_excluded) '
                'WHERE scan_id = ?',
                (count_dead, count_total, count_excluded, scan_id),
            )
            osp_batch_id = str(uuid.uuid4())
            connection.execute(
                'INSERT INTO claims '
                '(scan_id, redis_db, source_claim_id, osp_batch_id, state, '
                'payload_json, row_count, payload_bytes, count_dead, '
                'count_total, count_excluded, incomplete_reason, digest) '
                'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                (
                    scan_id,
                    redis_db,
                    source_claim_id,
                    osp_batch_id,
                    ClaimState.STAGED.value,
                    payload_json,
                    len(normalized_rows),
                    payload_bytes,
                    count_dead,
                    count_total,
                    count_excluded,
                    incomplete_reason,
                    digest,
                ),
            )
            row = connection.execute(
                'SELECT * FROM claims WHERE redis_db = ? AND source_claim_id = ?',
                (redis_db, source_claim_id),
            ).fetchone()
            return self._claim_from_row(row)

    def expose_next(self, scan_id: str) -> Optional[SpoolClaim]:
        """Expose the oldest unacknowledged OSP batch for a scan.

        An already exposed claim is returned before a later staged claim so an
        OSP retry retains its exact batch identity and payload.
        """
        self._validate_scan_id(scan_id)
        with self._transaction() as connection:
            if connection.execute(
                "SELECT 1 FROM claims WHERE scan_id = ? AND state = 'ACKING'",
                (scan_id,),
            ).fetchone():
                return None
            row = connection.execute(
                'SELECT * FROM claims WHERE scan_id = ? '
                "AND state IN ('EXPOSED', 'STAGED') "
                "ORDER BY CASE state WHEN 'EXPOSED' THEN 0 ELSE 1 END, "
                'sequence LIMIT 1',
                (scan_id,),
            ).fetchone()
            if row is None:
                return None
            if row['state'] == ClaimState.STAGED.value:
                connection.execute(
                    "UPDATE claims SET state = 'EXPOSED' WHERE sequence = ?",
                    (row['sequence'],),
                )
                row = connection.execute(
                    'SELECT * FROM claims WHERE sequence = ?',
                    (row['sequence'],),
                ).fetchone()
            return self._claim_from_row(row)

    def get_batch(
        self, scan_id: str, osp_batch_id: str
    ) -> Optional[SpoolClaim]:
        """Return one exact pending or tombstoned OSP batch."""
        self._validate_scan_id(scan_id)
        if not isinstance(osp_batch_id, str) or not osp_batch_id:
            raise ResultSpoolValidationError(
                'osp_batch_id must be a non-empty string'
            )
        claims = self._read_claims(
            'SELECT * FROM claims WHERE scan_id = ? AND osp_batch_id = ?',
            (scan_id, osp_batch_id),
        )
        if not claims:
            return None
        if len(claims) != 1:
            raise ResultSpoolCorruptionError('OSP batch identity is not unique')
        return claims[0]

    def begin_ack(
        self,
        scan_id: str,
        osp_batch_id: str,
        redis_db: int,
        source_claim_id: str,
    ) -> SpoolClaim:
        """Durably record gvmd acknowledgement before the Redis acknowledgement."""
        with self._transaction() as connection:
            row = self._exact_claim(
                connection, scan_id, osp_batch_id, redis_db, source_claim_id
            )
            state = ClaimState(row['state'])
            if state == ClaimState.EXPOSED:
                connection.execute(
                    "UPDATE claims SET state = 'ACKING' WHERE sequence = ?",
                    (row['sequence'],),
                )
                row = connection.execute(
                    'SELECT * FROM claims WHERE sequence = ?',
                    (row['sequence'],),
                ).fetchone()
            elif state not in (ClaimState.ACKING, ClaimState.ACKED):
                raise ResultSpoolStateError(
                    f'cannot begin acknowledgement from {state.value}'
                )
            return self._claim_from_row(row)

    def complete_ack(
        self,
        scan_id: str,
        osp_batch_id: str,
        redis_db: int,
        source_claim_id: str,
    ) -> SpoolClaim:
        """Record a successful Redis acknowledgement and retain a small tombstone."""
        with self._transaction() as connection:
            row = self._exact_claim(
                connection, scan_id, osp_batch_id, redis_db, source_claim_id
            )
            state = ClaimState(row['state'])
            if state == ClaimState.ACKING:
                connection.execute(
                    "UPDATE claims SET state = 'ACKED', payload_json = NULL, "
                    "payload_bytes = 0, incomplete_reason = NULL, "
                    "acked_sequence = sequence "
                    'WHERE sequence = ?',
                    (row['sequence'],),
                )
                self._prune_acked(connection)
                row = connection.execute(
                    'SELECT * FROM claims WHERE sequence = ?',
                    (row['sequence'],),
                ).fetchone()
                if row is None:
                    raise ResultSpoolStateError(
                        'acknowledged tombstone was pruned'
                    )
            elif state != ClaimState.ACKED:
                raise ResultSpoolStateError(
                    f'cannot complete acknowledgement from {state.value}'
                )
            return self._claim_from_row(row)

    def pending_records(
        self, scan_id: Optional[str] = None
    ) -> List[SpoolClaim]:
        """Return every recoverable non-ACKED claim in insertion order."""
        if scan_id is not None:
            self._validate_scan_id(scan_id)
            query = (
                "SELECT * FROM claims WHERE scan_id = ? AND state != 'ACKED' "
                'ORDER BY sequence'
            )
            parameters = (scan_id,)
        else:
            query = (
                "SELECT * FROM claims WHERE state != 'ACKED' ORDER BY sequence"
            )
            parameters = ()
        return self._read_claims(query, parameters)

    def recovery_records(self) -> List[SpoolClaim]:
        """Alias for the complete durable non-ACKED recovery view."""
        return self.pending_records()

    def pending_scan_states(self) -> List[PendingScanState]:
        """List aggregate states for scans that still have a pending claim."""
        connection = None
        try:
            connection = self._open_connection()
            rows = connection.execute(
                'SELECT scans.scan_id, scans.count_dead, scans.count_total, '
                'scans.count_excluded, COUNT(claims.sequence) AS pending_claims, '
                'COALESCE(SUM(claims.row_count), 0) AS pending_rows, '
                'COALESCE(SUM(claims.payload_bytes), 0) AS pending_bytes '
                'FROM scans JOIN claims ON claims.scan_id = scans.scan_id '
                "WHERE claims.state != 'ACKED' GROUP BY scans.scan_id "
                'ORDER BY MIN(claims.sequence)',
            ).fetchall()
            return [
                PendingScanState(
                    scan_id=row['scan_id'],
                    pending_claims=row['pending_claims'],
                    pending_rows=row['pending_rows'],
                    pending_bytes=row['pending_bytes'],
                    count_dead=row['count_dead'],
                    count_total=row['count_total'],
                    count_excluded=row['count_excluded'],
                )
                for row in rows
            ]
        except sqlite3.Error as exc:
            raise self._database_error(exc) from exc
        finally:
            if connection is not None:
                connection.close()

    def has_pending(self, scan_id: Optional[str] = None) -> bool:
        """Return whether one scan, or any scan, has a non-ACKED claim."""
        if scan_id is not None:
            self._validate_scan_id(scan_id)
            query = (
                "SELECT 1 FROM claims WHERE scan_id = ? AND state != 'ACKED'"
            )
            parameters = (scan_id,)
        else:
            query = "SELECT 1 FROM claims WHERE state != 'ACKED'"
            parameters = ()
        connection = None
        try:
            connection = self._open_connection()
            return connection.execute(query, parameters).fetchone() is not None
        except sqlite3.Error as exc:
            raise self._database_error(exc) from exc
        finally:
            if connection is not None:
                connection.close()

    def health(self) -> Dict[str, Any]:
        """Return the configured durability contract and quick-check state."""
        connection = None
        try:
            connection = self._open_connection()
            return {
                'quick_check': connection.execute(
                    'PRAGMA quick_check'
                ).fetchone()[0],
                'journal_mode': connection.execute(
                    'PRAGMA journal_mode'
                ).fetchone()[0],
                'synchronous': connection.execute(
                    'PRAGMA synchronous'
                ).fetchone()[0],
                'foreign_keys': connection.execute(
                    'PRAGMA foreign_keys'
                ).fetchone()[0],
                'user_version': connection.execute(
                    'PRAGMA user_version'
                ).fetchone()[0],
            }
        except sqlite3.Error as exc:
            raise self._database_error(exc) from exc
        finally:
            if connection is not None:
                connection.close()

    def delete_scan(self, scan_id: str) -> bool:
        """Delete a scan only after all of its claims reached ACKED."""
        self._validate_scan_id(scan_id)
        with self._transaction() as connection:
            if connection.execute(
                "SELECT 1 FROM claims WHERE scan_id = ? AND state != 'ACKED'",
                (scan_id,),
            ).fetchone():
                raise ResultSpoolStateError(
                    'cannot delete a scan with pending claims'
                )
            deleted = connection.execute(
                'DELETE FROM scans WHERE scan_id = ?', (scan_id,)
            ).rowcount
            return bool(deleted)

    def prune_acked(self) -> int:
        """Prune oldest ACKED tombstones deterministically to their configured bound."""
        with self._transaction() as connection:
            return self._prune_acked(connection)

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        connection = None
        try:
            connection = self._open_connection()
            connection.execute('BEGIN IMMEDIATE')
            try:
                yield connection
            except Exception:
                connection.execute('ROLLBACK')
                raise
            connection.execute('COMMIT')
            self._secure_database_files()
        except ResultSpoolError:
            raise
        except sqlite3.Error as exc:
            raise self._database_error(exc) from exc
        except OSError as exc:
            raise ResultSpoolIOError(str(exc)) from exc
        finally:
            if connection is not None:
                connection.close()

    def _read_claims(self, query: str, parameters: tuple) -> List[SpoolClaim]:
        connection = None
        try:
            connection = self._open_connection()
            return [
                self._claim_from_row(row)
                for row in connection.execute(query, parameters).fetchall()
            ]
        except sqlite3.Error as exc:
            raise self._database_error(exc) from exc
        finally:
            if connection is not None:
                connection.close()

    def _exact_claim(
        self,
        connection: sqlite3.Connection,
        scan_id: str,
        osp_batch_id: str,
        redis_db: int,
        source_claim_id: str,
    ) -> sqlite3.Row:
        self._validate_identity(scan_id, redis_db, source_claim_id)
        if not isinstance(osp_batch_id, str) or not osp_batch_id:
            raise ResultSpoolValidationError(
                'osp_batch_id must be a non-empty string'
            )
        row = connection.execute(
            'SELECT * FROM claims WHERE scan_id = ? AND osp_batch_id = ? '
            'AND redis_db = ? AND source_claim_id = ?',
            (scan_id, osp_batch_id, redis_db, source_claim_id),
        ).fetchone()
        if row is None:
            raise ResultSpoolStateError(
                'claim identity does not match a durable batch'
            )
        return row

    def _check_capacity(
        self,
        connection: sqlite3.Connection,
        scan_id: str,
        row_count: int,
        payload_bytes: int,
    ) -> None:
        if row_count > self.limits.max_claim_rows:
            raise ResultSpoolCapacityError('claim row limit exceeded')
        if payload_bytes > self.limits.max_claim_bytes:
            raise ResultSpoolCapacityError('claim byte limit exceeded')
        scan = connection.execute(
            'SELECT COUNT(*), COALESCE(SUM(row_count), 0), '
            'COALESCE(SUM(payload_bytes), 0) FROM claims '
            "WHERE scan_id = ? AND state != 'ACKED'",
            (scan_id,),
        ).fetchone()
        global_state = connection.execute(
            'SELECT COUNT(*), COALESCE(SUM(row_count), 0), '
            'COALESCE(SUM(payload_bytes), 0) FROM claims '
            "WHERE state != 'ACKED'"
        ).fetchone()
        if scan[0] + 1 > self.limits.max_scan_pending_claims:
            raise ResultSpoolCapacityError(
                'per-scan pending claim limit exceeded'
            )
        if scan[1] + row_count > self.limits.max_scan_pending_rows:
            raise ResultSpoolCapacityError(
                'per-scan pending row limit exceeded'
            )
        if scan[2] + payload_bytes > self.limits.max_scan_pending_bytes:
            raise ResultSpoolCapacityError(
                'per-scan pending byte limit exceeded'
            )
        if global_state[0] + 1 > self.limits.max_global_pending_claims:
            raise ResultSpoolCapacityError(
                'global pending claim limit exceeded'
            )
        if global_state[1] + row_count > self.limits.max_global_pending_rows:
            raise ResultSpoolCapacityError('global pending row limit exceeded')
        if (
            global_state[2] + payload_bytes
            > self.limits.max_global_pending_bytes
        ):
            raise ResultSpoolCapacityError('global pending byte limit exceeded')

    def _prune_acked(self, connection: sqlite3.Connection) -> int:
        excess = (
            connection.execute(
                "SELECT COUNT(*) FROM claims WHERE state = 'ACKED'"
            ).fetchone()[0]
            - self.limits.max_acked_tombstones
        )
        if excess <= 0:
            return 0
        deleted = connection.execute(
            "DELETE FROM claims WHERE sequence IN ("
            "SELECT sequence FROM claims WHERE state = 'ACKED' "
            'ORDER BY acked_sequence, sequence LIMIT ?)',
            (excess,),
        ).rowcount
        return deleted

    def _claim_from_row(self, row: sqlite3.Row) -> SpoolClaim:
        digest = row['digest']
        if not self._is_digest(digest):
            raise ResultSpoolCorruptionError('claim has a malformed digest')
        state = ClaimState(row['state'])
        payload_json = row['payload_json']
        if state == ClaimState.ACKED:
            if payload_json is not None or row['payload_bytes'] != 0:
                raise ResultSpoolCorruptionError(
                    'ACKED tombstone retains result payload'
                )
            results: List[Dict[str, Any]] = []
        else:
            if not isinstance(payload_json, str):
                raise ResultSpoolCorruptionError(
                    'pending claim has no result payload'
                )
            results = self._decode_rows(payload_json)
            if len(results) != row['row_count']:
                raise ResultSpoolCorruptionError(
                    'claim row count does not match payload'
                )
            if len(payload_json.encode('utf-8')) != row['payload_bytes']:
                raise ResultSpoolCorruptionError(
                    'claim byte count does not match payload'
                )
            metadata = (
                row['count_dead'],
                row['count_total'],
                row['count_excluded'],
                row['incomplete_reason'],
            )
            if self._digest(payload_json, metadata) != digest:
                raise ResultSpoolCorruptionError(
                    'claim digest does not match payload'
                )
        return SpoolClaim(
            scan_id=row['scan_id'],
            redis_db=row['redis_db'],
            source_claim_id=row['source_claim_id'],
            osp_batch_id=row['osp_batch_id'],
            state=state,
            results=results,
            count_dead=row['count_dead'],
            count_total=row['count_total'],
            count_excluded=row['count_excluded'],
            incomplete_reason=row['incomplete_reason'],
            digest=digest,
        )

    def _validate_stored_state(self, connection: sqlite3.Connection) -> None:
        try:
            for row in connection.execute('SELECT * FROM claims'):
                self._claim_from_row(row)
        except ResultSpoolError:
            raise
        except (sqlite3.Error, ValueError, TypeError) as exc:
            raise ResultSpoolCorruptionError(str(exc)) from exc

    def _open_connection(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            str(self.path),
            timeout=self._busy_timeout_ms / 1000,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute('PRAGMA foreign_keys = ON')
        connection.execute(f'PRAGMA busy_timeout = {self._busy_timeout_ms}')
        connection.execute('PRAGMA synchronous = FULL')
        connection.execute('PRAGMA trusted_schema = OFF')
        return connection

    def _prepare_path(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            self._check_owner_only(self.path.parent, directory=True)
            flags = os.O_CREAT | os.O_RDWR | getattr(os, 'O_CLOEXEC', 0)
            flags |= getattr(os, 'O_NOFOLLOW', 0)
            descriptor = os.open(self.path, flags, 0o600)
            try:
                details = os.fstat(descriptor)
                if not stat.S_ISREG(details.st_mode):
                    raise ResultSpoolIOError(
                        'spool database has an unsafe file type'
                    )
                if details.st_uid != os.geteuid():
                    raise ResultSpoolIOError(
                        'spool database is not owned by the current user'
                    )
                if stat.S_IMODE(details.st_mode) & 0o077:
                    raise ResultSpoolIOError(
                        'spool database permits group or other access'
                    )
            finally:
                os.close(descriptor)
        except ResultSpoolError:
            raise
        except OSError as exc:
            raise ResultSpoolIOError(str(exc)) from exc

    def _secure_database_files(self) -> None:
        for candidate in (
            self.path,
            Path(f'{self.path}-wal'),
            Path(f'{self.path}-shm'),
        ):
            if candidate.exists():
                if candidate.is_symlink():
                    raise ResultSpoolIOError(
                        f'{candidate} must not be a symlink'
                    )
                self._check_owner_only(candidate, directory=False)

    @staticmethod
    def _check_owner_only(path: Path, *, directory: bool) -> None:
        details = path.stat()
        expected = (
            stat.S_ISDIR(details.st_mode)
            if directory
            else stat.S_ISREG(details.st_mode)
        )
        if not expected:
            raise ResultSpoolIOError(f'{path} has an unsafe file type')
        if details.st_uid != os.geteuid():
            raise ResultSpoolIOError(f'{path} is not owned by the current user')
        if stat.S_IMODE(details.st_mode) & 0o077:
            raise ResultSpoolIOError(f'{path} permits group or other access')

    @staticmethod
    def _validate_limits(limits: SpoolLimits) -> None:
        for value in (
            limits.max_result_row_bytes,
            limits.max_claim_rows,
            limits.max_claim_bytes,
            limits.max_scan_pending_rows,
            limits.max_scan_pending_bytes,
            limits.max_scan_pending_claims,
            limits.max_global_pending_rows,
            limits.max_global_pending_bytes,
            limits.max_global_pending_claims,
        ):
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or value <= 0
            ):
                raise ResultSpoolValidationError(
                    'spool limits must be positive integers'
                )
        if (
            not isinstance(limits.max_acked_tombstones, int)
            or isinstance(limits.max_acked_tombstones, bool)
            or limits.max_acked_tombstones < 1
        ):
            raise ResultSpoolValidationError(
                'max_acked_tombstones must be a positive integer'
            )

    @staticmethod
    def _validate_scan_id(scan_id: str) -> None:
        if not isinstance(scan_id, str) or not scan_id:
            raise ResultSpoolValidationError(
                'scan_id must be a non-empty string'
            )

    def _validate_identity(
        self, scan_id: str, redis_db: int, source_claim_id: str
    ) -> None:
        self._validate_scan_id(scan_id)
        if (
            not isinstance(redis_db, int)
            or isinstance(redis_db, bool)
            or redis_db < 0
        ):
            raise ResultSpoolValidationError(
                'redis_db must be a non-negative integer'
            )
        if not isinstance(source_claim_id, str) or not source_claim_id:
            raise ResultSpoolValidationError(
                'source_claim_id must be a non-empty string'
            )

    @staticmethod
    def _validate_metadata(
        count_dead: int,
        count_total: Optional[int],
        count_excluded: Optional[int],
        incomplete_reason: Optional[str],
    ) -> tuple:
        for value, name in (
            (count_dead, 'count_dead'),
            (count_total, 'count_total'),
            (count_excluded, 'count_excluded'),
        ):
            if value is not None and (
                not isinstance(value, int)
                or isinstance(value, bool)
                or value < 0
            ):
                raise ResultSpoolValidationError(
                    f'{name} must be a non-negative integer or None'
                )
        if incomplete_reason is not None:
            if not isinstance(incomplete_reason, str):
                raise ResultSpoolValidationError(
                    'incomplete_reason must be a string or None'
                )
            if (
                len(incomplete_reason.encode('utf-8'))
                > MAX_INCOMPLETE_REASON_BYTES
            ):
                raise ResultSpoolCapacityError('incomplete reason is too large')
        return count_dead, count_total, count_excluded, incomplete_reason

    def _canonical_rows(self, results: Iterable[Mapping[str, Any]]) -> tuple:
        if isinstance(results, (str, bytes)):
            raise ResultSpoolSerializationError(
                'results must be an iterable of maps'
            )
        try:
            source_rows = list(results)
        except TypeError as exc:
            raise ResultSpoolSerializationError(
                'results is not iterable'
            ) from exc
        normalized_rows: List[Dict[str, Any]] = []
        for result in source_rows:
            if not isinstance(result, Mapping):
                raise ResultSpoolSerializationError(
                    'every result must be a mapping'
                )
            normalized = self._normalize_json(dict(result))
            if not isinstance(normalized, dict):
                raise ResultSpoolSerializationError(
                    'every result must normalize to a map'
                )
            encoded = self._canonical_json(normalized)
            if len(encoded.encode('utf-8')) > self.limits.max_result_row_bytes:
                raise ResultSpoolCapacityError('result row byte limit exceeded')
            normalized_rows.append(normalized)
        payload_json = self._canonical_json(normalized_rows)
        return payload_json, normalized_rows

    def _decode_rows(self, payload_json: str) -> List[Dict[str, Any]]:
        try:
            decoded = json.loads(payload_json)
        except (TypeError, ValueError) as exc:
            raise ResultSpoolCorruptionError(
                'claim payload is not valid JSON'
            ) from exc
        if not isinstance(decoded, list) or any(
            not isinstance(result, dict) for result in decoded
        ):
            raise ResultSpoolCorruptionError(
                'claim payload is not a list of maps'
            )
        if self._canonical_json(decoded) != payload_json:
            raise ResultSpoolCorruptionError(
                'claim payload is not canonical JSON'
            )
        return decoded

    @classmethod
    def _normalize_json(cls, value: Any) -> Any:
        if value is None or isinstance(value, (str, int, bool)):
            return value
        if isinstance(value, float):
            if value != value or value in (float('inf'), float('-inf')):
                raise ResultSpoolSerializationError(
                    'result contains a non-finite float'
                )
            return value
        if isinstance(value, list):
            return [cls._normalize_json(item) for item in value]
        if isinstance(value, dict):
            normalized: Dict[str, Any] = {}
            for key, item in value.items():
                if not isinstance(key, str):
                    raise ResultSpoolSerializationError(
                        'result maps must have string keys'
                    )
                normalized[key] = cls._normalize_json(item)
            return normalized
        raise ResultSpoolSerializationError(
            f'result contains unsupported value type {type(value).__name__}'
        )

    @staticmethod
    def _canonical_json(value: Any) -> str:
        try:
            return json.dumps(
                value,
                ensure_ascii=False,
                sort_keys=True,
                separators=(',', ':'),
                allow_nan=False,
            )
        except (TypeError, ValueError) as exc:
            raise ResultSpoolSerializationError(
                'result cannot be canonically serialized'
            ) from exc

    @classmethod
    def _digest(cls, payload_json: str, metadata: tuple) -> str:
        document = cls._canonical_json(
            {
                'count_dead': metadata[0],
                'count_excluded': metadata[2],
                'count_total': metadata[1],
                'incomplete_reason': metadata[3],
                'results': json.loads(payload_json),
            }
        )
        return hashlib.sha256(document.encode('utf-8')).hexdigest()

    @staticmethod
    def _is_digest(value: Any) -> bool:
        return (
            isinstance(value, str)
            and len(value) == 64
            and all(character in '0123456789abcdef' for character in value)
        )

    @staticmethod
    def _database_error(exc: sqlite3.Error) -> ResultSpoolError:
        message = str(exc).lower()
        if any(
            marker in message
            for marker in ('malformed', 'not a database', 'database disk image')
        ):
            return ResultSpoolCorruptionError(str(exc))
        return ResultSpoolIOError(str(exc))
