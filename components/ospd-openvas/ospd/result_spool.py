# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Durable, source-aware result spooling for OSPD result delivery.

Redis claims and admitted Notus messages are staged as stable OSP batches. The
spool keeps source acknowledgement separate so Notus results never enter the
Redis-release path and admitted evidence survives every process boundary.
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
MAX_NOTUS_RESULT_BYTES = 64 * 1024
MAX_NOTUS_SCAN_PENDING_ROWS = 10_000
MAX_NOTUS_SCAN_PENDING_BYTES = 4 * 1024 * 1024
MAX_NOTUS_GLOBAL_PENDING_ROWS = 100_000
MAX_NOTUS_GLOBAL_PENDING_BYTES = 32 * 1024 * 1024
MAX_NOTUS_PENDING_SCANS = 128
MAX_NOTUS_ACKED_TOMBSTONES = 100_000
MAX_NOTUS_MANIFEST_BYTES = 4 * 1024 * 1024
DEFAULT_BUSY_TIMEOUT_MS = 5000
DEFAULT_ACKED_TOMBSTONES = 10_000
NOTUS_REDIS_DB = -1


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


class SourceKind(str, Enum):
    """The external source whose evidence is retained by one claim."""

    REDIS = 'redis'
    NOTUS = 'notus'


class NotusRunState(str, Enum):
    """Durable lifecycle state for one table-driven LSC host run."""

    PENDING_START = 'PENDING_START'
    STARTED = 'STARTED'
    RUNNING = 'RUNNING'
    FINISHED = 'FINISHED'
    INTERRUPTED = 'INTERRUPTED'


class NotusManifestMode(str, Enum):
    """The authoritative table-driven LSC transport selected by OpenVAS."""

    MQTT = 'mqtt'
    NONE = 'none'


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
    max_notus_result_bytes: int = MAX_NOTUS_RESULT_BYTES
    max_notus_scan_pending_rows: int = MAX_NOTUS_SCAN_PENDING_ROWS
    max_notus_scan_pending_bytes: int = MAX_NOTUS_SCAN_PENDING_BYTES
    max_notus_global_pending_rows: int = MAX_NOTUS_GLOBAL_PENDING_ROWS
    max_notus_global_pending_bytes: int = MAX_NOTUS_GLOBAL_PENDING_BYTES
    max_notus_pending_scans: int = MAX_NOTUS_PENDING_SCANS
    max_notus_acked_tombstones: int = MAX_NOTUS_ACKED_TOMBSTONES


@dataclass(frozen=True)
class SpoolClaim:
    """A durable source claim and its one stable OSP batch."""

    scan_id: str
    source_kind: SourceKind
    redis_db: int
    owner_token: Optional[str]
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
class NotusBatch:
    """One durable, stable batch of accepted Notus MQTT messages."""

    scan_id: str
    batch_id: str
    results: List[Dict[str, Any]]


@dataclass(frozen=True)
class NotusRun:
    """One durable Notus run and its terminal result-count fence."""

    scan_id: str
    run_id: str
    host_ip: str
    state: NotusRunState
    expected_result_count: Optional[int]
    admitted_result_count: int
    start_message_id: Optional[str]
    terminal_message_id: Optional[str]


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
    incomplete_reason: Optional[str]


class ResultSpool:
    """SQLite-backed durable source-claim spool.

    Connections are opened per operation so the same lightweight object is
    safe to inherit into scanner processes and use from OSP request threads.
    Write transitions use ``BEGIN IMMEDIATE`` and SQLite's busy timeout.
    """

    _REQUIRED_CLAIM_COLUMNS = frozenset(
        {
            'sequence',
            'scan_id',
            'source_kind',
            'redis_db',
            'owner_token',
            'source_claim_id',
            'osp_batch_id',
            'state',
            'payload_json',
            'row_count',
            'payload_bytes',
            'count_dead',
            'count_total',
            'count_excluded',
            'incomplete_reason',
            'digest',
            'acked_sequence',
        }
    )
    _REQUIRED_SCAN_COLUMNS = frozenset(
        {
            'scan_id',
            'count_dead',
            'count_total',
            'count_excluded',
            'incomplete_reason',
            'notus_manifest_mode',
            'notus_manifest_json',
            'notus_manifest_digest',
        }
    )
    _REQUIRED_NOTUS_COLUMNS = frozenset(
        {
            'sequence',
            'scan_id',
            'message_id',
            'run_id',
            'batch_id',
            'payload_json',
            'payload_bytes',
            'digest',
            'acked',
            'acked_sequence',
        }
    )
    _REQUIRED_NOTUS_RUN_COLUMNS = frozenset(
        {
            'sequence',
            'scan_id',
            'run_id',
            'host_ip',
            'start_message_id',
            'start_digest',
            'state',
            'expected_result_count',
            'admitted_result_count',
            'terminal_message_id',
            'terminal_digest',
        }
    )

    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS scans (
        scan_id TEXT PRIMARY KEY,
        count_dead INTEGER NOT NULL DEFAULT 0,
        count_total INTEGER,
        count_excluded INTEGER,
        incomplete_reason TEXT,
        notus_manifest_mode TEXT CHECK(notus_manifest_mode IN (
            'mqtt', 'none'
        )),
        notus_manifest_json TEXT,
        notus_manifest_digest TEXT
    );
    CREATE TABLE IF NOT EXISTS claims (
        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
        source_kind TEXT NOT NULL DEFAULT 'redis'
            CHECK(source_kind IN ('redis', 'notus')),
        redis_db INTEGER NOT NULL,
        owner_token TEXT,
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
    CREATE TABLE IF NOT EXISTS notus_ingress (
        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
        message_id TEXT NOT NULL,
        run_id TEXT,
        batch_id TEXT,
        payload_json TEXT,
        payload_bytes INTEGER NOT NULL,
        digest TEXT NOT NULL,
        acked INTEGER NOT NULL DEFAULT 0 CHECK(acked IN (0, 1)),
        acked_sequence INTEGER,
        UNIQUE(message_id)
    );
    CREATE TABLE IF NOT EXISTS notus_runs (
        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
        run_id TEXT NOT NULL,
        host_ip TEXT NOT NULL,
        start_message_id TEXT UNIQUE,
        start_digest TEXT,
        state TEXT NOT NULL CHECK(state IN (
            'PENDING_START', 'STARTED', 'RUNNING', 'FINISHED', 'INTERRUPTED'
        )),
        expected_result_count INTEGER
            CHECK(expected_result_count IS NULL OR expected_result_count >= 0),
        admitted_result_count INTEGER NOT NULL DEFAULT 0
            CHECK(admitted_result_count >= 0),
        terminal_message_id TEXT UNIQUE,
        terminal_digest TEXT,
        UNIQUE(scan_id, run_id)
    );
    CREATE INDEX IF NOT EXISTS notus_runs_scan_state
        ON notus_runs(scan_id, state, sequence);
    CREATE INDEX IF NOT EXISTS notus_ingress_pending_scan_sequence
        ON notus_ingress(scan_id, acked, sequence);
    CREATE INDEX IF NOT EXISTS notus_ingress_batch
        ON notus_ingress(scan_id, batch_id, acked, sequence);
    CREATE INDEX IF NOT EXISTS notus_ingress_acked_sequence
        ON notus_ingress(acked, acked_sequence, sequence);
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
            claim_columns = {
                row['name']
                for row in connection.execute('PRAGMA table_info(claims)')
            }
            scan_columns = {
                row['name']
                for row in connection.execute('PRAGMA table_info(scans)')
            }
            if user_version in (0, 1):
                if 'owner_token' not in claim_columns:
                    connection.execute(
                        'ALTER TABLE claims ADD COLUMN owner_token TEXT'
                    )
                    claim_columns.add('owner_token')
            elif user_version == 2 and 'owner_token' not in claim_columns:
                raise ResultSpoolCorruptionError(
                    'version 2 result spool is missing owner_token'
                )
            if user_version in (0, 1, 2):
                if 'source_kind' not in claim_columns:
                    connection.execute(
                        "ALTER TABLE claims ADD COLUMN source_kind TEXT "
                        "NOT NULL DEFAULT 'redis' "
                        "CHECK(source_kind IN ('redis', 'notus'))"
                    )
                    claim_columns.add('source_kind')
                if 'incomplete_reason' not in scan_columns:
                    connection.execute(
                        'ALTER TABLE scans ADD COLUMN incomplete_reason TEXT'
                    )
                    scan_columns.add('incomplete_reason')
                connection.execute('PRAGMA user_version = 3')
                user_version = 3
            elif user_version not in (3, 4, 5):
                raise ResultSpoolCorruptionError(
                    f'unsupported result spool schema version {user_version}'
                )
            notus_columns = {
                row['name']
                for row in connection.execute(
                    'PRAGMA table_info(notus_ingress)'
                )
            }
            if user_version == 3:
                if 'run_id' not in notus_columns:
                    connection.execute(
                        'ALTER TABLE notus_ingress ADD COLUMN run_id TEXT'
                    )
                    notus_columns.add('run_id')
                legacy_rows = connection.execute(
                    'SELECT sequence, scan_id, message_id, payload_json '
                    'FROM notus_ingress WHERE run_id IS NULL'
                ).fetchall()
                for legacy in legacy_rows:
                    try:
                        payload = json.loads(legacy['payload_json'])
                        run_id = payload.get('group_id')
                    except (TypeError, ValueError):
                        run_id = None
                    if not isinstance(run_id, str) or not run_id:
                        run_id = f"legacy-{legacy['message_id']}"
                    connection.execute(
                        'UPDATE notus_ingress SET run_id = ? '
                        'WHERE sequence = ?',
                        (run_id, legacy['sequence']),
                    )
                    connection.execute(
                        'INSERT OR IGNORE INTO notus_runs '
                        '(scan_id, run_id, host_ip, state, '
                        'admitted_result_count) VALUES (?, ?, ?, ?, 0)',
                        (
                            legacy['scan_id'],
                            run_id,
                            '',
                            NotusRunState.PENDING_START.value,
                        ),
                    )
                    connection.execute(
                        'UPDATE scans SET incomplete_reason = '
                        'COALESCE(incomplete_reason, ?) WHERE scan_id = ?',
                        (
                            'Legacy Notus evidence has no terminal '
                            'completion fence.',
                            legacy['scan_id'],
                        ),
                    )
                connection.execute(
                    'UPDATE notus_runs SET admitted_result_count = ('
                    'SELECT COUNT(*) FROM notus_ingress '
                    'WHERE notus_ingress.scan_id = notus_runs.scan_id '
                    'AND notus_ingress.run_id = notus_runs.run_id)'
                )
                connection.execute('PRAGMA user_version = 4')
                user_version = 4
            if user_version == 4:
                for name in (
                    'notus_manifest_mode',
                    'notus_manifest_json',
                    'notus_manifest_digest',
                ):
                    if name not in scan_columns:
                        connection.execute(
                            f'ALTER TABLE scans ADD COLUMN {name} TEXT'
                        )
                        scan_columns.add(name)
                connection.execute(
                    'UPDATE scans SET incomplete_reason = '
                    'COALESCE(incomplete_reason, ?) '
                    'WHERE EXISTS (SELECT 1 FROM notus_runs '
                    'WHERE notus_runs.scan_id = scans.scan_id)',
                    (
                        'Legacy Notus evidence has no sealed expectation '
                        'manifest.',
                    ),
                )
                connection.execute('PRAGMA user_version = 5')
            claim_columns = {
                row['name']
                for row in connection.execute('PRAGMA table_info(claims)')
            }
            scan_columns = {
                row['name']
                for row in connection.execute('PRAGMA table_info(scans)')
            }
            notus_columns = {
                row['name']
                for row in connection.execute(
                    'PRAGMA table_info(notus_ingress)'
                )
            }
            notus_run_columns = {
                row['name']
                for row in connection.execute('PRAGMA table_info(notus_runs)')
            }
            if self._REQUIRED_CLAIM_COLUMNS - claim_columns:
                raise ResultSpoolCorruptionError(
                    'result spool schema is missing required claim columns'
                )
            if self._REQUIRED_SCAN_COLUMNS - scan_columns:
                raise ResultSpoolCorruptionError(
                    'result spool schema is missing required scan columns'
                )
            if self._REQUIRED_NOTUS_COLUMNS - notus_columns:
                raise ResultSpoolCorruptionError(
                    'result spool schema is missing required Notus columns'
                )
            if self._REQUIRED_NOTUS_RUN_COLUMNS - notus_run_columns:
                raise ResultSpoolCorruptionError(
                    'result spool schema is missing required Notus run columns'
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

    def has_pending_claim(self, scan_id: str) -> bool:
        """Return whether any source owns the scan's one OSP claim slot."""
        self._validate_scan_id(scan_id)
        connection = None
        try:
            connection = self._open_connection()
            return (
                connection.execute(
                    'SELECT 1 FROM claims WHERE scan_id = ? '
                    "AND state != 'ACKED'",
                    (scan_id,),
                ).fetchone()
                is not None
            )
        except sqlite3.Error as exc:
            raise self._database_error(exc) from exc
        finally:
            if connection is not None:
                connection.close()

    def has_pending_redis(self, scan_id: str) -> bool:
        """Return whether Redis owns the scan's current OSP claim slot."""
        self._validate_scan_id(scan_id)
        connection = None
        try:
            connection = self._open_connection()
            return (
                connection.execute(
                    'SELECT 1 FROM claims WHERE scan_id = ? '
                    "AND source_kind = 'redis' AND state != 'ACKED'",
                    (scan_id,),
                ).fetchone()
                is not None
            )
        except sqlite3.Error as exc:
            raise self._database_error(exc) from exc
        finally:
            if connection is not None:
                connection.close()

    def has_materializable_notus(self, scan_id: str) -> bool:
        """Return whether Notus ingress can acquire the current claim slot."""
        self._validate_scan_id(scan_id)
        connection = None
        try:
            connection = self._open_connection()
            if connection.execute(
                "SELECT 1 FROM claims WHERE scan_id = ? AND state != 'ACKED'",
                (scan_id,),
            ).fetchone():
                return False
            return (
                connection.execute(
                    'SELECT 1 FROM notus_ingress '
                    'WHERE scan_id = ? AND acked = 0',
                    (scan_id,),
                ).fetchone()
                is not None
            )
        except sqlite3.Error as exc:
            raise self._database_error(exc) from exc
        finally:
            if connection is not None:
                connection.close()

    def has_unmaterialized_notus(self, scan_id: str) -> bool:
        """Return whether admitted Notus evidence has no durable OSP claim."""
        self._validate_scan_id(scan_id)
        connection = None
        try:
            connection = self._open_connection()
            return (
                connection.execute(
                    'SELECT 1 FROM notus_ingress ingress '
                    'WHERE ingress.scan_id = ? AND ingress.acked = 0 '
                    'AND (ingress.batch_id IS NULL OR NOT EXISTS ('
                    'SELECT 1 FROM claims WHERE '
                    'claims.scan_id = ingress.scan_id '
                    "AND claims.source_kind = 'notus' "
                    'AND claims.source_claim_id = ingress.batch_id))',
                    (scan_id,),
                ).fetchone()
                is not None
            )
        except sqlite3.Error as exc:
            raise self._database_error(exc) from exc
        finally:
            if connection is not None:
                connection.close()

    def has_pending_notus(self, scan_id: str) -> bool:
        """Return whether a scan has admitted Notus evidence not yet retired."""
        self._validate_scan_id(scan_id)
        connection = None
        try:
            connection = self._open_connection()
            return (
                connection.execute(
                    'SELECT 1 FROM notus_ingress '
                    'WHERE scan_id = ? AND acked = 0',
                    (scan_id,),
                ).fetchone()
                is not None
            )
        except sqlite3.Error as exc:
            raise self._database_error(exc) from exc
        finally:
            if connection is not None:
                connection.close()

    def pending_notus_scan_ids(self) -> List[str]:
        """Return scans with admitted or unfinished Notus work."""
        connection = None
        try:
            connection = self._open_connection()
            return [
                row['scan_id']
                for row in connection.execute(
                    'SELECT scan_id, MIN(sequence) AS first_sequence FROM ('
                    'SELECT scan_id, sequence FROM notus_ingress '
                    'WHERE acked = 0 UNION ALL '
                    'SELECT runs.scan_id, runs.sequence FROM notus_runs runs '
                    'JOIN scans ON scans.scan_id = runs.scan_id '
                    'WHERE scans.notus_manifest_mode IS NULL '
                    "OR runs.state != 'FINISHED' "
                    'OR runs.start_message_id IS NULL '
                    'OR runs.expected_result_count IS NULL '
                    'OR runs.admitted_result_count '
                    '!= runs.expected_result_count) '
                    'GROUP BY scan_id ORDER BY first_sequence'
                ).fetchall()
            ]
        except sqlite3.Error as exc:
            raise self._database_error(exc) from exc
        finally:
            if connection is not None:
                connection.close()

    def seal_notus_manifest(
        self,
        scan_id: str,
        mode: str,
        entries: Iterable[Mapping[str, Any]],
    ) -> bool:
        """Persist OpenVAS's exact, terminal Notus expectation manifest."""
        self._validate_scan_id(scan_id)
        try:
            manifest_mode = NotusManifestMode(mode)
        except (TypeError, ValueError) as exc:
            raise ResultSpoolValidationError(
                'unsupported Notus manifest mode'
            ) from exc
        normalized = self._normalize_notus_manifest(entries)
        if manifest_mode != NotusManifestMode.MQTT and normalized:
            raise ResultSpoolValidationError(
                'non-MQTT Notus manifests must not contain runs'
            )
        manifest_json = self._canonical_json(normalized)
        if len(manifest_json.encode('utf-8')) > MAX_NOTUS_MANIFEST_BYTES:
            raise ResultSpoolCapacityError('Notus manifest exceeds byte limit')
        digest = self._notus_event_digest(
            {'mode': manifest_mode.value, 'runs': normalized}
        )
        failure = None
        changed = False
        with self._transaction() as connection:
            self._require_registered_scan(connection, scan_id)
            scan = connection.execute(
                'SELECT * FROM scans WHERE scan_id = ?', (scan_id,)
            ).fetchone()
            if scan['notus_manifest_mode'] is not None:
                if (
                    scan['notus_manifest_mode'] == manifest_mode.value
                    and scan['notus_manifest_json'] == manifest_json
                    and scan['notus_manifest_digest'] == digest
                ):
                    return False
                failure = 'The sealed Notus expectation manifest changed.'
            else:
                expected = {entry['run_id']: entry for entry in normalized}
                observed = connection.execute(
                    'SELECT * FROM notus_runs WHERE scan_id = ?', (scan_id,)
                ).fetchall()
                if manifest_mode != NotusManifestMode.MQTT and observed:
                    failure = (
                        'Notus MQTT work was observed for a non-MQTT scan.'
                    )
                else:
                    for row in observed:
                        if row['start_message_id'] is None:
                            continue
                        entry = expected.get(row['run_id'])
                        if entry is None or (
                            entry['start_message_id'] != row['start_message_id']
                            or entry['host_ip'] != row['host_ip']
                        ):
                            failure = (
                                'Observed Notus work does not match the '
                                'OpenVAS expectation manifest.'
                            )
                            break
                if failure is None:
                    connection.execute(
                        'UPDATE scans SET notus_manifest_mode = ?, '
                        'notus_manifest_json = ?, notus_manifest_digest = ? '
                        'WHERE scan_id = ?',
                        (
                            manifest_mode.value,
                            manifest_json,
                            digest,
                            scan_id,
                        ),
                    )
                    changed = True
            if failure is not None:
                self._mark_scans_incomplete(connection, failure, scan_id)
        if failure is not None:
            raise ResultSpoolConflictError(failure)
        return changed

    def notus_completion_ready(self, scan_id: str) -> bool:
        """Return whether the exact sealed Notus manifest reached its fence."""
        self._validate_scan_id(scan_id)
        connection = None
        try:
            connection = self._open_connection()
            scan = connection.execute(
                'SELECT * FROM scans WHERE scan_id = ?', (scan_id,)
            ).fetchone()
            if scan is None:
                raise ResultSpoolStateError(
                    'Notus completion scan is not durably registered'
                )
            manifest = self._notus_manifest_from_row(scan)
            if manifest is None:
                return False
            manifest_mode, entries = manifest
            rows = connection.execute(
                'SELECT * FROM notus_runs WHERE scan_id = ? ORDER BY sequence',
                (scan_id,),
            ).fetchall()
            if manifest_mode != NotusManifestMode.MQTT:
                return not rows and not self._has_notus_ingress(
                    connection, scan_id
                )
            expected = {entry['run_id']: entry for entry in entries}
            if len(rows) != len(expected):
                return False
            for row in rows:
                run = self._notus_run_from_row(row)
                entry = expected.get(run.run_id)
                if (
                    entry is None
                    or run.start_message_id != entry['start_message_id']
                    or run.host_ip != entry['host_ip']
                    or run.state != NotusRunState.FINISHED
                    or run.expected_result_count is None
                    or run.admitted_result_count != run.expected_result_count
                ):
                    return False
            return (
                connection.execute(
                    'SELECT 1 FROM notus_ingress ingress '
                    'WHERE ingress.scan_id = ? AND ingress.acked = 0 '
                    'AND (ingress.batch_id IS NULL OR NOT EXISTS ('
                    'SELECT 1 FROM claims WHERE '
                    'claims.scan_id = ingress.scan_id '
                    "AND claims.source_kind = 'notus' "
                    'AND claims.source_claim_id = ingress.batch_id))',
                    (scan_id,),
                ).fetchone()
                is None
            )
        except sqlite3.Error as exc:
            raise self._database_error(exc) from exc
        finally:
            if connection is not None:
                connection.close()

    def notus_completion_issue(self, scan_id: str) -> Optional[str]:
        """Return a terminal Notus integrity reason, if one is known."""
        self._validate_scan_id(scan_id)
        connection = None
        try:
            connection = self._open_connection()
            scan = connection.execute(
                'SELECT incomplete_reason, notus_manifest_mode, '
                'notus_manifest_json, notus_manifest_digest '
                'FROM scans WHERE scan_id = ?',
                (scan_id,),
            ).fetchone()
            if scan is None:
                raise ResultSpoolStateError(
                    'Notus completion scan is not durably registered'
                )
            if scan['incomplete_reason']:
                return scan['incomplete_reason']
            manifest = self._notus_manifest_from_row(scan)
            if manifest is None:
                return 'The Notus expectation manifest is not sealed.'
            if connection.execute(
                'SELECT 1 FROM notus_runs WHERE scan_id = ? '
                "AND state = 'INTERRUPTED'",
                (scan_id,),
            ).fetchone():
                return 'Notus reported an interrupted package scan.'
            return None
        except sqlite3.Error as exc:
            raise self._database_error(exc) from exc
        finally:
            if connection is not None:
                connection.close()

    def close(self) -> None:
        """Retained for context-manager compatibility; no connection is held."""

    def __enter__(self) -> 'ResultSpool':
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    def register_scan(self, scan_id: str) -> bool:
        """Register an active scan before any asynchronous source can admit."""
        self._validate_scan_id(scan_id)
        with self._transaction() as connection:
            return bool(
                connection.execute(
                    'INSERT OR IGNORE INTO scans '
                    '(scan_id, count_dead, count_total, count_excluded) '
                    'VALUES (?, 0, NULL, NULL)',
                    (scan_id,),
                ).rowcount
            )

    def stage_claim(
        self,
        scan_id: str,
        redis_db: int,
        source_claim_id: str,
        owner_token: str,
        results: Iterable[Mapping[str, Any]],
        *,
        count_dead: int = 0,
        count_total: Optional[int] = None,
        count_excluded: Optional[int] = None,
        incomplete_reason: Optional[str] = None,
    ) -> SpoolClaim:
        """Stage one Redis source claim, or return its exact durable replay."""
        self._validate_identity(scan_id, redis_db, source_claim_id)
        self._validate_owner_token(owner_token)
        metadata = self._validate_metadata(
            count_dead, count_total, count_excluded, incomplete_reason
        )
        payload_json, normalized_rows = self._canonical_rows(results)
        payload_bytes = len(payload_json.encode('utf-8'))
        digest = self._digest(payload_json, metadata)

        with self._transaction() as connection:
            existing = connection.execute(
                'SELECT * FROM claims WHERE redis_db = ? '
                'AND source_claim_id = ?',
                (redis_db, source_claim_id),
            ).fetchone()
            if existing is not None:
                claim = self._claim_from_row(existing)
                if (
                    claim.scan_id != scan_id
                    or claim.digest != digest
                    or claim.owner_token != owner_token
                ):
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
                'count_excluded = COALESCE(?, count_excluded), '
                'incomplete_reason = COALESCE(incomplete_reason, ?) '
                'WHERE scan_id = ?',
                (
                    count_dead,
                    count_total,
                    count_excluded,
                    incomplete_reason,
                    scan_id,
                ),
            )
            osp_batch_id = str(uuid.uuid4())
            connection.execute(
                'INSERT INTO claims '
                '(scan_id, source_kind, redis_db, owner_token, '
                'source_claim_id, '
                'osp_batch_id, state, '
                'payload_json, row_count, payload_bytes, count_dead, '
                'count_total, count_excluded, incomplete_reason, digest) '
                'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                (
                    scan_id,
                    SourceKind.REDIS.value,
                    redis_db,
                    owner_token,
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
                'SELECT * FROM claims WHERE redis_db = ? '
                'AND source_claim_id = ?',
                (redis_db, source_claim_id),
            ).fetchone()
            return self._claim_from_row(row)

    def admit_notus_start(
        self,
        scan_id: str,
        run_id: str,
        message_id: str,
        host_ip: str,
    ) -> bool:
        """Durably register one Notus run before accepting its results."""
        self._validate_scan_id(scan_id)
        self._validate_notus_run_id(run_id)
        self._validate_notus_message_id(message_id)
        self._validate_notus_host_ip(host_ip)
        if not host_ip:
            raise ResultSpoolValidationError(
                'Notus start host identity must not be empty'
            )
        digest = self._notus_event_digest(
            {
                'kind': 'start',
                'scan_id': scan_id,
                'run_id': run_id,
                'message_id': message_id,
                'host_ip': host_ip,
            }
        )
        failure = None
        failure_type = ResultSpoolConflictError
        admitted = False
        with self._transaction() as connection:
            self._require_registered_scan(connection, scan_id)
            by_message = connection.execute(
                'SELECT * FROM notus_runs WHERE start_message_id = ?',
                (message_id,),
            ).fetchone()
            if by_message is not None:
                run = self._notus_run_from_row(by_message)
                if (
                    run.scan_id == scan_id
                    and run.run_id == run_id
                    and by_message['start_digest'] == digest
                ):
                    return False
                failure = (
                    'A Notus start identity was reused with conflicting data.'
                )
                self._mark_scans_incomplete(
                    connection, failure, scan_id, run.scan_id
                )
            else:
                existing = connection.execute(
                    'SELECT * FROM notus_runs '
                    'WHERE scan_id = ? AND run_id = ?',
                    (scan_id, run_id),
                ).fetchone()
                if existing is None:
                    failure = self._notus_run_capacity_reason(
                        connection, scan_id
                    )
                    if failure is not None:
                        failure_type = ResultSpoolCapacityError
                        self._mark_scans_incomplete(
                            connection, failure, scan_id
                        )
                    else:
                        connection.execute(
                            'INSERT INTO notus_runs '
                            '(scan_id, run_id, host_ip, start_message_id, '
                            'start_digest, state, admitted_result_count) '
                            'VALUES (?, ?, ?, ?, ?, ?, 0)',
                            (
                                scan_id,
                                run_id,
                                host_ip,
                                message_id,
                                digest,
                                NotusRunState.STARTED.value,
                            ),
                        )
                        admitted = True
                elif existing['start_message_id'] is None:
                    if existing['host_ip'] not in ('', host_ip):
                        failure = (
                            'A Notus run reused one identity for different '
                            'hosts.'
                        )
                        self._mark_scans_incomplete(
                            connection, failure, scan_id
                        )
                    else:
                        connection.execute(
                            'UPDATE notus_runs SET host_ip = ?, '
                            'start_message_id = ?, start_digest = ?, '
                            "state = CASE WHEN state = 'PENDING_START' "
                            "THEN 'STARTED' ELSE state END "
                            'WHERE sequence = ?',
                            (
                                host_ip,
                                message_id,
                                digest,
                                existing['sequence'],
                            ),
                        )
                        admitted = True
                else:
                    failure = (
                        'A Notus run identity was reused for another start.'
                    )
                    self._mark_scans_incomplete(connection, failure, scan_id)
        if failure is not None:
            raise failure_type(failure)
        return admitted

    def admit_notus_status(
        self,
        scan_id: str,
        run_id: str,
        message_id: str,
        host_ip: str,
        status: str,
        result_count: Optional[int] = None,
    ) -> bool:
        """Durably record a Notus run state and its terminal count fence."""
        self._validate_scan_id(scan_id)
        self._validate_notus_run_id(run_id)
        self._validate_notus_message_id(message_id)
        self._validate_notus_host_ip(host_ip)
        if not host_ip:
            raise ResultSpoolValidationError(
                'Notus status host identity must not be empty'
            )
        try:
            state = NotusRunState(status.upper())
        except (AttributeError, ValueError) as exc:
            raise ResultSpoolValidationError(
                'unsupported Notus run status'
            ) from exc
        if state not in (
            NotusRunState.RUNNING,
            NotusRunState.FINISHED,
            NotusRunState.INTERRUPTED,
        ):
            raise ResultSpoolValidationError('unsupported Notus run status')
        if state == NotusRunState.FINISHED:
            if (
                not isinstance(result_count, int)
                or isinstance(result_count, bool)
                or result_count < 0
                or result_count > self.limits.max_notus_scan_pending_rows
            ):
                raise ResultSpoolValidationError(
                    'finished Notus status result count exceeds the '
                    'supported range'
                )
        elif result_count is not None:
            raise ResultSpoolValidationError(
                'only finished Notus status may carry a result count'
            )
        digest = self._notus_event_digest(
            {
                'kind': 'status',
                'scan_id': scan_id,
                'run_id': run_id,
                'message_id': message_id,
                'host_ip': host_ip,
                'status': state.value,
                'result_count': result_count,
            }
        )
        failure = None
        failure_type = ResultSpoolConflictError
        changed = False
        with self._transaction() as connection:
            self._require_registered_scan(connection, scan_id)
            by_terminal = connection.execute(
                'SELECT * FROM notus_runs WHERE terminal_message_id = ?',
                (message_id,),
            ).fetchone()
            if by_terminal is not None:
                run = self._notus_run_from_row(by_terminal)
                if (
                    run.scan_id == scan_id
                    and run.run_id == run_id
                    and by_terminal['terminal_digest'] == digest
                ):
                    return False
                failure = (
                    'A Notus terminal identity was reused with conflicting '
                    'data.'
                )
                self._mark_scans_incomplete(
                    connection, failure, scan_id, run.scan_id
                )
            else:
                row = connection.execute(
                    'SELECT * FROM notus_runs '
                    'WHERE scan_id = ? AND run_id = ?',
                    (scan_id, run_id),
                ).fetchone()
                if row is None:
                    failure = self._notus_run_capacity_reason(
                        connection, scan_id
                    )
                    if failure is not None:
                        failure_type = ResultSpoolCapacityError
                        self._mark_scans_incomplete(
                            connection, failure, scan_id
                        )
                    else:
                        connection.execute(
                            'INSERT INTO notus_runs '
                            '(scan_id, run_id, host_ip, state, '
                            'admitted_result_count) VALUES (?, ?, ?, ?, 0)',
                            (
                                scan_id,
                                run_id,
                                host_ip,
                                NotusRunState.PENDING_START.value,
                            ),
                        )
                        row = connection.execute(
                            'SELECT * FROM notus_runs '
                            'WHERE scan_id = ? AND run_id = ?',
                            (scan_id, run_id),
                        ).fetchone()
                if failure is not None:
                    pass
                elif row['host_ip'] not in ('', host_ip):
                    failure = (
                        'A Notus run reused one identity for different hosts.'
                    )
                    self._mark_scans_incomplete(connection, failure, scan_id)
                elif state == NotusRunState.RUNNING:
                    if row['state'] not in (
                        NotusRunState.FINISHED.value,
                        NotusRunState.INTERRUPTED.value,
                    ):
                        connection.execute(
                            'UPDATE notus_runs SET host_ip = ?, '
                            "state = CASE WHEN start_message_id IS NULL "
                            "THEN 'PENDING_START' ELSE 'RUNNING' END "
                            'WHERE sequence = ?',
                            (host_ip, row['sequence']),
                        )
                        changed = True
                elif row['terminal_message_id'] is not None:
                    failure = (
                        'A Notus run produced conflicting terminal states.'
                    )
                    self._mark_scans_incomplete(connection, failure, scan_id)
                else:
                    connection.execute(
                        'UPDATE notus_runs SET host_ip = ?, state = ?, '
                        'expected_result_count = ?, terminal_message_id = ?, '
                        'terminal_digest = ? WHERE sequence = ?',
                        (
                            host_ip,
                            state.value,
                            result_count,
                            message_id,
                            digest,
                            row['sequence'],
                        ),
                    )
                    changed = True
                    if state == NotusRunState.INTERRUPTED:
                        self._mark_scans_incomplete(
                            connection,
                            'Notus reported an interrupted package scan.',
                            scan_id,
                        )
                    elif row['admitted_result_count'] > result_count:
                        self._mark_scans_incomplete(
                            connection,
                            'Notus admitted more results than its terminal '
                            'completion count.',
                            scan_id,
                        )
        if failure is not None:
            raise failure_type(failure)
        return changed

    def admit_notus_result(
        self,
        scan_id: str,
        message_id: str,
        result: Mapping[str, Any],
    ) -> bool:
        """Durably admit one Notus message before the MQTT callback returns.

        Exact QoS redelivery is idempotent. Reuse of a message identity with a
        different scan or payload fails closed and marks the affected evidence
        incomplete without replacing the original durable row.
        """
        self._validate_scan_id(scan_id)
        self._validate_notus_message_id(message_id)
        payload_json, normalized = self._canonical_notus_result(result)
        if normalized.get('message_id') != message_id:
            raise ResultSpoolValidationError(
                'Notus result message_id does not match its source identity'
            )
        run_id = normalized.get('group_id')
        self._validate_notus_run_id(run_id)
        host_ip = normalized.get('host_ip')
        self._validate_notus_host_ip(host_ip)
        if not host_ip:
            raise ResultSpoolValidationError(
                'Notus result host identity must not be empty'
            )
        payload_bytes = len(payload_json.encode('utf-8'))
        digest = hashlib.sha256(payload_json.encode('utf-8')).hexdigest()
        if payload_bytes > self.limits.max_notus_result_bytes:
            reason = (
                'A Notus result exceeded the durable per-result byte limit.'
            )
            self.mark_scan_incomplete(scan_id, reason)
            raise ResultSpoolCapacityError(reason)

        failure = None
        admitted = False
        with self._transaction() as connection:
            self._require_registered_scan(connection, scan_id)
            existing = connection.execute(
                'SELECT * FROM notus_ingress WHERE message_id = ?',
                (message_id,),
            ).fetchone()
            if existing is not None:
                self._validate_notus_row(existing)
                if (
                    existing['scan_id'] == scan_id
                    and existing['digest'] == digest
                ):
                    return False
                failure = (
                    ResultSpoolConflictError,
                    'A Notus message identity was reused with conflicting '
                    'data.',
                )
                connection.execute(
                    'UPDATE scans SET incomplete_reason = '
                    'COALESCE(incomplete_reason, ?) '
                    'WHERE scan_id IN (?, ?)',
                    (failure[1], scan_id, existing['scan_id']),
                )
            else:
                capacity_reason = self._notus_capacity_reason(
                    connection, scan_id, payload_bytes
                )
                if capacity_reason is not None:
                    failure = (ResultSpoolCapacityError, capacity_reason)
                    connection.execute(
                        'UPDATE scans SET incomplete_reason = '
                        'COALESCE(incomplete_reason, ?) WHERE scan_id = ?',
                        (capacity_reason, scan_id),
                    )
                else:
                    run = connection.execute(
                        'SELECT * FROM notus_runs '
                        'WHERE scan_id = ? AND run_id = ?',
                        (scan_id, run_id),
                    ).fetchone()
                    if run is None:
                        run_capacity_reason = self._notus_run_capacity_reason(
                            connection, scan_id
                        )
                        if run_capacity_reason is not None:
                            failure = (
                                ResultSpoolCapacityError,
                                run_capacity_reason,
                            )
                            self._mark_scans_incomplete(
                                connection, run_capacity_reason, scan_id
                            )
                        else:
                            connection.execute(
                                'INSERT INTO notus_runs '
                                '(scan_id, run_id, host_ip, state, '
                                'admitted_result_count) '
                                'VALUES (?, ?, ?, ?, 0)',
                                (
                                    scan_id,
                                    run_id,
                                    host_ip,
                                    NotusRunState.PENDING_START.value,
                                ),
                            )
                            run = connection.execute(
                                'SELECT * FROM notus_runs '
                                'WHERE scan_id = ? AND run_id = ?',
                                (scan_id, run_id),
                            ).fetchone()
                    elif run['host_ip'] not in ('', host_ip):
                        failure = (
                            ResultSpoolConflictError,
                            'A Notus run reused one identity for different '
                            'hosts.',
                        )
                        self._mark_scans_incomplete(
                            connection, failure[1], scan_id
                        )
                    if failure is None:
                        connection.execute(
                            'INSERT INTO notus_ingress '
                            '(scan_id, message_id, run_id, batch_id, '
                            'payload_json, payload_bytes, digest, acked) '
                            'VALUES (?, ?, ?, NULL, ?, ?, ?, 0)',
                            (
                                scan_id,
                                message_id,
                                run_id,
                                payload_json,
                                payload_bytes,
                                digest,
                            ),
                        )
                        connection.execute(
                            'UPDATE notus_runs SET host_ip = CASE '
                            "WHEN host_ip = '' THEN ? ELSE host_ip END, "
                            'admitted_result_count = admitted_result_count + 1 '
                            'WHERE sequence = ?',
                            (host_ip, run['sequence']),
                        )
                        if (
                            run['expected_result_count'] is not None
                            and run['admitted_result_count'] + 1
                            > run['expected_result_count']
                        ):
                            self._mark_scans_incomplete(
                                connection,
                                'Notus admitted more results than its terminal '
                                'completion count.',
                                scan_id,
                            )
                        admitted = True
        if failure is not None:
            error_type, reason = failure
            raise error_type(reason)
        return admitted

    def prepare_next_notus_batch(self, scan_id: str) -> Optional[NotusBatch]:
        """Assign and return the oldest stable Notus source batch."""
        self._validate_scan_id(scan_id)
        with self._transaction() as connection:
            acknowledged_batches = connection.execute(
                'SELECT DISTINCT ingress.batch_id FROM notus_ingress ingress '
                'JOIN claims ON claims.scan_id = ingress.scan_id '
                'AND claims.source_kind = ? '
                'AND claims.source_claim_id = ingress.batch_id '
                "AND claims.state = 'ACKED' "
                'WHERE ingress.scan_id = ? AND ingress.acked = 0',
                (SourceKind.NOTUS.value, scan_id),
            ).fetchall()
            for batch in acknowledged_batches:
                self._retire_notus_ingress(
                    connection, scan_id, batch['batch_id']
                )
            pending = connection.execute(
                "SELECT * FROM claims WHERE scan_id = ? AND state != 'ACKED'",
                (scan_id,),
            ).fetchone()
            if pending is not None:
                self._claim_from_row(pending)
                return None

            batch_rows = connection.execute(
                'SELECT DISTINCT batch_id FROM notus_ingress '
                'WHERE scan_id = ? AND acked = 0 AND batch_id IS NOT NULL',
                (scan_id,),
            ).fetchall()
            if len(batch_rows) > 1:
                raise ResultSpoolCorruptionError(
                    'scan has multiple unacknowledged Notus batches'
                )
            if batch_rows:
                source_claim_id = batch_rows[0]['batch_id']
                ingress = connection.execute(
                    'SELECT * FROM notus_ingress WHERE scan_id = ? '
                    'AND batch_id = ? AND acked = 0 ORDER BY sequence',
                    (scan_id, source_claim_id),
                ).fetchall()
            else:
                candidates = connection.execute(
                    'SELECT * FROM notus_ingress WHERE scan_id = ? '
                    'AND acked = 0 AND batch_id IS NULL ORDER BY sequence '
                    'LIMIT ?',
                    (scan_id, self.limits.max_claim_rows),
                ).fetchall()
                ingress = []
                payload_bytes = 0
                for row in candidates:
                    self._validate_notus_row(row)
                    if (
                        payload_bytes + row['payload_bytes']
                        > self.limits.max_claim_bytes
                    ):
                        break
                    ingress.append(row)
                    payload_bytes += row['payload_bytes']
                if not ingress:
                    return None
                source_claim_id = str(uuid.uuid4())
                placeholders = ','.join('?' for _ in ingress)
                connection.execute(
                    'UPDATE notus_ingress SET batch_id = ? '
                    f'WHERE sequence IN ({placeholders}) AND batch_id IS NULL',
                    (source_claim_id, *(row['sequence'] for row in ingress)),
                )
                ingress = connection.execute(
                    'SELECT * FROM notus_ingress WHERE scan_id = ? '
                    'AND batch_id = ? AND acked = 0 ORDER BY sequence',
                    (scan_id, source_claim_id),
                ).fetchall()

            return NotusBatch(
                scan_id=scan_id,
                batch_id=source_claim_id,
                results=[self._notus_result_from_row(row) for row in ingress],
            )

    def stage_notus_claim(
        self,
        scan_id: str,
        source_batch_id: str,
        results: Iterable[Mapping[str, Any]],
        *,
        incomplete_reason: Optional[str] = None,
    ) -> SpoolClaim:
        """Stage normalized OSP results for one exact admitted Notus batch."""
        self._validate_scan_id(scan_id)
        self._validate_notus_batch_id(source_batch_id)
        metadata = self._validate_metadata(0, None, None, incomplete_reason)
        payload_json, normalized_rows = self._canonical_rows(results)
        payload_bytes = len(payload_json.encode('utf-8'))
        digest = self._digest(payload_json, metadata)
        with self._transaction() as connection:
            existing = connection.execute(
                'SELECT * FROM claims WHERE redis_db = ? '
                'AND source_claim_id = ?',
                (NOTUS_REDIS_DB, source_batch_id),
            ).fetchone()
            if existing is not None:
                claim = self._claim_from_row(existing)
                if (
                    claim.source_kind != SourceKind.NOTUS
                    or claim.scan_id != scan_id
                    or claim.digest != digest
                ):
                    raise ResultSpoolConflictError(
                        'Notus source batch conflicts with its durable payload'
                    )
                return claim
            ingress = connection.execute(
                'SELECT * FROM notus_ingress WHERE scan_id = ? '
                'AND batch_id = ? AND acked = 0 ORDER BY sequence',
                (scan_id, source_batch_id),
            ).fetchall()
            if not ingress:
                raise ResultSpoolStateError(
                    'Notus source batch is not durably admitted'
                )
            for row in ingress:
                self._validate_notus_row(row)
            self._check_capacity(
                connection, scan_id, len(normalized_rows), payload_bytes
            )
            connection.execute(
                'UPDATE scans SET incomplete_reason = '
                'COALESCE(incomplete_reason, ?) WHERE scan_id = ?',
                (incomplete_reason, scan_id),
            )
            osp_batch_id = str(uuid.uuid4())
            connection.execute(
                'INSERT INTO claims '
                '(scan_id, source_kind, redis_db, owner_token, '
                'source_claim_id, osp_batch_id, state, payload_json, '
                'row_count, payload_bytes, '
                'count_dead, count_total, count_excluded, '
                'incomplete_reason, digest) '
                'VALUES (?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, 0, NULL, NULL, ?, ?)',
                (
                    scan_id,
                    SourceKind.NOTUS.value,
                    NOTUS_REDIS_DB,
                    source_batch_id,
                    osp_batch_id,
                    ClaimState.STAGED.value,
                    payload_json,
                    len(normalized_rows),
                    payload_bytes,
                    incomplete_reason,
                    digest,
                ),
            )
            row = connection.execute(
                'SELECT * FROM claims WHERE redis_db = ? '
                'AND source_claim_id = ?',
                (NOTUS_REDIS_DB, source_batch_id),
            ).fetchone()
            return self._claim_from_row(row)

    def complete_notus_batch(self, scan_id: str, batch_id: str) -> int:
        """Retire ingress for one locally acknowledged Notus claim."""
        self._validate_scan_id(scan_id)
        self._validate_notus_batch_id(batch_id)
        with self._transaction() as connection:
            claim_row = connection.execute(
                'SELECT * FROM claims WHERE scan_id = ? AND source_kind = ? '
                'AND source_claim_id = ?',
                (scan_id, SourceKind.NOTUS.value, batch_id),
            ).fetchone()
            if claim_row is None:
                raise ResultSpoolStateError(
                    'Notus batch does not match a durable claim'
                )
            claim = self._claim_from_row(claim_row)
            if claim.state != ClaimState.ACKED:
                raise ResultSpoolStateError(
                    'Notus ingress cannot retire before claim acknowledgement'
                )
            return self._retire_notus_ingress(connection, scan_id, batch_id)

    def mark_scan_incomplete(self, scan_id: str, reason: str) -> bool:
        """Durably retain the first reason evidence became incomplete."""
        self._validate_scan_id(scan_id)
        self._validate_metadata(0, None, None, reason)
        with self._transaction() as connection:
            if (
                connection.execute(
                    'SELECT 1 FROM scans WHERE scan_id = ?', (scan_id,)
                ).fetchone()
                is None
            ):
                raise ResultSpoolStateError(
                    'incomplete scan is not durably registered'
                )
            changed = connection.execute(
                'UPDATE scans SET incomplete_reason = ? '
                'WHERE scan_id = ? AND incomplete_reason IS NULL',
                (reason, scan_id),
            ).rowcount
            return bool(changed)

    def scan_incomplete_reason(self, scan_id: str) -> Optional[str]:
        """Return the durable first incomplete-evidence reason for a scan."""
        self._validate_scan_id(scan_id)
        connection = None
        try:
            connection = self._open_connection()
            row = connection.execute(
                'SELECT incomplete_reason FROM scans WHERE scan_id = ?',
                (scan_id,),
            ).fetchone()
            return row['incomplete_reason'] if row is not None else None
        except sqlite3.Error as exc:
            raise self._database_error(exc) from exc
        finally:
            if connection is not None:
                connection.close()

    def bind_owner_token(
        self, redis_db: int, source_claim_id: str, owner_token: str
    ) -> SpoolClaim:
        """Bind a migrated claim to its verified unique Redis owner."""
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
        self._validate_owner_token(owner_token)
        if owner_token == '1':
            raise ResultSpoolValidationError(
                'owner_token must not be the reusable legacy marker'
            )
        with self._transaction() as connection:
            row = connection.execute(
                'SELECT * FROM claims WHERE redis_db = ? '
                'AND source_claim_id = ?',
                (redis_db, source_claim_id),
            ).fetchone()
            if row is None:
                raise ResultSpoolStateError('claim identity is not durable')
            claim = self._claim_from_row(row)
            if claim.owner_token not in (None, '1', owner_token):
                raise ResultSpoolConflictError(
                    'source claim conflicts with its durable owner'
                )
            if claim.owner_token != owner_token:
                connection.execute(
                    'UPDATE claims SET owner_token = ? WHERE sequence = ?',
                    (owner_token, row['sequence']),
                )
                row = connection.execute(
                    'SELECT * FROM claims WHERE sequence = ?',
                    (row['sequence'],),
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
        """Record gvmd acknowledgement before Redis acknowledgement."""
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
        """Record Redis acknowledgement and retain a small tombstone."""
        with self._transaction() as connection:
            row = self._exact_claim(
                connection, scan_id, osp_batch_id, redis_db, source_claim_id
            )
            state = ClaimState(row['state'])
            if state == ClaimState.ACKING:
                acked_sequence = connection.execute(
                    'SELECT COALESCE(MAX(acked_sequence), 0) + 1 '
                    "FROM claims WHERE state = 'ACKED'"
                ).fetchone()[0]
                connection.execute(
                    "UPDATE claims SET state = 'ACKED', payload_json = NULL, "
                    "payload_bytes = 0, incomplete_reason = NULL, "
                    'acked_sequence = ? '
                    'WHERE sequence = ?',
                    (acked_sequence, row['sequence']),
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
        """List scans with unsealed completion or retained evidence."""
        connection = None
        try:
            connection = self._open_connection()
            rows = connection.execute(
                'SELECT scans.scan_id, scans.count_dead, scans.count_total, '
                'scans.count_excluded, scans.incomplete_reason, '
                '(SELECT COUNT(*) FROM claims c '
                'WHERE c.scan_id = scans.scan_id '
                "AND c.state != 'ACKED') AS pending_claims, "
                '(SELECT COALESCE(SUM(c.row_count), 0) FROM claims c '
                "WHERE c.scan_id = scans.scan_id AND c.state != 'ACKED') + "
                '(SELECT COUNT(*) FROM notus_ingress n '
                'WHERE n.scan_id = scans.scan_id AND n.acked = 0 '
                'AND (n.batch_id IS NULL OR NOT EXISTS ('
                'SELECT 1 FROM claims nc WHERE nc.scan_id = n.scan_id '
                "AND nc.source_kind = 'notus' "
                'AND nc.source_claim_id = n.batch_id '
                "AND nc.state != 'ACKED'))) AS pending_rows, "
                '(SELECT COALESCE(SUM(c.payload_bytes), 0) FROM claims c '
                "WHERE c.scan_id = scans.scan_id AND c.state != 'ACKED') + "
                '(SELECT COALESCE(SUM(n.payload_bytes), 0) '
                'FROM notus_ingress n '
                'WHERE n.scan_id = scans.scan_id AND n.acked = 0 '
                'AND (n.batch_id IS NULL OR NOT EXISTS ('
                'SELECT 1 FROM claims nc WHERE nc.scan_id = n.scan_id '
                "AND nc.source_kind = 'notus' "
                'AND nc.source_claim_id = n.batch_id '
                "AND nc.state != 'ACKED'))) AS pending_bytes "
                'FROM scans WHERE scans.notus_manifest_mode IS NULL '
                'OR scans.incomplete_reason IS NOT NULL '
                'OR EXISTS (SELECT 1 FROM claims c '
                'WHERE c.scan_id = scans.scan_id '
                "AND c.state != 'ACKED') "
                'OR EXISTS (SELECT 1 FROM notus_ingress n '
                'WHERE n.scan_id = scans.scan_id AND n.acked = 0) '
                'OR EXISTS (SELECT 1 FROM notus_runs r '
                'WHERE r.scan_id = scans.scan_id '
                "AND (r.state != 'FINISHED' OR r.start_message_id IS NULL "
                'OR r.expected_result_count IS NULL '
                'OR r.admitted_result_count != r.expected_result_count)) '
                'ORDER BY scans.scan_id',
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
                    incomplete_reason=row['incomplete_reason'],
                )
                for row in rows
            ]
        except sqlite3.Error as exc:
            raise self._database_error(exc) from exc
        finally:
            if connection is not None:
                connection.close()

    def prune_clean_scan_rows(self) -> int:
        """Remove manifest-sealed registry rows with no retained evidence."""
        with self._transaction() as connection:
            return connection.execute(
                'DELETE FROM scans WHERE incomplete_reason IS NULL '
                'AND notus_manifest_mode IS NOT NULL '
                'AND NOT EXISTS (SELECT 1 FROM claims '
                'WHERE claims.scan_id = scans.scan_id '
                "AND claims.state != 'ACKED') "
                'AND NOT EXISTS (SELECT 1 FROM notus_ingress '
                'WHERE notus_ingress.scan_id = scans.scan_id '
                'AND notus_ingress.acked = 0) '
                'AND NOT EXISTS (SELECT 1 FROM notus_runs '
                'WHERE notus_runs.scan_id = scans.scan_id '
                "AND (notus_runs.state != 'FINISHED' "
                'OR notus_runs.start_message_id IS NULL '
                'OR notus_runs.expected_result_count IS NULL '
                'OR notus_runs.admitted_result_count '
                '!= notus_runs.expected_result_count))'
            ).rowcount

    def has_pending(self, scan_id: Optional[str] = None) -> bool:
        """Return whether one or any scan has pending durable evidence."""
        if scan_id is not None:
            self._validate_scan_id(scan_id)
            query = (
                'SELECT 1 WHERE EXISTS (SELECT 1 FROM claims '
                "WHERE scan_id = ? AND state != 'ACKED') "
                'OR EXISTS (SELECT 1 FROM notus_ingress '
                'WHERE scan_id = ? AND acked = 0) '
                'OR EXISTS (SELECT 1 FROM notus_runs WHERE scan_id = ? '
                "AND (state != 'FINISHED' OR start_message_id IS NULL "
                'OR expected_result_count IS NULL '
                'OR admitted_result_count != expected_result_count))'
            )
            parameters = (scan_id, scan_id, scan_id)
        else:
            query = (
                'SELECT 1 WHERE EXISTS (SELECT 1 FROM claims '
                "WHERE state != 'ACKED') OR EXISTS "
                '(SELECT 1 FROM notus_ingress WHERE acked = 0) OR EXISTS '
                '(SELECT 1 FROM notus_runs '
                "WHERE state != 'FINISHED' OR start_message_id IS NULL "
                'OR expected_result_count IS NULL '
                'OR admitted_result_count != expected_result_count)'
            )
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
        """Delete a scan only after all durable evidence reached ACKED."""
        self._validate_scan_id(scan_id)
        with self._transaction() as connection:
            if connection.execute(
                'SELECT 1 WHERE EXISTS (SELECT 1 FROM claims '
                "WHERE scan_id = ? AND state != 'ACKED') "
                'OR EXISTS (SELECT 1 FROM notus_ingress '
                'WHERE scan_id = ? AND acked = 0) '
                'OR EXISTS (SELECT 1 FROM notus_runs WHERE scan_id = ? '
                "AND (state != 'FINISHED' OR start_message_id IS NULL "
                'OR expected_result_count IS NULL '
                'OR admitted_result_count != expected_result_count))',
                (scan_id, scan_id, scan_id),
            ).fetchone():
                raise ResultSpoolStateError(
                    'cannot delete a scan with pending durable evidence'
                )
            deleted = connection.execute(
                'DELETE FROM scans WHERE scan_id = ?', (scan_id,)
            ).rowcount
            return bool(deleted)

    def prune_acked(self) -> int:
        """Prune oldest ACKED tombstones to their configured bound."""
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
        self._validate_claim_identity(scan_id, redis_db, source_claim_id)
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

    def _notus_capacity_reason(
        self,
        connection: sqlite3.Connection,
        scan_id: str,
        payload_bytes: int,
    ) -> Optional[str]:
        scan = connection.execute(
            'SELECT COUNT(*), COALESCE(SUM(payload_bytes), 0) '
            'FROM notus_ingress WHERE scan_id = ? AND acked = 0',
            (scan_id,),
        ).fetchone()
        global_state = connection.execute(
            'SELECT COUNT(*), COALESCE(SUM(payload_bytes), 0) '
            'FROM notus_ingress WHERE acked = 0'
        ).fetchone()
        pending_scans = connection.execute(
            'SELECT COUNT(*) FROM (SELECT scan_id FROM notus_ingress '
            'WHERE acked = 0 GROUP BY scan_id)'
        ).fetchone()[0]
        if scan[0] + 1 > self.limits.max_notus_scan_pending_rows:
            return 'Notus per-scan result-count capacity was exhausted.'
        if scan[1] + payload_bytes > self.limits.max_notus_scan_pending_bytes:
            return 'Notus per-scan byte capacity was exhausted.'
        if global_state[0] + 1 > self.limits.max_notus_global_pending_rows:
            return 'Notus global result-count capacity was exhausted.'
        if (
            global_state[1] + payload_bytes
            > self.limits.max_notus_global_pending_bytes
        ):
            return 'Notus global byte capacity was exhausted.'
        if (
            scan[0] == 0
            and pending_scans >= self.limits.max_notus_pending_scans
        ):
            return 'Notus pending-scan capacity was exhausted.'
        return None

    def _notus_run_capacity_reason(
        self, connection: sqlite3.Connection, scan_id: str
    ) -> Optional[str]:
        scan_runs = connection.execute(
            'SELECT COUNT(*) FROM notus_runs WHERE scan_id = ?',
            (scan_id,),
        ).fetchone()[0]
        if scan_runs >= self.limits.max_notus_scan_pending_rows:
            return 'Notus per-scan run capacity was exhausted.'
        global_runs = connection.execute(
            'SELECT COUNT(*) FROM notus_runs'
        ).fetchone()[0]
        if global_runs >= self.limits.max_notus_global_pending_rows:
            return 'Notus global run capacity was exhausted.'
        return None

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

    def _prune_notus_acked(self, connection: sqlite3.Connection) -> int:
        excess = (
            connection.execute(
                'SELECT COUNT(*) FROM notus_ingress WHERE acked = 1'
            ).fetchone()[0]
            - self.limits.max_notus_acked_tombstones
        )
        if excess <= 0:
            return 0
        return connection.execute(
            'DELETE FROM notus_ingress WHERE sequence IN ('
            'SELECT sequence FROM notus_ingress WHERE acked = 1 '
            'ORDER BY acked_sequence, sequence LIMIT ?)',
            (excess,),
        ).rowcount

    def _retire_notus_ingress(
        self,
        connection: sqlite3.Connection,
        scan_id: str,
        batch_id: str,
    ) -> int:
        rows = connection.execute(
            'SELECT sequence FROM notus_ingress WHERE scan_id = ? '
            'AND batch_id = ? AND acked = 0 ORDER BY sequence',
            (scan_id, batch_id),
        ).fetchall()
        if not rows:
            return 0
        acked_sequence = connection.execute(
            'SELECT COALESCE(MAX(acked_sequence), 0) + 1 '
            'FROM notus_ingress WHERE acked = 1'
        ).fetchone()[0]
        connection.execute(
            'UPDATE notus_ingress SET acked = 1, payload_json = NULL, '
            'payload_bytes = 0, acked_sequence = ? '
            'WHERE scan_id = ? AND batch_id = ? AND acked = 0',
            (acked_sequence, scan_id, batch_id),
        )
        self._prune_notus_acked(connection)
        return len(rows)

    def _claim_from_row(self, row: sqlite3.Row) -> SpoolClaim:
        digest = row['digest']
        if not self._is_digest(digest):
            raise ResultSpoolCorruptionError('claim has a malformed digest')
        state = ClaimState(row['state'])
        source_kind = SourceKind(row['source_kind'])
        if source_kind == SourceKind.REDIS:
            if row['redis_db'] < 0:
                raise ResultSpoolCorruptionError(
                    'Redis claim has an invalid logical database'
                )
            if row['owner_token'] is not None:
                self._validate_owner_token(row['owner_token'])
        elif (
            row['redis_db'] != NOTUS_REDIS_DB or row['owner_token'] is not None
        ):
            raise ResultSpoolCorruptionError(
                'Notus claim has Redis ownership metadata'
            )
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
            source_kind=source_kind,
            redis_db=row['redis_db'],
            owner_token=row['owner_token'],
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

    def _notus_run_from_row(self, row: sqlite3.Row) -> NotusRun:
        self._validate_scan_id(row['scan_id'])
        self._validate_notus_run_id(row['run_id'])
        self._validate_notus_host_ip(row['host_ip'])
        try:
            state = NotusRunState(row['state'])
        except ValueError as exc:
            raise ResultSpoolCorruptionError(
                'Notus run has an invalid state'
            ) from exc
        start_message_id = row['start_message_id']
        start_digest = row['start_digest']
        if (start_message_id is None) != (start_digest is None):
            raise ResultSpoolCorruptionError(
                'Notus run has incomplete start identity'
            )
        if start_message_id is not None:
            self._validate_notus_message_id(start_message_id)
            if not self._is_digest(start_digest):
                raise ResultSpoolCorruptionError(
                    'Notus run has a malformed start digest'
                )
        terminal_message_id = row['terminal_message_id']
        terminal_digest = row['terminal_digest']
        if (terminal_message_id is None) != (terminal_digest is None):
            raise ResultSpoolCorruptionError(
                'Notus run has incomplete terminal identity'
            )
        if terminal_message_id is not None:
            self._validate_notus_message_id(terminal_message_id)
            if not self._is_digest(terminal_digest):
                raise ResultSpoolCorruptionError(
                    'Notus run has a malformed terminal digest'
                )
        expected = row['expected_result_count']
        admitted = row['admitted_result_count']
        if (
            not isinstance(admitted, int)
            or isinstance(admitted, bool)
            or admitted < 0
            or (
                expected is not None
                and (
                    not isinstance(expected, int)
                    or isinstance(expected, bool)
                    or expected < 0
                )
            )
        ):
            raise ResultSpoolCorruptionError(
                'Notus run has an invalid result count'
            )
        if (
            state == NotusRunState.PENDING_START
            and start_message_id is not None
        ):
            raise ResultSpoolCorruptionError(
                'pending Notus run already has a start identity'
            )
        if state in (NotusRunState.STARTED, NotusRunState.RUNNING) and (
            start_message_id is None or terminal_message_id is not None
        ):
            raise ResultSpoolCorruptionError(
                'active Notus run has inconsistent identities'
            )
        if state == NotusRunState.FINISHED and (
            terminal_message_id is None or expected is None
        ):
            raise ResultSpoolCorruptionError(
                'finished Notus run has no exact completion fence'
            )
        if state == NotusRunState.INTERRUPTED and terminal_message_id is None:
            raise ResultSpoolCorruptionError(
                'interrupted Notus run has no terminal identity'
            )
        return NotusRun(
            scan_id=row['scan_id'],
            run_id=row['run_id'],
            host_ip=row['host_ip'],
            state=state,
            expected_result_count=expected,
            admitted_result_count=admitted,
            start_message_id=start_message_id,
            terminal_message_id=terminal_message_id,
        )

    def _validate_notus_row(self, row: sqlite3.Row) -> None:
        self._validate_scan_id(row['scan_id'])
        self._validate_notus_message_id(row['message_id'])
        self._validate_notus_run_id(row['run_id'])
        if not self._is_digest(row['digest']):
            raise ResultSpoolCorruptionError(
                'Notus ingress has a malformed digest'
            )
        acked = row['acked']
        if acked not in (0, 1):
            raise ResultSpoolCorruptionError(
                'Notus ingress has an invalid acknowledgement state'
            )
        batch_id = row['batch_id']
        if batch_id is not None:
            self._validate_notus_batch_id(batch_id)
        payload_json = row['payload_json']
        if acked:
            if (
                payload_json is not None
                or row['payload_bytes'] != 0
                or batch_id is None
                or not isinstance(row['acked_sequence'], int)
                or row['acked_sequence'] < 1
            ):
                raise ResultSpoolCorruptionError(
                    'ACKED Notus tombstone retains invalid state'
                )
            return
        if row['acked_sequence'] is not None:
            raise ResultSpoolCorruptionError(
                'pending Notus ingress has an ACK sequence'
            )
        if not isinstance(payload_json, str):
            raise ResultSpoolCorruptionError(
                'pending Notus ingress has no result payload'
            )
        try:
            result = json.loads(payload_json)
        except (TypeError, ValueError) as exc:
            raise ResultSpoolCorruptionError(
                'Notus ingress payload is not valid JSON'
            ) from exc
        if (
            not isinstance(result, dict)
            or self._canonical_json(result) != payload_json
            or result.get('message_id') != row['message_id']
            or result.get('group_id') != row['run_id']
        ):
            raise ResultSpoolCorruptionError(
                'Notus ingress payload is not a canonical matching result'
            )
        if len(payload_json.encode('utf-8')) != row['payload_bytes']:
            raise ResultSpoolCorruptionError(
                'Notus ingress byte count does not match payload'
            )
        if (
            hashlib.sha256(payload_json.encode('utf-8')).hexdigest()
            != row['digest']
        ):
            raise ResultSpoolCorruptionError(
                'Notus ingress digest does not match payload'
            )

    def _notus_result_from_row(self, row: sqlite3.Row) -> Dict[str, Any]:
        self._validate_notus_row(row)
        payload_json = row['payload_json']
        if not isinstance(payload_json, str):
            raise ResultSpoolCorruptionError(
                'pending Notus ingress has no result payload'
            )
        return json.loads(payload_json)

    def _validate_stored_state(self, connection: sqlite3.Connection) -> None:
        try:
            for row in connection.execute('SELECT * FROM scans'):
                self._notus_manifest_from_row(row)
            for row in connection.execute('SELECT * FROM claims'):
                self._claim_from_row(row)
            for row in connection.execute('SELECT * FROM notus_ingress'):
                self._validate_notus_row(row)
            for row in connection.execute('SELECT * FROM notus_runs'):
                self._notus_run_from_row(row)
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
            limits.max_notus_result_bytes,
            limits.max_notus_scan_pending_rows,
            limits.max_notus_scan_pending_bytes,
            limits.max_notus_global_pending_rows,
            limits.max_notus_global_pending_bytes,
            limits.max_notus_pending_scans,
            limits.max_notus_acked_tombstones,
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
    def _validate_notus_message_id(message_id: str) -> None:
        if (
            not isinstance(message_id, str)
            or not message_id
            or len(message_id) > 128
            or not message_id.isprintable()
            or '\x00' in message_id
        ):
            raise ResultSpoolValidationError(
                'Notus message_id must be a printable non-empty string'
            )

    @staticmethod
    def _validate_notus_run_id(run_id: str) -> None:
        if (
            not isinstance(run_id, str)
            or not run_id
            or len(run_id) > 128
            or not run_id.isprintable()
            or '\x00' in run_id
        ):
            raise ResultSpoolValidationError(
                'Notus run identity must be a printable non-empty string'
            )

    @staticmethod
    def _validate_notus_host_ip(host_ip: str) -> None:
        if (
            not isinstance(host_ip, str)
            or len(host_ip) > 255
            or not host_ip.isprintable()
            or '\x00' in host_ip
        ):
            raise ResultSpoolValidationError(
                'Notus host identity must be a bounded printable string'
            )

    @staticmethod
    def _validate_notus_batch_id(batch_id: str) -> None:
        if (
            not isinstance(batch_id, str)
            or not batch_id
            or len(batch_id) > 128
            or not batch_id.isprintable()
            or '\x00' in batch_id
        ):
            raise ResultSpoolValidationError('Notus batch identity is invalid')

    def _normalize_notus_manifest(
        self, entries: Iterable[Mapping[str, Any]]
    ) -> List[Dict[str, str]]:
        if isinstance(entries, (str, bytes, Mapping)):
            raise ResultSpoolValidationError(
                'Notus manifest must be a list of entries'
            )
        try:
            values = list(entries)
        except TypeError as exc:
            raise ResultSpoolValidationError(
                'Notus manifest must be iterable'
            ) from exc
        if len(values) > self.limits.max_notus_scan_pending_rows:
            raise ResultSpoolCapacityError(
                'Notus manifest exceeds the run limit'
            )
        normalized = []
        run_ids = set()
        message_ids = set()
        for value in values:
            if not isinstance(value, Mapping) or set(value) != {
                'run_id',
                'start_message_id',
                'host_ip',
            }:
                raise ResultSpoolValidationError(
                    'Notus manifest entry has an invalid shape'
                )
            run_id = value['run_id']
            message_id = value['start_message_id']
            host_ip = value['host_ip']
            self._validate_notus_run_id(run_id)
            self._validate_notus_message_id(message_id)
            self._validate_notus_host_ip(host_ip)
            if not host_ip:
                raise ResultSpoolValidationError(
                    'Notus manifest host identity must not be empty'
                )
            if run_id in run_ids or message_id in message_ids:
                raise ResultSpoolValidationError(
                    'Notus manifest identities must be unique'
                )
            run_ids.add(run_id)
            message_ids.add(message_id)
            normalized.append(
                {
                    'run_id': run_id,
                    'start_message_id': message_id,
                    'host_ip': host_ip,
                }
            )
        return sorted(normalized, key=lambda entry: entry['run_id'])

    def _notus_manifest_from_row(
        self, row: sqlite3.Row
    ) -> Optional[tuple[NotusManifestMode, List[Dict[str, str]]]]:
        mode_value = row['notus_manifest_mode']
        manifest_json = row['notus_manifest_json']
        digest = row['notus_manifest_digest']
        if mode_value is None and manifest_json is None and digest is None:
            return None
        if mode_value is None or manifest_json is None or digest is None:
            raise ResultSpoolCorruptionError(
                'Notus expectation manifest is only partially sealed'
            )
        try:
            mode = NotusManifestMode(mode_value)
            decoded = json.loads(manifest_json)
        except (TypeError, ValueError) as exc:
            raise ResultSpoolCorruptionError(
                'Notus expectation manifest is malformed'
            ) from exc
        try:
            normalized = self._normalize_notus_manifest(decoded)
        except ResultSpoolError as exc:
            raise ResultSpoolCorruptionError(str(exc)) from exc
        if mode != NotusManifestMode.MQTT and normalized:
            raise ResultSpoolCorruptionError(
                'Non-MQTT Notus manifest contains runs'
            )
        if (
            self._canonical_json(normalized) != manifest_json
            or len(manifest_json.encode('utf-8')) > MAX_NOTUS_MANIFEST_BYTES
            or not self._is_digest(digest)
            or self._notus_event_digest(
                {'mode': mode.value, 'runs': normalized}
            )
            != digest
        ):
            raise ResultSpoolCorruptionError(
                'Notus expectation manifest failed integrity validation'
            )
        return mode, normalized

    @staticmethod
    def _has_notus_ingress(
        connection: sqlite3.Connection, scan_id: str
    ) -> bool:
        return (
            connection.execute(
                'SELECT 1 FROM notus_ingress WHERE scan_id = ?', (scan_id,)
            ).fetchone()
            is not None
        )

    def _validate_claim_identity(
        self, scan_id: str, redis_db: int, source_claim_id: str
    ) -> None:
        self._validate_scan_id(scan_id)
        if (
            not isinstance(redis_db, int)
            or isinstance(redis_db, bool)
            or redis_db < NOTUS_REDIS_DB
        ):
            raise ResultSpoolValidationError(
                'claim source database identity is invalid'
            )
        if not isinstance(source_claim_id, str) or not source_claim_id:
            raise ResultSpoolValidationError(
                'source_claim_id must be a non-empty string'
            )

    @staticmethod
    def _validate_owner_token(owner_token: str) -> None:
        if (
            not isinstance(owner_token, str)
            or not owner_token
            or len(owner_token) > 128
            or ':' in owner_token
            or '\x00' in owner_token
        ):
            raise ResultSpoolValidationError('owner_token is invalid')

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

    def _canonical_notus_result(self, result: Mapping[str, Any]) -> tuple:
        if not isinstance(result, Mapping):
            raise ResultSpoolSerializationError(
                'Notus result must be a mapping'
            )
        normalized = self._normalize_json(dict(result))
        if not isinstance(normalized, dict):
            raise ResultSpoolSerializationError(
                'Notus result must normalize to a map'
            )
        return self._canonical_json(normalized), normalized

    def _notus_event_digest(self, value: Mapping[str, Any]) -> str:
        encoded = self._canonical_json(self._normalize_json(dict(value)))
        return hashlib.sha256(encoded.encode('utf-8')).hexdigest()

    @staticmethod
    def _require_registered_scan(
        connection: sqlite3.Connection, scan_id: str
    ) -> None:
        if (
            connection.execute(
                'SELECT 1 FROM scans WHERE scan_id = ?', (scan_id,)
            ).fetchone()
            is None
        ):
            raise ResultSpoolStateError(
                'Notus evidence scan is not durably registered'
            )

    @staticmethod
    def _mark_scans_incomplete(
        connection: sqlite3.Connection,
        reason: str,
        *scan_ids: str,
    ) -> None:
        unique_scan_ids = tuple(dict.fromkeys(scan_ids))
        placeholders = ','.join('?' for _ in unique_scan_ids)
        connection.execute(
            'UPDATE scans SET incomplete_reason = '
            'COALESCE(incomplete_reason, ?) '
            f'WHERE scan_id IN ({placeholders})',
            (reason, *unique_scan_ids),
        )

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
