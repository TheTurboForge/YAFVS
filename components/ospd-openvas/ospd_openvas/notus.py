# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2021-2023 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: AGPL-3.0-or-later

from pathlib import Path
from typing import Any, Dict, Iterator, Optional, Callable, Tuple
from threading import Condition, Lock, Timer
import json
import logging

from ospd.config import strtoboolean
from ospd.parser import CliParser
from ospd_openvas.messages.result import ResultMessage
from ospd_openvas.db import OpenvasDB, MainDB
from ospd_openvas.gpg_sha_verifier import (
    ReloadConfiguration,
    create_verify,
    reload_sha256sums,
)

logger = logging.getLogger(__name__)

NOTUS_CACHE_NAME = "notuscache"
NOTUS_RESULT_DELAY_SECONDS = 0.25
NOTUS_RESULT_RETRY_SECONDS = 1.0
MAX_NOTUS_RESULT_RETRIES = 10
MAX_RESULTS_PER_SCAN = 10000
MAX_BUFFERED_NOTUS_RESULTS = 100000
MAX_PENDING_NOTUS_SCANS = 128
MAX_NOTUS_SCAN_ID_LENGTH = 128
MAX_NOTUS_RESULT_BYTES = 64 * 1024
MAX_NOTUS_RESULT_BYTES_PER_SCAN = 4 * 1024 * 1024
MAX_BUFFERED_NOTUS_RESULT_BYTES = 32 * 1024 * 1024


def hashsum_verificator(
    advisories_directory_path: Path, disable: bool
) -> Callable[[Path], bool]:
    if disable:
        logger.info("hashsum verification is disabled")
        return lambda _: True

    def on_hash_sum_verification_failure(
        _: Optional[Dict[str, str]],
    ) -> Dict[str, str]:
        logger.warning(
            "GPG verification of notus sha256sums failed."
            " Notus advisories are not loaded."
        )
        return {}

    sha_sum_file_path = advisories_directory_path / "sha256sums"
    sha_sum_reload_config = ReloadConfiguration(
        hash_file=sha_sum_file_path,
        on_verification_failure=on_hash_sum_verification_failure,
    )

    sums = reload_sha256sums(sha_sum_reload_config)
    return create_verify(sums)


class Cache:
    def __init__(
        self, main_db: MainDB, prefix: str = "internal/notus/advisories"
    ):
        self._main_db = main_db
        # Check if it was previously uploaded
        self.ctx, _ = OpenvasDB.find_database_by_pattern(
            NOTUS_CACHE_NAME, self._main_db.max_database_index
        )
        # Get a new namespace for the Notus Cache
        if not self.ctx:
            new_db = self._main_db.get_new_kb_database()
            self.ctx = new_db.ctx
            OpenvasDB.add_single_item(
                self.ctx, NOTUS_CACHE_NAME, set([1]), lpush=True
            )
        self.__prefix = prefix

    def store_advisory(self, oid: str, value: Dict[str, str]):
        return OpenvasDB.set_single_item(
            self.ctx, f"{self.__prefix}/{oid}", [json.dumps(value)]
        )

    def replace_advisories(self, advisories: Dict[str, Dict[str, str]]):
        """Atomically replace all advisory entries in this cache namespace."""
        keys = OpenvasDB.get_keys_by_pattern(self.ctx, f"{self.__prefix}/*")
        pipe = self.ctx.pipeline(transaction=True)
        if keys:
            pipe.delete(*keys)
        for oid, advisory in advisories.items():
            pipe.rpush(f"{self.__prefix}/{oid}", json.dumps(advisory))
        pipe.execute()

    def exists(self, oid: str) -> bool:
        return OpenvasDB.exists(self.ctx, f"{self.__prefix}/{oid}")

    def get_advisory(self, oid: str) -> Optional[Dict[str, str]]:
        result = OpenvasDB.get_single_item(self.ctx, f"{self.__prefix}/{oid}")

        if result:
            return json.loads(result)
        return None

    def get_oids(self) -> Iterator[Tuple[str, str]]:
        """Get the list of NVT file names and OIDs.

        Returns:
            An iterable of tuples of file name and oid.
        """

        def parse_oid(item):
            return str(item).rsplit('/', maxsplit=1)[-1]

        for f, oid in OpenvasDB.get_filenames_and_oids(
            self.ctx, f"{self.__prefix}*", parse_oid
        ):
            yield (f, oid)


class Notus:
    """Stores and access notus advisory data in redis"""

    cache: Cache
    loaded: bool = False
    loading: bool = False
    path: Path
    disable_hashsum_verification: bool
    _verifier: Optional[Callable[[Path], bool]]

    def __init__(
        self,
        path: Path,
        cache: Cache,
        disable_notus_hashsum_verification: bool = False,
    ):
        self.path = path
        self.cache = cache
        self._verifier = None
        self.disable_hashsum_verification = disable_notus_hashsum_verification
        self.loaded = False
        self.loading = False
        self._loading_condition = Condition()

    def reload_cache(self):
        with self._loading_condition:
            if self.loading:
                while self.loading:
                    self._loading_condition.wait()
                return
            self.loading = True

        try:
            advisories = self._stage_advisories()
            self.cache.replace_advisories(advisories)
        except Exception:  # pylint: disable=broad-exception-caught
            # A broken feed or Redis failure must not destroy the prior cache.
            logger.exception("Unable to reload Notus advisories.")
        else:
            self.loaded = True
        finally:
            with self._loading_condition:
                self.loading = False
                self._loading_condition.notify_all()

    def _stage_advisories(self) -> Dict[str, Dict[str, str]]:
        """Verify and parse the complete feed before changing Redis."""
        verifier = self._verifier
        if verifier is None:
            verifier = hashsum_verificator(
                self.path, self.disable_hashsum_verification
            )

        staged_advisories = {}
        for f in self.path.glob('*.notus'):
            if not verifier(f):
                raise ValueError(f"Invalid Notus advisory signature: {f}")
            data = json.loads(f.read_bytes())
            advisories = data.pop("advisories", [])
            for advisory in advisories:
                oid = advisory["oid"]
                if oid in staged_advisories:
                    raise ValueError(f"Duplicate Notus advisory OID: {oid}")
                staged_advisories[oid] = self.__to_ospd(f, advisory, data)
        return staged_advisories

    def __to_ospd(
        self, path: Path, advisory: Dict[str, Any], meta_data: Dict[str, Any]
    ):
        result = {}
        result["vt_params"] = []
        result["creation_date"] = str(advisory.get("creation_date", 0))
        result["last_modification"] = str(advisory.get("last_modification", 0))
        result["modification_time"] = str(advisory.get("last_modification", 0))
        result["summary"] = advisory.get("summary")
        result["impact"] = advisory.get("impact")
        result["affected"] = advisory.get("affected")
        result["insight"] = advisory.get("insight")
        result['solution'] = "Please install the updated package(s)."
        result['solution_type'] = "VendorFix"
        result['vuldetect'] = (
            'Checks if a vulnerable package version is present on the target'
            ' host.'
        )
        result['qod_type'] = advisory.get('qod_type', 'package')
        severity = advisory.get('severity', {})
        cvss = severity.get("cvss_v3", None)
        if not cvss:
            cvss = severity.get("cvss_v2", None)
        result["severity_vector"] = cvss
        result["filename"] = path.name
        cves = advisory.get("cves", None)
        xrefs = advisory.get("xrefs", None)
        advisory_xref = advisory.get("advisory_xref", "")
        refs = {}
        refs['url'] = [advisory_xref]
        advisory_id = advisory.get("advisory_id", None)
        if cves:
            refs['cve'] = cves
        if xrefs:
            refs['url'] = refs['url'] + xrefs
        if advisory_id:
            refs['advisory_id'] = [advisory_id]

        result["refs"] = refs
        result["family"] = meta_data.get("family", path.stem)
        result["name"] = advisory.get("title", "")
        result["category"] = "3"
        return result

    def get_oids(self):
        if not self.loaded:
            self.reload_cache()

        return self.cache.get_oids()

    def exists(self, oid: str) -> bool:
        return self.cache.exists(oid)

    def get_nvt_metadata(self, oid: str) -> Optional[Dict[str, str]]:
        return self.cache.get_advisory(oid)


class NotusResultHandler:
    """Class to handle results generated by the Notus-Scanner"""

    def __init__(
        self,
        report_func: Callable[[list, str], bool],
        scan_exists: Optional[Callable[[str], bool]] = None,
        incomplete_func: Optional[Callable[[str, str], None]] = None,
    ) -> None:
        self._results = {}
        self._result_sizes = {}
        self._timers = {}
        self._reporting_scans = set()
        self._result_count = 0
        self._result_bytes = 0
        self._result_bytes_per_scan = {}
        self._report_failures = {}
        self._incomplete_scans = set()
        self._lock = Lock()
        self._report_func = report_func
        self._scan_exists = scan_exists
        self._incomplete_func = incomplete_func

    def _mark_incomplete(self, scan_id: str, reason: str) -> None:
        if self._incomplete_func is None:
            return
        with self._lock:
            if scan_id in self._incomplete_scans:
                return
            self._incomplete_scans.add(scan_id)
        try:
            self._incomplete_func(scan_id, reason)
        except Exception:  # pylint: disable=broad-exception-caught
            with self._lock:
                self._incomplete_scans.discard(scan_id)
            logger.exception(
                "Unable to mark Notus results incomplete for scan id %s.",
                scan_id,
            )

    def _schedule_report(
        self, scan_id: str, delay: float = NOTUS_RESULT_DELAY_SECONDS
    ) -> bool:
        with self._lock:
            if self._timers.get(scan_id) is not None:
                return True
            if scan_id in self._reporting_scans:
                return True
            if not self._results.get(scan_id):
                return True
            timer = Timer(delay, self._report_results, [scan_id])
            self._timers[scan_id] = timer
        try:
            timer.start()
        except RuntimeError:
            with self._lock:
                if self._timers.get(scan_id) is timer:
                    self._timers.pop(scan_id, None)
            logger.exception(
                "Unable to schedule Notus result reporting for scan id %s.",
                scan_id,
            )
            self._mark_incomplete(
                scan_id, "Notus result delivery could not be scheduled."
            )
            return False
        return True

    def _remove_batch_prefix(self, scan_id: str, results: list) -> bool:
        with self._lock:
            current_results = self._results.get(scan_id, [])
            current_sizes = self._result_sizes.get(scan_id, [])
            if current_results[: len(results)] != results or len(
                current_sizes
            ) < len(results):
                return False

            batch_bytes = sum(current_sizes[: len(results)])
            del current_results[: len(results)]
            del current_sizes[: len(results)]
            self._result_count -= len(results)
            self._result_bytes -= batch_bytes
            if current_results:
                self._result_bytes_per_scan[scan_id] -= batch_bytes
            else:
                self._results.pop(scan_id, None)
                self._result_sizes.pop(scan_id, None)
                self._result_bytes_per_scan.pop(scan_id, None)
            return True

    def _discard_scan_buffer(self, scan_id: str) -> None:
        with self._lock:
            results = self._results.pop(scan_id, [])
            self._result_sizes.pop(scan_id, None)
            self._result_count -= len(results)
            self._result_bytes -= self._result_bytes_per_scan.pop(scan_id, 0)
            self._report_failures.pop(scan_id, None)
            self._reporting_scans.discard(scan_id)
            timer = self._timers.pop(scan_id, None)
        if timer is not None:
            timer.cancel()

    def _report_results(self, scan_id: str) -> None:
        """Reports all results collected for a scan"""
        with self._lock:
            if scan_id in self._reporting_scans:
                return
            self._timers.pop(scan_id, None)
            results = list(self._results.get(scan_id, []))
            if not results:
                return
            self._reporting_scans.add(scan_id)

        try:
            reported = self._report_func(results, scan_id)
        except Exception:  # pylint: disable=broad-exception-caught
            logger.exception(
                "Unable to report %d notus results for scan id %s.",
                len(results),
                scan_id,
            )
            reported = False
        if not reported:
            logger.warning(
                "Unable to report %d notus results for scan id %s.",
                len(results),
                scan_id,
            )
            if self._scan_exists is not None and not self._scan_exists(scan_id):
                logger.info(
                    "Discarding undeliverable Notus results for removed "
                    "scan id %s.",
                    scan_id,
                )
                self._discard_scan_buffer(scan_id)
                return
            with self._lock:
                failures = self._report_failures.get(scan_id, 0) + 1
                self._report_failures[scan_id] = failures
            if failures >= MAX_NOTUS_RESULT_RETRIES:
                self._mark_incomplete(
                    scan_id,
                    "Notus result delivery failed after bounded retries.",
                )
                self._discard_scan_buffer(scan_id)
                return
        else:
            if not self._remove_batch_prefix(scan_id, results):
                logger.error(
                    "Notus result buffer changed before delivery "
                    "confirmation for scan id %s.",
                    scan_id,
                )
                self._mark_incomplete(
                    scan_id,
                    "Notus result delivery ordering could not be verified.",
                )
                self._discard_scan_buffer(scan_id)
                return
            with self._lock:
                self._report_failures.pop(scan_id, None)

        with self._lock:
            self._reporting_scans.discard(scan_id)
            pending = bool(self._results.get(scan_id))
        if pending:
            delay = (
                NOTUS_RESULT_DELAY_SECONDS
                if reported
                else NOTUS_RESULT_RETRY_SECONDS
            )
            self._schedule_report(scan_id, delay)

    def result_handler(self, res_msg: ResultMessage) -> None:
        """Handles results generated by the Notus-Scanner.

        When receiving a result for a scan a time gets started to publish all
        results given within 0.25 seconds."""
        result = res_msg.serialize()
        scan_id = result.pop("scan_id", None)
        if (
            not isinstance(scan_id, str)
            or not scan_id
            or len(scan_id) > MAX_NOTUS_SCAN_ID_LENGTH
            or not scan_id.isprintable()
        ):
            logger.warning("Ignoring Notus result without a valid scan id.")
            return
        if self._scan_exists is not None and not self._scan_exists(scan_id):
            logger.warning(
                "Ignoring Notus result for unknown scan id %s.", scan_id
            )
            return
        try:
            result_bytes = len(
                json.dumps(
                    result, ensure_ascii=True, separators=(',', ':')
                ).encode('utf-8')
            )
        except (TypeError, ValueError, UnicodeError):
            logger.warning(
                "Ignoring Notus result that cannot be safely buffered for "
                "scan id %s.",
                scan_id,
            )
            self._mark_incomplete(
                scan_id, "A Notus result could not be serialized safely."
            )
            return
        if result_bytes > MAX_NOTUS_RESULT_BYTES:
            logger.warning(
                "Notus result is too large for scan id %s; dropping result.",
                scan_id,
            )
            self._mark_incomplete(
                scan_id, "A Notus result exceeded the per-result byte limit."
            )
            return

        schedule_report = False
        drop_reason = None

        with self._lock:
            results = self._results.get(scan_id)
            scan_result_bytes = self._result_bytes_per_scan.get(scan_id, 0)
            if results and len(results) >= MAX_RESULTS_PER_SCAN:
                drop_reason = "per-scan result-count capacity was exhausted"
            elif (
                scan_result_bytes + result_bytes
                > MAX_NOTUS_RESULT_BYTES_PER_SCAN
            ):
                drop_reason = "per-scan byte capacity was exhausted"
            elif self._result_count >= MAX_BUFFERED_NOTUS_RESULTS:
                drop_reason = "global result-count capacity was exhausted"
            elif (
                self._result_bytes + result_bytes
                > MAX_BUFFERED_NOTUS_RESULT_BYTES
            ):
                drop_reason = "global byte capacity was exhausted"
            elif results is None:
                if len(self._results) >= MAX_PENDING_NOTUS_SCANS:
                    drop_reason = "pending-scan capacity was exhausted"
                else:
                    results = []
                    self._results[scan_id] = results
                    self._result_sizes[scan_id] = []
                    schedule_report = True

            if drop_reason is None:
                results.append(result)
                self._result_sizes[scan_id].append(result_bytes)
                self._result_count += 1
                self._result_bytes += result_bytes
                self._result_bytes_per_scan[scan_id] = (
                    scan_result_bytes + result_bytes
                )
                schedule_report = (
                    self._timers.get(scan_id) is None
                    and scan_id not in self._reporting_scans
                )

        if drop_reason is not None:
            logger.warning(
                "Notus result delivery is incomplete for scan id %s: %s.",
                scan_id,
                drop_reason,
            )
            self._mark_incomplete(scan_id, f"Notus result {drop_reason}.")
            return

        if schedule_report:
            self._schedule_report(scan_id)

    def discard_scan(self, scan_id: str) -> None:
        """Release buffered delivery state after a scan is deleted."""
        self._discard_scan_buffer(scan_id)
        with self._lock:
            self._incomplete_scans.discard(scan_id)

    def shutdown(self) -> None:
        """Cancel timers and release all buffered delivery state."""
        with self._lock:
            timers = list(self._timers.values())
            self._results.clear()
            self._result_sizes.clear()
            self._timers.clear()
            self._reporting_scans.clear()
            self._report_failures.clear()
            self._incomplete_scans.clear()
            self._result_bytes_per_scan.clear()
            self._result_count = 0
            self._result_bytes = 0
        for timer in timers:
            timer.cancel()


DEFAULT_NOTUS_FEED_DIR = "/var/lib/notus/advisories"


class NotusParser(CliParser):
    def __init__(self):
        super().__init__('OSPD - openvas')
        self.parser.add_argument(
            '--notus-feed-dir',
            default=DEFAULT_NOTUS_FEED_DIR,
            help='Directory where notus feed is placed. Default: %(default)s',
        )
        self.parser.add_argument(
            '--disable-notus-hashsum-verification',
            default=False,
            type=strtoboolean,
            help=(
                'Disable hashsum verification for notus advisories.'
                ' %(default)s'
            ),
        )
