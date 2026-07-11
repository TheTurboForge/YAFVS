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
    ) -> None:
        self._results = {}
        self._timers = {}
        self._result_count = 0
        self._result_bytes = 0
        self._result_bytes_per_scan = {}
        self._lock = Lock()
        self._report_func = report_func
        self._scan_exists = scan_exists

    def _report_results(self, scan_id: str) -> None:
        """Reports all results collected for a scan"""
        with self._lock:
            results = self._results.pop(scan_id, None)
            self._timers.pop(scan_id, None)
            if not results:
                return
            self._result_count -= len(results)
            self._result_bytes -= self._result_bytes_per_scan.pop(scan_id, 0)

        try:
            reported = self._report_func(results, scan_id)
        except Exception:  # pylint: disable=broad-exception-caught
            # Reporting is external to this buffer and must not kill its timer.
            logger.exception(
                "Unable to report %d notus results for scan id %s.",
                len(results),
                scan_id,
            )
            return
        if not reported:
            logger.warning(
                "Unable to report %d notus results for scan id %s.",
                len(results),
                scan_id,
            )

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
            return
        if result_bytes > MAX_NOTUS_RESULT_BYTES:
            logger.warning(
                "Notus result is too large for scan id %s; dropping result.",
                scan_id,
            )
            return

        timer = None

        with self._lock:
            results = self._results.get(scan_id)
            scan_result_bytes = self._result_bytes_per_scan.get(scan_id, 0)
            if results and len(results) >= MAX_RESULTS_PER_SCAN:
                logger.warning(
                    "Notus result buffer is full for scan id %s; dropping "
                    "result.",
                    scan_id,
                )
                return
            if (
                scan_result_bytes + result_bytes
                > MAX_NOTUS_RESULT_BYTES_PER_SCAN
            ):
                logger.warning(
                    "Notus result byte buffer is full for scan id %s; "
                    "dropping result.",
                    scan_id,
                )
                return
            if self._result_count >= MAX_BUFFERED_NOTUS_RESULTS:
                logger.warning("Notus result buffer is full; dropping result.")
                return
            if (
                self._result_bytes + result_bytes
                > MAX_BUFFERED_NOTUS_RESULT_BYTES
            ):
                logger.warning(
                    "Notus result byte buffer is full; dropping result."
                )
                return
            if results is None:
                if len(self._results) >= MAX_PENDING_NOTUS_SCANS:
                    logger.warning(
                        "Too many pending Notus result scans; dropping result "
                        "for scan id %s.",
                        scan_id,
                    )
                    return
                results = []
                self._results[scan_id] = results
                timer = Timer(
                    NOTUS_RESULT_DELAY_SECONDS, self._report_results, [scan_id]
                )
                self._timers[scan_id] = timer

            results.append(result)
            self._result_count += 1
            self._result_bytes += result_bytes
            self._result_bytes_per_scan[scan_id] = (
                scan_result_bytes + result_bytes
            )

        if timer:
            try:
                timer.start()
            except RuntimeError:
                with self._lock:
                    if self._timers.get(scan_id) is timer:
                        discarded = self._results.pop(scan_id, [])
                        self._timers.pop(scan_id, None)
                        self._result_count -= len(discarded)
                        self._result_bytes -= self._result_bytes_per_scan.pop(
                            scan_id, 0
                        )
                logger.exception(
                    "Unable to schedule Notus result reporting for scan id %s.",
                    scan_id,
                )


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
