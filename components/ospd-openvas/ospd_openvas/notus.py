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
from ospd.result_spool import (
    ResultSpoolCapacityError,
    ResultSpoolConflictError,
    ResultSpoolSerializationError,
    ResultSpoolValidationError,
)
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
MAX_NOTUS_SCAN_ID_LENGTH = 128


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
    """Durably admit Notus results and schedule their OSP materialization."""

    def __init__(
        self,
        admit_func: Callable[[str, str, Dict[str, Any]], Optional[bool]],
        report_func: Callable[[str], bool],
        pending_func: Callable[[str], bool],
        incomplete_func: Optional[Callable[[str, str], bool]] = None,
    ) -> None:
        self._timers = {}
        self._reporting_scans = set()
        self._report_failures = {}
        self._incomplete_scans = set()
        self._lock = Lock()
        self._admit_func = admit_func
        self._report_func = report_func
        self._pending_func = pending_func
        self._incomplete_func = incomplete_func

    def _mark_incomplete(self, scan_id: str, reason: str) -> bool:
        if self._incomplete_func is None:
            return False
        with self._lock:
            if scan_id in self._incomplete_scans:
                return True
            self._incomplete_scans.add(scan_id)
        try:
            recorded = self._incomplete_func(scan_id, reason)
        except Exception:  # pylint: disable=broad-exception-caught
            with self._lock:
                self._incomplete_scans.discard(scan_id)
            logger.exception(
                "Unable to mark Notus results incomplete for scan id %s.",
                scan_id,
            )
            return False
        if recorded is False:
            with self._lock:
                self._incomplete_scans.discard(scan_id)
            return False
        return True

    def _schedule_report(
        self, scan_id: str, delay: float = NOTUS_RESULT_DELAY_SECONDS
    ) -> bool:
        try:
            if not self._pending_func(scan_id):
                return True
        except Exception:  # pylint: disable=broad-exception-caught
            logger.exception(
                "Unable to inspect durable Notus results for scan id %s.",
                scan_id,
            )
            self._mark_incomplete(
                scan_id, "Durable Notus result state could not be inspected."
            )
            delay = NOTUS_RESULT_RETRY_SECONDS
        with self._lock:
            if self._timers.get(scan_id) is not None:
                return True
            if scan_id in self._reporting_scans:
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

    def _report_results(self, scan_id: str) -> None:
        """Materialize the next durable Notus source batch."""
        with self._lock:
            if scan_id in self._reporting_scans:
                return
            self._timers.pop(scan_id, None)
            self._reporting_scans.add(scan_id)
        try:
            reported = self._report_func(scan_id)
        except Exception:  # pylint: disable=broad-exception-caught
            logger.exception(
                "Unable to report durable Notus results for scan id %s.",
                scan_id,
            )
            reported = False

        retry = False
        if reported:
            with self._lock:
                self._report_failures.pop(scan_id, None)
        else:
            logger.warning(
                "Unable to report durable Notus results for scan id %s.",
                scan_id,
            )
            with self._lock:
                failures = self._report_failures.get(scan_id, 0) + 1
                self._report_failures[scan_id] = failures
            if failures >= MAX_NOTUS_RESULT_RETRIES:
                retry = not self._mark_incomplete(
                    scan_id,
                    "Notus result delivery failed after bounded retries; "
                    "admitted evidence remains durable.",
                )
            else:
                retry = True

        with self._lock:
            self._reporting_scans.discard(scan_id)
        if retry:
            self._schedule_report(scan_id, NOTUS_RESULT_RETRY_SECONDS)
        elif reported:
            self._schedule_report(scan_id)

    def result_handler(self, res_msg: ResultMessage) -> bool:
        """Admit a Notus message durably before returning to MQTT."""
        try:
            result = res_msg.serialize()
        except Exception:  # pylint: disable=broad-exception-caught
            logger.exception(
                "Ignoring a Notus result that cannot be serialized."
            )
            return True
        scan_id = result.pop("scan_id", None)
        if (
            not isinstance(scan_id, str)
            or not scan_id
            or len(scan_id) > MAX_NOTUS_SCAN_ID_LENGTH
            or not scan_id.isprintable()
        ):
            logger.warning("Ignoring Notus result without a valid scan id.")
            return True
        message_id = result.get('message_id')
        required_strings = (
            'message_id',
            'host_ip',
            'host_name',
            'oid',
            'value',
            'port',
            'result_type',
        )
        if (
            any(
                not isinstance(result.get(field), str)
                for field in required_strings
            )
            or result.get('result_type') != 'ALARM'
        ):
            logger.warning(
                "Rejecting malformed Notus result fields for scan id %s.",
                scan_id,
            )
            return self._mark_incomplete(
                scan_id, "A Notus result contained malformed required fields."
            )
        if result.get('uri') is not None and not isinstance(
            result.get('uri'), str
        ):
            logger.warning(
                "Rejecting malformed Notus result URI for scan id %s.", scan_id
            )
            return self._mark_incomplete(
                scan_id, "A Notus result contained a malformed URI."
            )
        try:
            admitted = self._admit_func(scan_id, message_id, result)
        except (
            ResultSpoolCapacityError,
            ResultSpoolConflictError,
            ResultSpoolSerializationError,
            ResultSpoolValidationError,
        ) as error:
            logger.warning(
                "Rejecting a Notus result for scan id %s after durable "
                "incomplete-evidence handling.",
                scan_id,
            )
            return self._mark_incomplete(scan_id, str(error))
        except Exception:  # pylint: disable=broad-exception-caught
            logger.exception(
                "Unable to admit a Notus result durably for scan id %s; "
                "leaving the broker message unacknowledged.",
                scan_id,
            )
            return False
        if admitted is None:
            logger.warning(
                "Ignoring Notus result for unknown scan id %s.", scan_id
            )
            return True
        self._schedule_report(scan_id)
        return True

    def resume_scan(self, scan_id: str) -> bool:
        """Resume materialization of durable ingress after restart."""
        return self._schedule_report(scan_id, 0)

    def discard_scan(self, scan_id: str) -> None:
        """Release scheduler state after durable scan deletion."""
        with self._lock:
            timer = self._timers.pop(scan_id, None)
            self._report_failures.pop(scan_id, None)
            self._reporting_scans.discard(scan_id)
            self._incomplete_scans.discard(scan_id)
        if timer is not None:
            timer.cancel()

    def shutdown(self) -> None:
        """Cancel timers without erasing durably admitted evidence."""
        with self._lock:
            timers = list(self._timers.values())
            self._timers.clear()
            self._reporting_scans.clear()
            self._report_failures.clear()
            self._incomplete_scans.clear()
        for timer in timers:
            timer.cancel()


DEFAULT_NOTUS_FEED_DIR = "/var/lib/notus/advisories"
DEFAULT_RESULT_SPOOL_DIR = "/var/lib/openvas/result-spool"


class NotusParser(CliParser):
    def __init__(self):
        super().__init__('OSPD - openvas')
        self.parser.add_argument(
            '--notus-feed-dir',
            default=DEFAULT_NOTUS_FEED_DIR,
            help='Directory where notus feed is placed. Default: %(default)s',
        )
        self.parser.add_argument(
            '--result-spool-dir',
            default=DEFAULT_RESULT_SPOOL_DIR,
            help=(
                'Private durable scanner-result spool directory. '
                'Default: %(default)s'
            ),
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
