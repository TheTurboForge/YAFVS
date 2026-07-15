# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2014-2023 Greenbone AG
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: AGPL-3.0-or-later


# pylint: disable=invalid-name,line-too-long,no-member,no-value-for-parameter

"""Unit Test for ospd-openvas"""

import io
import json
import logging
from pathlib import Path

from unittest import TestCase
from unittest.mock import patch, Mock, MagicMock

from ospd.protocol import OspRequest
from ospd.scan import ScanStatus

from tests.dummydaemon import DummyDaemon
from tests.helper import assert_called_once

from ospd_openvas.daemon import (
    OSPD_PARAMS,
    OpenVasVtsFilter,
    parse_openvas_result_row,
)
from ospd_openvas.openvas import Openvas
from ospd_openvas.notus import Notus, hashsum_verificator

OSPD_PARAMS_OUT = {
    'auto_enable_dependencies': {
        'type': 'boolean',
        'name': 'auto_enable_dependencies',
        'default': 1,
        'mandatory': 1,
        'visible_for_client': True,
        'description': 'Automatically enable the plugins that are depended on',
    },
    'cgi_path': {
        'type': 'string',
        'name': 'cgi_path',
        'default': '/cgi-bin:/scripts',
        'mandatory': 1,
        'visible_for_client': True,
        'description': 'Look for default CGIs in /cgi-bin and /scripts',
    },
    'checks_read_timeout': {
        'type': 'integer',
        'name': 'checks_read_timeout',
        'default': 5,
        'mandatory': 1,
        'visible_for_client': True,
        'description': (
            'Number  of seconds that the security checks will '
            + 'wait for when doing a recv()'
        ),
    },
    'non_simult_ports': {
        'type': 'string',
        'name': 'non_simult_ports',
        'default': '139, 445, 3389, Services/irc',
        'mandatory': 1,
        'visible_for_client': True,
        'description': (
            'Prevent to make two connections on the same given '
            + 'ports at the same time.'
        ),
    },
    'open_sock_max_attempts': {
        'type': 'integer',
        'name': 'open_sock_max_attempts',
        'default': 5,
        'mandatory': 0,
        'visible_for_client': True,
        'description': (
            'Number of unsuccessful retries to open the socket '
            + 'before to set the port as closed.'
        ),
    },
    'timeout_retry': {
        'type': 'integer',
        'name': 'timeout_retry',
        'default': 5,
        'mandatory': 0,
        'visible_for_client': True,
        'description': (
            'Number of retries when a socket connection attempt ' + 'timesout.'
        ),
    },
    'optimize_test': {
        'type': 'boolean',
        'name': 'optimize_test',
        'default': 1,
        'mandatory': 0,
        'visible_for_client': True,
        'description': (
            'By default, optimize_test is enabled which means openvas does '
            + 'trust the remote host banners and is only launching plugins '
            + 'against the services they have been designed to check. '
            + 'For example it will check a web server claiming to be IIS only '
            + 'for IIS related flaws but will skip plugins testing for Apache '
            + 'flaws, and so on. This default behavior is used to optimize '
            + 'the scanning performance and to avoid false positives. '
            + 'If you are not sure that the banners of the remote host '
            + 'have been tampered with, you can disable this option.'
        ),
    },
    'plugins_timeout': {
        'type': 'integer',
        'name': 'plugins_timeout',
        'default': 180,
        'mandatory': 0,
        'visible_for_client': True,
        'description': 'This is the maximum lifetime, in seconds of a plugin.',
    },
    'report_host_details': {
        'type': 'boolean',
        'name': 'report_host_details',
        'default': 1,
        'mandatory': 1,
        'visible_for_client': True,
        'description': '',
    },
    'safe_checks': {
        'type': 'boolean',
        'name': 'safe_checks',
        'default': 1,
        'mandatory': 1,
        'visible_for_client': True,
        'description': (
            'Disable the plugins with potential to crash '
            + 'the remote services'
        ),
    },
    'scanner_plugins_timeout': {
        'type': 'integer',
        'name': 'scanner_plugins_timeout',
        'default': 180,
        'mandatory': 1,
        'visible_for_client': True,
        'description': 'Like plugins_timeout, but for ACT_SCANNER plugins.',
    },
    'time_between_request': {
        'type': 'integer',
        'name': 'time_between_request',
        'default': 0,
        'mandatory': 0,
        'visible_for_client': True,
        'description': (
            'Allow to set a wait time between two actions '
            + '(open, send, close).'
        ),
    },
    'unscanned_closed': {
        'type': 'boolean',
        'name': 'unscanned_closed',
        'default': 1,
        'mandatory': 1,
        'visible_for_client': True,
        'description': '',
    },
    'unscanned_closed_udp': {
        'type': 'boolean',
        'name': 'unscanned_closed_udp',
        'default': 1,
        'mandatory': 1,
        'visible_for_client': True,
        'description': '',
    },
    'expand_vhosts': {
        'type': 'boolean',
        'name': 'expand_vhosts',
        'default': 1,
        'mandatory': 0,
        'visible_for_client': True,
        'description': 'Whether to expand the target hosts '
        + 'list of vhosts with values gathered from sources '
        + 'such as reverse-lookup queries and VT checks '
        + 'for SSL/TLS certificates.',
    },
    'test_empty_vhost': {
        'type': 'boolean',
        'name': 'test_empty_vhost',
        'default': 0,
        'mandatory': 0,
        'visible_for_client': True,
        'description': 'If  set  to  yes, the scanner will '
        + 'also test the target by using empty vhost value '
        + 'in addition to the targets associated vhost values.',
    },
    'max_hosts': {
        'type': 'integer',
        'name': 'max_hosts',
        'default': 30,
        'mandatory': 0,
        'visible_for_client': False,
        'description': (
            'The maximum number of hosts to test at the same time which '
            + 'should be given to the client (which can override it). '
            + 'This value must be computed given your bandwidth, '
            + 'the number of hosts you want to test, your amount of '
            + 'memory and the performance of your processor(s).'
        ),
    },
    'max_checks': {
        'type': 'integer',
        'name': 'max_checks',
        'default': 10,
        'mandatory': 0,
        'visible_for_client': False,
        'description': (
            'The number of plugins that will run against each host being '
            + 'tested. Note that the total number of process will be max '
            + 'checks x max_hosts so you need to find a balance between '
            + 'these two options. Note that launching too many plugins at '
            + 'the same time may disable the remote host, either temporarily '
            + '(ie: inetd closes its ports) or definitely (the remote host '
            + 'crash because it is asked to do too many things at the '
            + 'same time), so be careful.'
        ),
    },
    'port_range': {
        'type': 'string',
        'name': 'port_range',
        'default': '',
        'mandatory': 0,
        'visible_for_client': False,
        'description': (
            'This is the default range of ports that the scanner plugins will '
            + 'probe. The syntax of this option is flexible, it can be a '
            + 'single range ("1-1500"), several ports ("21,23,80"), several '
            + 'ranges of ports ("1-1500,32000-33000"). Note that you can '
            + 'specify UDP and TCP ports by prefixing each range by T or U. '
            + 'For instance, the following range will make openvas scan UDP '
            + 'ports 1 to 1024 and TCP ports 1 to 65535 : '
            + '"T:1-65535,U:1-1024".'
        ),
    },
    'alive_test_ports': {
        'type': 'string',
        'name': 'alive_test_ports',
        'default': '21-23,25,53,80,110-111,135,139,143,443,445,'
        + '993,995,1723,3306,3389,5900,8080',
        'mandatory': 0,
        'visible_for_client': True,
        'description': ('Port list used for host alive detection.'),
    },
    'test_alive_hosts_only': {
        'type': 'boolean',
        'name': 'test_alive_hosts_only',
        'default': 0,
        'mandatory': 0,
        'visible_for_client': False,
        'description': (
            'If this option is set, openvas will scan the target list for '
            + 'alive hosts in a separate process while only testing those '
            + 'hosts which are identified as alive. This boosts the scan '
            + 'speed of target ranges with a high amount of dead hosts '
            + 'significantly.'
        ),
    },
    'test_alive_wait_timeout': {
        'type': 'integer',
        'name': 'test_alive_wait_timeout',
        'default': 1,
        'mandatory': 0,
        'visible_for_client': True,
        'description': (
            'This is the default timeout to wait for replies after last '
            + 'packet was sent.'
        ),
    },
    'icmp_retries': {
        'type': 'integer',
        'name': 'icmp_retries',
        'default': 1,
        'mandatory': 0,
        'visible_for_client': True,
        'description': (
            'This is the default amount of icmp packets that will be '
            + 'sent to the host target during an alive test.'
        ),
    },
    'icmp_grace_period': {
        'type': 'integer',
        'name': 'icmp_grace_period',
        'default': 0,
        'mandatory': 0,
        'visible_for_client': True,
        'description': (
            'Wait time between icmp packets during alive tests. '
            + 'Useful for sensitive targets. It can slow '
            + 'down the alive test.'
        ),
    },
    'hosts_allow': {
        'type': 'string',
        'name': 'hosts_allow',
        'default': '',
        'mandatory': 0,
        'visible_for_client': False,
        'description': (
            'Comma-separated list of the only targets that are authorized '
            + 'to be scanned. Supports the same syntax as the list targets. '
            + 'Both target hostnames and the address to which they resolve '
            + 'are checked. Hostnames in hosts_allow list are not resolved '
            + 'however.'
        ),
    },
    'hosts_deny': {
        'type': 'string',
        'name': 'hosts_deny',
        'default': '',
        'mandatory': 0,
        'visible_for_client': False,
        'description': (
            'Comma-separated list of targets that are not authorized to '
            + 'be scanned. Supports the same syntax as the list targets. '
            + 'Both target hostnames and the address to which they resolve '
            + 'are checked. Hostnames in hosts_deny list are not '
            + 'resolved however.'
        ),
    },
    'results_per_host': {
        'type': 'integer',
        'name': 'results_per_host',
        'default': 10,
        'mandatory': 0,
        'visible_for_client': True,
        'description': (
            'Amount of fake results generated per each host in the target '
            + 'list for a dry run scan.'
        ),
    },
    'table_driven_lsc': {
        'type': 'boolean',
        'name': 'table_driven_lsc',
        'default': 1,
        'mandatory': 0,
        'visible_for_client': True,
        'description': (
            'If this option is enabled a scanner for table_driven_lsc will '
            + 'scan package results.'
        ),
    },
    'max_mem_kb': {
        'type': 'integer',
        'name': 'max_mem_kb',
        'default': 0,
        'mandatory': 0,
        'visible_for_client': True,
        'description': (
            'Maximum amount of memory (in MB) allowed to use for a single '
            + 'script. If this value is set, the amount of memory put into '
            + 'redis is tracked for every Script. If the amount of memory '
            + 'exceeds this limit, the script is not able to set more kb '
            + 'items. The tracked the value written into redis is only '
            + 'estimated, as it does not check, if a value was replaced or '
            + 'appended. The size of the key is also not tracked. If this '
            + 'value is not set or <= 0, the maximum amount is unlimited '
            + '(Default).'
        ),
    },
}


def openvas_result_row(
    result_type,
    host_ip='',
    host_name='',
    port='',
    oid='',
    value='',
    uri='',
):
    return json.dumps(
        {
            'version': 1,
            'result_type': result_type,
            'host_ip': host_ip,
            'host_name': host_name,
            'port': port,
            'oid': oid,
            'value': value,
            'uri': uri,
        },
        separators=(',', ':'),
    )


def set_result_claim(db, results, claim_id='claim-1'):
    db.claim_results.return_value = (claim_id, results)
    db.ack_result_claim.return_value = True


class TestOspdOpenvas(TestCase):
    def test_scanner_delivery_failure_is_visible_and_not_duplicated(self):
        daemon = DummyDaemon()
        daemon.scan_collection = MagicMock()
        daemon.scan_collection.id_exists.return_value = True
        daemon.scan_collection.mark_evidence_incomplete.side_effect = [
            True,
            False,
        ]
        daemon.scan_collection.get_status.return_value = ScanStatus.FINISHED
        daemon.add_scan_error = MagicMock()
        daemon.set_scan_status = MagicMock()

        daemon.mark_scanner_evidence_incomplete('scan_1', 'delivery failed')
        daemon.mark_scanner_evidence_incomplete('scan_1', 'delivery failed')

        daemon.add_scan_error.assert_called_once_with(
            'scan_1',
            name='Incomplete scanner result delivery',
            value='delivery failed',
        )
        daemon.set_scan_status.assert_called_once_with(
            'scan_1', ScanStatus.INTERRUPTED
        )

    def test_non_result_notus_messages_are_acknowledged(self):
        daemon = DummyDaemon()
        daemon.scan_collection = MagicMock()
        daemon.scan_collection.id_exists.return_value = True
        daemon.scan_collection.mark_evidence_incomplete.return_value = True
        daemon.add_scan_error = MagicMock()

        reported = daemon.report_results(
            [
                {
                    'result_type': 'HOSTS_COUNT',
                    'host_ip': '',
                    'host_name': '',
                    'port': '',
                    'oid': '',
                    'value': '1',
                    'uri': '',
                }
            ],
            'scan_1',
        )

        self.assertTrue(reported)
        daemon.scan_collection.apply_result_batch.assert_called_once()
        self.assertEqual(
            daemon.scan_collection.apply_result_batch.call_args.args[0],
            'scan_1',
        )
        self.assertEqual(
            daemon.scan_collection.apply_result_batch.call_args.kwargs,
            {
                'total_dead': 0,
                'count_total': 1,
                'count_excluded': None,
            },
        )

    def test_malformed_notus_count_marks_evidence_incomplete(self):
        daemon = DummyDaemon()
        daemon.scan_collection = MagicMock()
        daemon.scan_collection.id_exists.return_value = True
        daemon.scan_collection.mark_evidence_incomplete.return_value = True
        daemon.add_scan_error = MagicMock()

        reported = daemon.report_results(
            [
                {
                    'result_type': 'HOSTS_COUNT',
                    'host_ip': '',
                    'host_name': '',
                    'port': '',
                    'oid': '',
                    'value': 'not-a-count',
                    'uri': '',
                }
            ],
            'scan_1',
        )

        self.assertTrue(reported)
        daemon.scan_collection.apply_result_batch.assert_called_once()
        daemon.add_scan_error.assert_called_once_with(
            'scan_1',
            name='Incomplete scanner result delivery',
            value='Invalid scanner host-count metadata was discarded.',
        )

    def test_return_disabled_verifier(self):
        verifier = hashsum_verificator(Path('/tmp'), True)
        self.assertEqual(verifier(Path('/tmp')), True)

    @patch('ospd_openvas.daemon.Openvas')
    def test_set_params_from_openvas_settings(self, mock_openvas: Openvas):
        mock_openvas.get_settings.return_value = {
            'non_simult_ports': '139, 445, 3389, Services/irc',
            'plugins_folder': '/foo/bar',
        }
        w = DummyDaemon()
        w.set_params_from_openvas_settings()

        self.assertEqual(mock_openvas.get_settings.call_count, 1)
        self.assertEqual(OSPD_PARAMS, OSPD_PARAMS_OUT)
        self.assertEqual(w.scan_only_params.get('plugins_folder'), '/foo/bar')

    @patch('ospd_openvas.daemon.Openvas')
    def test_sudo_available(self, mock_openvas):
        mock_openvas.check_sudo.return_value = True

        w = DummyDaemon()
        w._sudo_available = None  # pylint: disable=protected-access
        w._is_running_as_root = False  # pylint: disable=protected-access

        self.assertTrue(w.sudo_available)

    def test_update_vts(self):
        daemon = DummyDaemon()
        daemon.notus = MagicMock(spec=Notus)
        daemon.update_vts()
        self.assertEqual(daemon.notus.reload_cache.call_count, 1)

    @patch('ospd_openvas.daemon.Path.exists')
    @patch('ospd_openvas.daemon.Path.open')
    def test_get_feed_info(
        self,
        mock_path_open: MagicMock,
        mock_path_exists: MagicMock,
    ):
        read_data = 'PLUGIN_SET = "1235";'

        mock_path_exists.return_value = True
        mock_read = MagicMock(name='Path open context manager')
        mock_read.__enter__ = MagicMock(return_value=io.StringIO(read_data))
        mock_path_open.return_value = mock_read

        w = DummyDaemon()

        # Return True
        w.scan_only_params['plugins_folder'] = '/foo/bar'

        ret = w.get_feed_info()
        self.assertEqual(ret, {"PLUGIN_SET": "1235"})

        self.assertEqual(mock_path_exists.call_count, 1)
        self.assertEqual(mock_path_open.call_count, 1)

    @patch('ospd_openvas.daemon.Path.exists')
    @patch('ospd_openvas.daemon.OSPDopenvas.set_params_from_openvas_settings')
    def test_get_feed_info_none(
        self, mock_set_params: MagicMock, mock_path_exists: MagicMock
    ):
        w = DummyDaemon()

        w.scan_only_params['plugins_folder'] = '/foo/bar'

        # Return None
        mock_path_exists.return_value = False

        ret = w.get_feed_info()
        self.assertEqual(ret, {})

        self.assertEqual(mock_set_params.call_count, 1)
        self.assertEqual(mock_path_exists.call_count, 1)

    @patch('ospd_openvas.daemon.Path.exists')
    @patch('ospd_openvas.daemon.Path.open')
    def test_feed_is_outdated_true(
        self,
        mock_path_open: MagicMock,
        mock_path_exists: MagicMock,
    ):
        read_data = 'PLUGIN_SET = "1235";'

        mock_path_exists.return_value = True
        mock_read = MagicMock(name='Path open context manager')
        mock_read.__enter__ = MagicMock(return_value=io.StringIO(read_data))
        mock_path_open.return_value = mock_read

        w = DummyDaemon()

        # Return True
        w.scan_only_params['plugins_folder'] = '/foo/bar'

        ret = w.feed_is_outdated('1234')
        self.assertTrue(ret)

        self.assertEqual(mock_path_exists.call_count, 1)
        self.assertEqual(mock_path_open.call_count, 1)

    @patch('ospd_openvas.daemon.Path.exists')
    @patch('ospd_openvas.daemon.Path.open')
    def test_feed_is_outdated_false(
        self,
        mock_path_open: MagicMock,
        mock_path_exists: MagicMock,
    ):
        mock_path_exists.return_value = True

        read_data = 'PLUGIN_SET = "1234"'
        mock_path_exists.return_value = True
        mock_read = MagicMock(name='Path open context manager')
        mock_read.__enter__ = MagicMock(return_value=io.StringIO(read_data))
        mock_path_open.return_value = mock_read

        w = DummyDaemon()
        w.scan_only_params['plugins_folder'] = '/foo/bar'

        ret = w.feed_is_outdated('1234')
        self.assertFalse(ret)

        self.assertEqual(mock_path_exists.call_count, 1)
        self.assertEqual(mock_path_open.call_count, 1)

    def test_check_feed_cache_unavailable(self):
        w = DummyDaemon()
        w.vts.is_cache_available = False
        w.feed_is_outdated = Mock()

        w.feed_is_outdated.assert_not_called()

    @patch('ospd_openvas.daemon.BaseDB')
    @patch('ospd_openvas.daemon.ResultList.add_scan_log_to_list')
    def test_get_openvas_result(self, mock_add_scan_log_to_list, MockDBClass):
        w = DummyDaemon()

        target_element = w.create_xml_target()
        targets = OspRequest.process_target_element(target_element)
        w.create_scan('123-456', targets, None, [])

        results = [
            openvas_result_row(
                'LOG',
                host_ip='192.168.0.1',
                host_name='localhost',
                port='general/Host_Details',
                value='Host dead',
            ),
        ]
        set_result_claim(MockDBClass, results)
        mock_add_scan_log_to_list.return_value = None

        w.report_openvas_results(MockDBClass, '123-456')
        mock_add_scan_log_to_list.assert_called_with(
            host='192.168.0.1',
            hostname='localhost',
            name='',
            port='general/Host_Details',
            qod='',
            test_id='',
            uri='',
            value='Host dead',
        )
        MockDBClass.claim_results.assert_called_once_with(
            max_items=1000,
            max_bytes=16 * 1024 * 1024,
            max_item_bytes=4 * 1024 * 1024,
        )
        MockDBClass.ack_result_claim.assert_called_once_with('claim-1')

    @patch('ospd_openvas.daemon.BaseDB')
    def test_result_claim_replays_without_duplicate_application(
        self, MockDBClass
    ):
        w = DummyDaemon()
        target_element = w.create_xml_target()
        targets = OspRequest.process_target_element(target_element)
        w.create_scan('123-456', targets, None, [])
        results = [
            openvas_result_row(
                'HOST_START', host_ip='192.0.2.1', value='started'
            )
        ]
        set_result_claim(MockDBClass, results)
        MockDBClass.ack_result_claim.side_effect = [False, True]

        self.assertFalse(w.report_openvas_results(MockDBClass, '123-456'))
        self.assertTrue(w.report_openvas_results(MockDBClass, '123-456'))

        scan = w.scan_collection.scans_table['123-456']
        self.assertEqual(len(scan['results']), 1)
        self.assertEqual(scan['last_result_claim_id'], '')
        self.assertEqual(MockDBClass.ack_result_claim.call_count, 2)

    @patch('ospd_openvas.daemon.BaseDB')
    def test_stopped_scan_drain_requires_every_claim_acknowledgment(
        self, MockDBClass
    ):
        w = DummyDaemon()
        MockDBClass.has_pending_results.side_effect = [True, True, False]
        w.report_openvas_results = MagicMock(side_effect=[True, True])

        self.assertTrue(w.drain_openvas_results(MockDBClass, 'scan-1'))
        self.assertEqual(w.report_openvas_results.call_count, 2)

        MockDBClass.reset_mock()
        MockDBClass.has_pending_results.return_value = True
        MockDBClass.has_pending_results.side_effect = None
        w.report_openvas_results = MagicMock(return_value=False)

        self.assertFalse(w.drain_openvas_results(MockDBClass, 'scan-1'))
        w.report_openvas_results.assert_called_once_with(MockDBClass, 'scan-1')

    @patch('ospd_openvas.daemon.BaseDB')
    @patch('ospd_openvas.daemon.ResultList.add_scan_error_to_list')
    def test_get_openvas_result_host_deny(
        self, mock_add_scan_error_to_list, MockDBClass
    ):
        w = DummyDaemon()

        target_element = w.create_xml_target()
        targets = OspRequest.process_target_element(target_element)
        w.create_scan('123-456', targets, None, [])

        results = [
            openvas_result_row(
                'ERRMSG',
                host_ip='127.0.0.1',
                host_name='localhost',
                value='Host access denied.',
            ),
        ]
        set_result_claim(MockDBClass, results)
        mock_add_scan_error_to_list.return_value = None

        w.report_openvas_results(MockDBClass, '123-456')
        mock_add_scan_error_to_list.assert_called_with(
            host='127.0.0.1',
            hostname='localhost',
            name='',
            port='',
            test_id='',
            uri='',
            value='Host access denied.',
        )

    @patch('ospd_openvas.daemon.BaseDB')
    def test_get_openvas_result_dead_hosts(self, MockDBClass):
        w = DummyDaemon()
        target_element = w.create_xml_target()
        targets = OspRequest.process_target_element(target_element)
        w.create_scan('123-456', targets, None, [])

        results = [openvas_result_row('DEADHOST', value='4')]
        set_result_claim(MockDBClass, results)

        w.report_openvas_results(MockDBClass, '123-456')
        self.assertEqual(
            w.scan_collection.scans_table['123-456']['count_dead'], 4
        )

    @patch('ospd_openvas.daemon.BaseDB')
    @patch('ospd_openvas.daemon.ResultList.add_scan_log_to_list')
    def test_get_openvas_result_host_start(
        self, mock_add_scan_log_to_list, MockDBClass
    ):
        w = DummyDaemon()
        target_element = w.create_xml_target()
        targets = OspRequest.process_target_element(target_element)
        w.create_scan('123-456', targets, None, [])

        results = [
            openvas_result_row(
                'HOST_START', host_ip='192.168.10.124', value='today 1'
            ),
        ]

        set_result_claim(MockDBClass, results)
        mock_add_scan_log_to_list.return_value = None

        w.report_openvas_results(MockDBClass, '123-456')

        mock_add_scan_log_to_list.assert_called_with(
            host='192.168.10.124',
            name='HOST_START',
            value='today 1',
        )

    @patch('ospd_openvas.daemon.BaseDB')
    def test_get_openvas_result_hosts_count(self, MockDBClass):
        w = DummyDaemon()
        target_element = w.create_xml_target()
        targets = OspRequest.process_target_element(target_element)
        w.create_scan('123-456', targets, None, [])

        results = [openvas_result_row('HOSTS_COUNT', value='4')]
        set_result_claim(MockDBClass, results)

        w.report_openvas_results(MockDBClass, '123-456')
        self.assertEqual(
            w.scan_collection.scans_table['123-456']['count_total'], 4
        )

    @patch('ospd_openvas.daemon.logger.warning')
    @patch('ospd_openvas.daemon.BaseDB')
    @patch('ospd_openvas.daemon.ResultList.add_scan_log_to_list')
    def test_get_openvas_result_quarantines_malformed_rows(
        self, mock_add_scan_log_to_list, MockDBClass, mock_warning
    ):
        w = DummyDaemon()
        target_element = w.create_xml_target()
        targets = OspRequest.process_target_element(target_element)
        w.create_scan('123-456', targets, None, [])

        hostile_row = 'HOSTILE-RESULT-PAYLOAD'
        set_result_claim(
            MockDBClass,
            [
                hostile_row,
                b'not-a-text-result-row',
                '{"turbovas_internal":"oversized_result","bytes":4194305}',
                'x' * (w.MAX_REDIS_RESULT_ROW_LENGTH + 1),
                openvas_result_row(
                    'LOG',
                    host_ip='192.168.0.1',
                    host_name='localhost',
                    port='general/Host_Details',
                    value='Host dead',
                ),
            ],
        )

        w.report_openvas_results(MockDBClass, '123-456')

        mock_add_scan_log_to_list.assert_called_once()
        self.assertEqual(mock_warning.call_count, 4)
        self.assertNotIn(hostile_row, str(mock_warning.call_args_list))
        self.assertTrue(
            w.scan_collection.scans_table['123-456']['evidence_incomplete']
        )

    def test_versioned_openvas_result_preserves_delimiter_fields(self):
        row = (
            '{"version":1,"result_type":"ALARM","host_ip":"192.0.2.1",'
            '"host_name":"host|||name.example","port":"443/tcp",'
            '"oid":"1.3.6.1","value":"line ||| two","uri":"/a|||b"}'
        )

        result = parse_openvas_result_row(row)

        self.assertEqual(result['host_name'], 'host|||name.example')
        self.assertEqual(result['value'], 'line ||| two')
        self.assertEqual(result['uri'], '/a|||b')

    def test_openvas_result_rejects_shifted_or_invalid_rows(self):
        self.assertIsNone(
            parse_openvas_result_row(
                'ALARM|||192.0.2.1|||host|||shift|||443/tcp|||1.3.6.1|||value'
            )
        )
        self.assertIsNone(parse_openvas_result_row('LOG|||too|||short'))
        self.assertIsNone(
            parse_openvas_result_row(
                '{"version":true,"result_type":"LOG","host_ip":"",'
                '"host_name":"","port":"","oid":"","value":"","uri":""}'
            )
        )
        self.assertIsNone(
            parse_openvas_result_row(
                '{"version":1,"version":1,"result_type":"LOG","host_ip":"",'
                '"host_name":"","port":"","oid":"","value":"","uri":""}'
            )
        )
        self.assertIsNone(
            parse_openvas_result_row(
                '{"version":2,"result_type":"LOG","host_ip":"","host_name":"",'
                '"port":"","oid":"","value":"","uri":""}'
            )
        )

    @patch('ospd_openvas.daemon.logger.warning')
    @patch('ospd_openvas.daemon.BaseDB')
    def test_get_openvas_result_quarantines_invalid_host_counts(
        self, MockDBClass, mock_warning
    ):
        w = DummyDaemon()
        target_element = w.create_xml_target()
        targets = OspRequest.process_target_element(target_element)
        w.create_scan('123-456', targets, None, [])
        set_result_claim(
            MockDBClass,
            [
                openvas_result_row('HOSTS_COUNT', value='NaN'),
                openvas_result_row('HOSTS_COUNT', value='-1'),
                openvas_result_row('HOSTS_COUNT', value='2147483648'),
                openvas_result_row('HOSTS_COUNT', value='4'),
                openvas_result_row('HOSTS_EXCLUDED', value='Infinity'),
                openvas_result_row('HOSTS_EXCLUDED', value='2'),
                openvas_result_row('DEADHOST', value='-1'),
                openvas_result_row('DEADHOST', value='3'),
            ],
        )

        w.report_openvas_results(MockDBClass, '123-456')

        scan = w.scan_collection.scans_table['123-456']
        self.assertEqual(scan['count_total'], 4)
        self.assertEqual(scan['count_excluded'], 2)
        self.assertEqual(scan['count_dead'], 3)
        self.assertTrue(scan['evidence_incomplete'])
        self.assertEqual(mock_warning.call_count, 5)

    @patch('ospd_openvas.daemon.logger.warning')
    @patch('ospd_openvas.daemon.BaseDB')
    def test_get_openvas_result_bounds_accumulated_dead_hosts(
        self, MockDBClass, mock_warning
    ):
        w = DummyDaemon()
        target_element = w.create_xml_target()
        targets = OspRequest.process_target_element(target_element)
        w.create_scan('123-456', targets, None, [])
        set_result_claim(
            MockDBClass,
            [
                openvas_result_row(
                    'DEADHOST', value=str(w.MAX_OPENVAS_HOST_COUNT)
                ),
                openvas_result_row('DEADHOST', value='1'),
            ],
        )

        w.report_openvas_results(MockDBClass, '123-456')

        scan = w.scan_collection.scans_table['123-456']
        self.assertEqual(scan['count_dead'], w.MAX_OPENVAS_HOST_COUNT)
        self.assertTrue(scan['evidence_incomplete'])
        mock_warning.assert_called_once()

    @patch('ospd_openvas.daemon.BaseDB')
    @patch('ospd_openvas.daemon.ResultList.add_scan_alarm_to_list')
    def test_result_without_vt_oid(
        self, mock_add_scan_alarm_to_list, MockDBClass
    ):
        w = DummyDaemon()
        logging.Logger.warning = Mock()

        target_element = w.create_xml_target()
        targets = OspRequest.process_target_element(target_element)
        w.create_scan('123-456', targets, None, [])
        w.scan_collection.scans_table['123-456']['results'] = list()
        results = [
            openvas_result_row('ALARM', value='some alarm', uri='path'),
            None,
        ]
        set_result_claim(MockDBClass, results)
        mock_add_scan_alarm_to_list.return_value = None

        w.report_openvas_results(MockDBClass, '123-456')

        assert_called_once(logging.Logger.warning)

    @patch('psutil.Popen')
    def test_openvas_is_alive_already_stopped(self, mock_process):
        w = DummyDaemon()

        mock_process.is_running.return_value = True
        ret = w.is_openvas_process_alive(mock_process)
        self.assertTrue(ret)

    @patch('psutil.Popen')
    def test_openvas_is_alive_still(self, mock_process):
        w = DummyDaemon()

        mock_process.is_running.return_value = False
        ret = w.is_openvas_process_alive(mock_process)
        self.assertFalse(ret)

    def configure_exec_scan(self, daemon, kbdb):
        daemon.scan_collection.get_options = MagicMock(return_value={})
        daemon.main_db.check_consistency.return_value = (None, 0)
        daemon.main_db.get_new_kb_database.return_value = kbdb
        daemon.main_db.reset_mock()
        daemon.notus = MagicMock()
        daemon.get_scan_status = MagicMock(return_value=None)
        daemon.add_scan_error = MagicMock()
        kbdb.scan_is_stopped.return_value = False

    @patch('ospd_openvas.daemon.PreferenceHandler')
    @patch('ospd_openvas.daemon.Openvas.start_scan')
    def test_exec_scan_does_not_launch_after_credential_preparation_failure(
        self, mock_start_scan, mock_preference_handler
    ):
        daemon = DummyDaemon()
        kbdb = MagicMock()
        self.configure_exec_scan(daemon, kbdb)
        preferences = mock_preference_handler.return_value
        preferences.prepare_ports_for_openvas.return_value = True
        preferences.prepare_credentials_for_openvas.return_value = False
        preferences.get_error_messages.return_value = []
        preferences.prepare_plugins_for_openvas.return_value = True

        daemon.exec_scan('scan-1')

        mock_start_scan.assert_not_called()
        daemon.add_scan_error.assert_called_once_with(
            'scan-1',
            name='',
            host='',
            value='Credential preparation failed. Scan was not launched.',
        )
        daemon.main_db.release_database.assert_called_once_with(kbdb)

    @patch('ospd_openvas.daemon.PreferenceHandler')
    @patch('ospd_openvas.daemon.Openvas.start_scan')
    def test_exec_scan_does_not_launch_after_malformed_credential(
        self, mock_start_scan, mock_preference_handler
    ):
        daemon = DummyDaemon()
        kbdb = MagicMock()
        self.configure_exec_scan(daemon, kbdb)
        preferences = mock_preference_handler.return_value
        preferences.prepare_ports_for_openvas.return_value = True
        preferences.prepare_credentials_for_openvas.return_value = True
        preferences.get_error_messages.return_value = ['Missing service type.']
        preferences.prepare_plugins_for_openvas.return_value = True

        daemon.exec_scan('scan-1')

        mock_start_scan.assert_not_called()
        daemon.add_scan_error.assert_called_once_with(
            'scan-1',
            name='',
            host='',
            value='Malformed credential. Missing service type.',
        )
        daemon.main_db.release_database.assert_called_once_with(kbdb)

    @patch('ospd_openvas.daemon.PreferenceHandler')
    @patch('ospd_openvas.daemon.Openvas.start_scan')
    def test_exec_scan_records_zero_exit_during_startup(
        self, mock_start_scan, mock_preference_handler
    ):
        daemon = DummyDaemon()
        kbdb = MagicMock()
        self.configure_exec_scan(daemon, kbdb)
        preferences = mock_preference_handler.return_value
        preferences.prepare_ports_for_openvas.return_value = True
        preferences.prepare_credentials_for_openvas.return_value = True
        preferences.get_error_messages.return_value = []
        preferences.prepare_plugins_for_openvas.return_value = True
        process = MagicMock(pid=42)
        process.poll.return_value = 0
        mock_start_scan.return_value = process
        kbdb.get_status.return_value = 'new'
        kbdb.get_scan_process_id.return_value = '42'
        daemon.stop_scan_cleanup = MagicMock()

        daemon.exec_scan('scan-1')

        daemon.stop_scan_cleanup.assert_called_once_with(
            kbdb, 'scan-1', '42', True
        )
        daemon.add_scan_error.assert_called_once_with(
            'scan-1',
            name='',
            host='',
            value=(
                'OpenVAS scanner exited before reporting startup readiness '
                '(exit code 0).'
            ),
        )
        daemon.main_db.release_database.assert_called_once_with(kbdb)

    @patch('ospd_openvas.daemon.OPENVAS_STARTUP_TIMEOUT_SECONDS', 0)
    @patch('ospd_openvas.daemon.PreferenceHandler')
    @patch('ospd_openvas.daemon.Openvas.start_scan')
    def test_exec_scan_records_startup_timeout(
        self, mock_start_scan, mock_preference_handler
    ):
        daemon = DummyDaemon()
        kbdb = MagicMock()
        self.configure_exec_scan(daemon, kbdb)
        preferences = mock_preference_handler.return_value
        preferences.prepare_ports_for_openvas.return_value = True
        preferences.prepare_credentials_for_openvas.return_value = True
        preferences.get_error_messages.return_value = []
        preferences.prepare_plugins_for_openvas.return_value = True
        process = MagicMock(pid=42)
        process.poll.return_value = None
        mock_start_scan.return_value = process
        kbdb.get_status.return_value = 'new'
        kbdb.get_scan_process_id.return_value = '42'
        daemon.stop_scan_cleanup = MagicMock()

        daemon.exec_scan('scan-1')

        daemon.stop_scan_cleanup.assert_called_once_with(
            kbdb, 'scan-1', '42', False
        )
        daemon.add_scan_error.assert_called_once_with(
            'scan-1',
            name='',
            host='',
            value=(
                'OpenVAS scanner did not report startup readiness within '
                '0 seconds.'
            ),
        )
        daemon.main_db.release_database.assert_called_once_with(kbdb)

    @patch('ospd_openvas.daemon.OSPDaemon.set_scan_progress_batch')
    @patch('ospd_openvas.daemon.OSPDaemon.sort_host_finished')
    @patch('ospd_openvas.db.KbDB')
    def test_report_openvas_scan_status(
        self, mock_db, mock_sort_host_finished, mock_set_scan_progress_batch
    ):
        w = DummyDaemon()

        mock_set_scan_progress_batch.return_value = None
        mock_sort_host_finished.return_value = None
        mock_db.get_scan_status.return_value = [
            '192.168.0.1/15/1000',
            '192.168.0.2/15/0',
            '192.168.0.3/15/-1',
            '192.168.0.4/1500/1500',
        ]

        target_element = w.create_xml_target()
        targets = OspRequest.process_target_element(target_element)

        w.create_scan('123-456', targets, None, [])
        w.report_openvas_scan_status(mock_db, '123-456')

        mock_set_scan_progress_batch.assert_called_with(
            '123-456',
            host_progress={
                '192.168.0.1': 1,
                '192.168.0.3': -1,
                '192.168.0.4': 100,
            },
        )

        mock_sort_host_finished.assert_called_with(
            '123-456', ['192.168.0.3', '192.168.0.4']
        )

    @patch('ospd_openvas.daemon.logger.warning')
    @patch('ospd_openvas.daemon.OSPDaemon.set_scan_progress_batch')
    @patch('ospd_openvas.daemon.OSPDaemon.sort_host_finished')
    @patch('ospd_openvas.db.KbDB')
    def test_report_openvas_scan_status_quarantines_invalid_rows(
        self,
        mock_db,
        mock_sort_host_finished,
        mock_set_scan_progress_batch,
        mock_warning,
    ):
        w = DummyDaemon()
        hostile_row = 'HOSTILE-PROGRESS-PAYLOAD'
        mock_db.get_scan_status.return_value = [
            hostile_row,
            b'not-a-text-progress-row',
            '192.168.0.1/NaN/1',
            '192.168.0.2/Infinity/1',
            '192.168.0.3/2/1',
            '192.168.0.4/-1/1',
            '192.168.0.4/-1/-1',
            'x' * (w.MAX_REDIS_PROGRESS_ROW_LENGTH + 1),
            '192.168.0.5/1/1',
            '192.168.0.6/15/-1',
        ]

        w.report_openvas_scan_status(mock_db, '123-456')

        mock_set_scan_progress_batch.assert_called_once_with(
            '123-456',
            host_progress={
                '192.168.0.5': 100,
                '192.168.0.6': -1,
            },
        )
        mock_sort_host_finished.assert_called_once_with(
            '123-456', ['192.168.0.5', '192.168.0.6']
        )
        self.assertEqual(mock_warning.call_count, 8)
        self.assertNotIn(hostile_row, str(mock_warning.call_args_list))


class TestFilters(TestCase):
    def test_format_vt_modification_time(self):
        ovformat = OpenVasVtsFilter(None, None)
        td = '1517443741'
        formatted = ovformat.format_vt_modification_time(td)
        self.assertEqual(formatted, "20180201000901")

    def test_get_filtered_vts_false(self):
        w = DummyDaemon()
        vts_collection = ['1234', '1.3.6.1.4.1.25623.1.0.100061']

        ovfilter = OpenVasVtsFilter(w.nvti, None)
        res = ovfilter.get_filtered_vts_list(
            vts_collection, "modification_time<10"
        )
        self.assertNotIn('1.3.6.1.4.1.25623.1.0.100061', res)

    def test_get_filtered_vts_true(self):
        w = DummyDaemon()
        vts_collection = ['1234', '1.3.6.1.4.1.25623.1.0.100061']

        ovfilter = OpenVasVtsFilter(w.nvti, None)
        res = ovfilter.get_filtered_vts_list(
            vts_collection, "modification_time>10"
        )
        self.assertIn('1.3.6.1.4.1.25623.1.0.100061', res)
