/* SPDX-FileCopyrightText: 2026 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import React from 'react';
import {describe, expect, test, testing} from '@gsa/testing';
import {render, screen} from 'web/testing';
import Alert, {METHOD_TYPE_SNMP} from 'gmp/models/alert';
import AlertDialog from 'web/pages/alerts/Dialog';

describe('AlertDialog', () => {
  test('renders an edit definition supplied by the native definition GET', () => {
    render(
      <AlertDialog
        active={1}
        alert={Alert.fromElement({_id: 'alert-id'})}
        comment="Native definition"
        credentials={[]}
        event_data_status="Done"
        filter_id={0}
        method={METHOD_TYPE_SNMP}
        method_data_snmp_agent="localhost"
        method_data_snmp_community=""
        method_data_snmp_community_configured="1"
        method_data_snmp_message="$e"
        name="Configured SNMP alert"
        report_formats={[]}
        tasks={[]}
        onClose={testing.fn()}
        onEmailCredentialChange={testing.fn()}
        onNewEmailCredentialClick={testing.fn()}
        onNewScpCredentialClick={testing.fn()}
        onNewSmbCredentialClick={testing.fn()}
        onSave={testing.fn()}
        onScpCredentialChange={testing.fn()}
        onSmbCredentialChange={testing.fn()}
      />,
    );

    expect(screen.getByName('name')).toHaveValue('Configured SNMP alert');
  });
});
