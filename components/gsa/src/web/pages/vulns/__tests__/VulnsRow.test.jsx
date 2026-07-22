/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import React from 'react';
import {describe, expect, test, vi} from '@gsa/testing';
import Vulnerability from 'gmp/models/vulnerability';
import {createSession} from 'gmp/testing';
import Row from 'web/pages/vulns/Row';
import {rendererWithTableBody, screen, fireEvent} from 'web/testing';

const createGmp = () => ({
  settings: {},
  session: createSession(),
});
const {render} = rendererWithTableBody({gmp: createGmp()});

describe('Vulns row tests', () => {
  test('clicking the vulnerability name toggles row details', () => {
    const entity = Vulnerability.fromElement({
      _id: '1.3.6.1.4.1.25623.1.0.900001',
      name: 'Example vulnerability',
      results: {count: 3},
      hosts: {count: 2},
      qod: 80,
      severity: 7.5,
    });
    const onToggleDetailsClick = vi.fn();

    render(
      <Row entity={entity} onToggleDetailsClick={onToggleDetailsClick} />,
    );

    fireEvent.click(screen.getByText('Example vulnerability'));

    expect(onToggleDetailsClick).toHaveBeenCalledWith(
      undefined,
      '1.3.6.1.4.1.25623.1.0.900001',
    );
  });
});
