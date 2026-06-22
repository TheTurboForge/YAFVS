/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import React from 'react';
import {describe, expect, test} from '@gsa/testing';
import CollectionCounts from 'gmp/collection/collection-counts';
import Filter from 'gmp/models/filter';
import Vulnerability from 'gmp/models/vulnerability';
import {createSession} from 'gmp/testing';
import VulnsTable from 'web/pages/vulns/Table';
import {rendererWith, screen, fireEvent} from 'web/testing';

const vulnerability = Vulnerability.fromElement({
  _id: '1.3.6.1.4.1.25623.1.0.900001',
  name: 'Example vulnerability',
  family: 'General',
  results: {
    count: 3,
    oldest: '2026-06-01T10:00:00Z',
    newest: '2026-06-02T11:00:00Z',
  },
  hosts: {count: 2},
  qod: 80,
  severity: 7.5,
  summary: 'Native vulnerability summary',
  detection: 'Native detection method',
  affected: 'Native affected package',
  impact: 'Native impact',
  solution: {type: 'VendorFix', description: 'Install the vendor fix.'},
  cves: ['CVE-2026-0001'],
  epss: {
    maxEpss: {
      score: 0.91,
      percentile: 0.98,
      cve: {id: 'CVE-2026-0001', severity: 7.5},
    },
  },
});

const counts = new CollectionCounts({
  first: 1,
  all: 1,
  filtered: 1,
  length: 1,
  rows: 25,
});

const filter = Filter.fromString('first=1 rows=25');

const createGmp = () => ({
  settings: {enableEPSS: true},
  session: createSession(),
});

describe('Vulns table tests', () => {
  test('renders inline vulnerability details from the row toggle', () => {
    const {render} = rendererWith({
      capabilities: true,
      gmp: createGmp(),
      router: true,
    });
    const {element} = render(
      <VulnsTable
        entities={[vulnerability]}
        entitiesCounts={counts}
        filter={filter}
      />,
    );

    expect(element).not.toHaveTextContent('OID');

    fireEvent.click(screen.getByText('Example vulnerability'));

    expect(element).toHaveTextContent('OID');
    expect(element).toHaveTextContent('1.3.6.1.4.1.25623.1.0.900001');
    expect(element).toHaveTextContent('General');
    expect(element).toHaveTextContent('Native vulnerability summary');
    expect(element).toHaveTextContent('Native detection method');
    expect(element).toHaveTextContent('Native affected package');
    expect(element).toHaveTextContent('Native impact');
    expect(element).toHaveTextContent('Solution Type');
    expect(element).toHaveTextContent('Vendorfix');
    expect(element).toHaveTextContent('CVE-2026-0001');
    expect(element).toHaveTextContent('91.000%');
    expect(element).toHaveTextContent('Results');
    expect(screen.getByTitle('Open all details')).toBeInTheDocument();
  });
});
