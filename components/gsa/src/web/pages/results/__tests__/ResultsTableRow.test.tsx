/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * Modified by TurboVAS contributors, 2026.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {describe, test, expect} from '@gsa/testing';
import {rendererWithTableBody, screen} from 'web/testing';
import Result from 'gmp/models/result';
import {createSession} from 'gmp/testing';
import ResultsTableRow from 'web/pages/results/ResultsTableRow';

const createGmp = () => ({
  settings: {
    enableEPSS: true,
  },
  session: createSession(),
});
const {render} = rendererWithTableBody({gmp: createGmp()});

describe('ResultsTableRow tests', () => {
  test('should render EPSS fields 1 columns', () => {
    const entity = Result.fromElement({
      _id: '101',
      name: 'Result 1',
      host: {__text: '123.456.78.910', hostname: 'foo'},
      port: '80/tcp',
      severity: 10.0,
      qod: {value: 80},
      nvt: {
        type: 'nvt',
        epss: {
          max_severity: {
            score: 0.8765,
            percentile: 80.123,
            cve: {
              _id: 'CVE-2019-1234',
              severity: 5.0,
            },
          },
          max_epss: {
            score: 0.9876,
            percentile: 90.0,
            cve: {
              _id: 'CVE-2020-5678',
              severity: 2.0,
            },
          },
        },
      },
    });

    render(<ResultsTableRow entity={entity} />);
    const row = screen.getByTestId('result-table-row');
    expect(row).toHaveTextContent('98.760%');
    expect(row).toHaveTextContent('90th');
  });

  test('should render EPSS fields 2 columns', () => {
    const entity = Result.fromElement({
      _id: '101',
      name: 'Result 1',
      host: {__text: '123.456.78.910', hostname: 'foo'},
      port: '80/tcp',
      severity: 10.0,
      qod: {value: 80},
      nvt: {
        type: 'cve',
        epss: {
          max_severity: {
            score: 0.8765,
            percentile: 83.123,
            cve: {
              _id: 'CVE-2019-1234',
              severity: 5.0,
            },
          },
          max_epss: {
            score: 0.87555,
            percentile: 89.0,
            cve: {
              _id: 'CVE-2020-5678',
              severity: 2.0,
            },
          },
        },
      },
    });

    render(<ResultsTableRow entity={entity} />);
    const row = screen.getByTestId('result-table-row');
    expect(row).toHaveTextContent('87.555%');
    expect(row).toHaveTextContent('89th');
  });

  test('should render Delta V2 with changed severity, qod and hostname', () => {
    const entity = Result.fromElement({
      _id: '101',
      name: 'Result 1',
      host: {__text: '123.456.78.910', hostname: 'foo'},
      port: '80/tcp',
      severity: 10.0,
      qod: {value: 80},
      delta: {
        __text: 'changed',
        result: {
          _id: '102',
          host: {hostname: 'bar'},
          severity: 2.6,
          qod: {value: 70},
        },
      },
    });

    render(<ResultsTableRow entity={entity} />);

    expect(screen.getAllByTestId('delta-difference-icon')[0]).toHaveAttribute(
      'title',
      'Severity is changed from 2.6.',
    );
    expect(screen.getAllByTestId('delta-difference-icon')[1]).toHaveAttribute(
      'title',
      'QoD is changed from 70.',
    );
    expect(screen.getAllByTestId('delta-difference-icon')[2]).toHaveAttribute(
      'title',
      'Hostname is changed from bar.',
    );
  });

  test('should not render Delta Difference icon for Delta reports V2 with same severity, qod and hostname', () => {
    const entity = Result.fromElement({
      _id: '101',
      name: 'Result 1',
      host: {__text: '123.456.78.910', hostname: 'foo'},
      port: '80/tcp',
      severity: 10.0,
      qod: {value: 80},
      delta: {
        __text: 'same',
        result: {
          _id: '102',
          host: {hostname: 'foo'},
          severity: 10.0,
          qod: {value: 80},
        },
      },
    });

    render(<ResultsTableRow entity={entity} />);

    const icons = screen.queryAllByTestId('svg-icon');
    expect(icons.length).toBe(0);
  });


});
