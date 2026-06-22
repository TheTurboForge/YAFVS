/* SPDX-FileCopyrightText: 2026 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {describe, expect, test, testing} from '@gsa/testing';
import {rendererWith, screen, within} from 'web/testing';
import Filter from 'gmp/models/filter';
import {createSession} from 'gmp/testing';
import {SEVERITY_RATING_CVSS_3} from 'gmp/utils/severity';
import {getMockReport} from 'web/pages/reports/__fixtures__/MockReport';
import HostsTab from 'web/pages/reports/details/HostsTab';

const getRow = (link: HTMLElement): HTMLTableRowElement => {
  const row = link.closest('tr');
  if (!row) throw new Error('Expected parent row element');
  return row;
};

const getImgSrc = (row: HTMLTableRowElement): string => {
  const img = row.querySelector('img');
  if (!img) throw new Error('Expected img element');
  return img.getAttribute('src') ?? '';
};

const filter = Filter.fromString(
  'apply_overrides=0 levels=hml rows=2 min_qod=70 first=1 sort-reverse=severity',
);

const createGmp = ({severityRating = SEVERITY_RATING_CVSS_3} = {}) => ({
  settings: {
    severityRating,
  },
  session: createSession({timezone: 'CET'}),
});

describe('Report Hosts Tab tests', () => {
  test('should render Report Hosts Tab', () => {
    const {hosts} = getMockReport();

    const onSortChange = testing.fn();

    const {render} = rendererWith({
      gmp: createGmp(),
      capabilities: true,
      router: true,
    });

    render(
      <HostsTab
        counts={hosts?.counts}
        filter={filter}
        hosts={hosts?.entities}
        isUpdating={false}
        sortField={'severity'}
        sortReverse={true}
        onSortChange={sortField => onSortChange('hosts', sortField)}
      />,
    );

    // Headings
    screen.getByRole('columnheader', {name: /IP Address/i});
    screen.getByRole('columnheader', {name: /Hostname/i});
    screen.getByRole('columnheader', {name: /^OS/i});
    screen.getByRole('columnheader', {name: /Ports/i});
    screen.getByRole('columnheader', {name: /Apps/i});
    screen.getByRole('columnheader', {name: /Distance/i});
    screen.getByRole('columnheader', {name: /Auth/i});
    screen.getByRole('columnheader', {name: /Start/i});
    screen.getByRole('columnheader', {name: /End/i});
    screen.getByRole('columnheader', {name: /Critical/i});
    screen.getByRole('columnheader', {name: /High/i});
    screen.getByRole('columnheader', {name: /Medium/i});
    screen.getByRole('columnheader', {name: /Low/i});
    screen.getByRole('columnheader', {name: /Log/i});
    screen.getByRole('columnheader', {name: /False Pos/i});
    screen.getByRole('columnheader', {name: /Total/i});
    screen.getByRole('columnheader', {name: /Severity/i});

    // Row 1 (host with asset id)
    const host1Link = screen.getByRole('link', {name: '123.456.78.910'});
    expect(host1Link).toHaveAttribute('href', '/host/123');

    const row1 = getRow(host1Link);
    expect(row1).toHaveTextContent('foo.bar');
    expect(getImgSrc(row1)).toContain('/img/os_unknown.svg');
    expect(row1).toHaveTextContent('1032');
    expect(row1).toHaveTextContent(
      'Mon, Jun 3, 2019 1:00 PM Central European Summer Time',
    );
    expect(row1).toHaveTextContent(
      'Mon, Jun 3, 2019 1:15 PM Central European Summer Time',
    );
    expect(row1).toHaveTextContent('143050150');

    const bar1 = within(row1).getByTestId('progressbar-box');
    expect(bar1).toHaveAttribute('title', 'Critical');
    expect(bar1).toHaveTextContent('10.0 (Critical)');

    // Row 2 (host without asset id)
    const host2Link = screen.getByRole('link', {name: '109.876.54.321'});
    expect(host2Link).toHaveAttribute(
      'href',
      '/hosts?filter=name%3D109.876.54.321',
    );

    const row2 = getRow(host2Link);
    expect(row2).toHaveTextContent('lorem.ipsum');
    expect(getImgSrc(row2)).toContain('/img/os_unknown.svg');
    expect(row2).toHaveTextContent('1521');
    expect(row2).toHaveTextContent(
      'Mon, Jun 3, 2019 1:15 PM Central European Summer Time',
    );
    expect(row2).toHaveTextContent(
      'Mon, Jun 3, 2019 1:31 PM Central European Summer Time',
    );
    expect(row2).toHaveTextContent('53005040');

    const bar2 = within(row2).getByTestId('progressbar-box');
    expect(bar2).toHaveAttribute('title', 'Medium');
    expect(bar2).toHaveTextContent('5.0 (Medium)');

    // Filter
    screen.getByText(
      '(Applied filter: apply_overrides=0 levels=hml rows=2 min_qod=70 first=1 sort-reverse=severity)',
    );
  });
});
