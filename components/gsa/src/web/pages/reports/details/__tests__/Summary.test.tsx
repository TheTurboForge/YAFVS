/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {describe, test, expect} from '@gsa/testing';
import {screen, rendererWith} from 'web/testing';
import Filter from 'gmp/models/filter';
import {createSession} from 'gmp/testing';
import {getMockReport} from 'web/pages/reports/__fixtures__/MockReport';
import Summary from 'web/pages/reports/details/Summary';

const filter = Filter.fromString(
  'apply_overrides=0 levels=hml rows=2 min_qod=70 first=1 sort-reverse=severity',
);

const createGmp = () => ({
  session: createSession({timezone: 'CET'}),
});

describe('Report Summary tests', () => {
  test('should render Report Summary', () => {
    const {report} = getMockReport();

    const {render} = rendererWith({
      gmp: createGmp(),
      capabilities: true,
      router: true,
    });

    const {element} = render(
      <Summary
        filter={filter}
        isUpdating={false}
        report={report}
        reportId={report.id as string}
      />,
    );

    const tableData = element.querySelectorAll('td');
    const links = element.querySelectorAll('a');
    const progressbar = screen.queryAllByTestId('progressbar-box');

    expect(tableData[0]).toHaveTextContent('Task Name');
    expect(links[0]).toHaveAttribute('href', '/task/314');
    expect(tableData[1]).toHaveTextContent('foo');

    expect(tableData[2]).toHaveTextContent('Comment');
    expect(tableData[3]).toHaveTextContent('bar');

    expect(tableData[4]).toHaveTextContent('Scan Time');
    expect(tableData[5]).toHaveTextContent(
      'Mon, Jun 3, 2019 1:00 PM Central European Summer Time - Mon, Jun 3, 2019 1:31 PM Central European Summer Time',
    );

    expect(tableData[6]).toHaveTextContent('Scan Duration');
    expect(tableData[7]).toHaveTextContent('0:31 h');

    expect(tableData[8]).toHaveTextContent('Scan Status');
    expect(progressbar[0]).toHaveTextContent('Done');

    expect(tableData[10]).toHaveTextContent('Hosts scanned');
    expect(tableData[11]).toHaveTextContent('2');

    expect(tableData[12]).toHaveTextContent('Results');
    expect(tableData[13]).toHaveTextContent('3');

    expect(tableData[14]).toHaveTextContent('Vulnerabilities');
    expect(tableData[15]).toHaveTextContent('0');

    expect(tableData[16]).toHaveTextContent('CVEs');
    expect(tableData[17]).toHaveTextContent('3');

    expect(tableData[18]).toHaveTextContent('Filter');
    expect(tableData[19]).toHaveTextContent(
      'apply_overrides=0 levels=hml min_qod=70',
    );

    expect(tableData[20]).toHaveTextContent('Timezone');
    expect(tableData[21]).toHaveTextContent('UTC (UTC)');
  });

  // TODO: should render report error
});
