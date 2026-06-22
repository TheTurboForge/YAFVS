/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {describe, test, expect} from '@gsa/testing';
import {
  createAggregatesResponse,
  createEntitiesResponse,
  createHttp,
} from 'gmp/commands/testing';
import {VulnerabilitiesCommand} from 'gmp/commands/vulns';

describe('VulnerabilitiesCommand tests', () => {
  test('should parse get_vulns response', async () => {
    const response = createEntitiesResponse(
      'vuln',
      [{id: 'v1'}, {id: 'v2'}],
      {
        getName: 'get_vulns',
        responseName: 'get_vulns_response',
        pluralName: 'vulns',
        countName: 'vuln_count',
      },
    );
    const fakeHttp = createHttp(response);
    const cmd = new VulnerabilitiesCommand(fakeHttp);

    const result = await cmd.get();

    expect(result.data).toHaveLength(2);
    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {cmd: 'get_vulns'},
    });
  });

  test('should request severity aggregates for vulnerabilities', async () => {
    const response = createAggregatesResponse();
    const fakeHttp = createHttp(response);
    const cmd = new VulnerabilitiesCommand(fakeHttp);

    await cmd.getSeverityAggregates({filter: 'first=1'});

    expect(fakeHttp.request).toHaveBeenCalledWith('get', {
      args: {
        aggregate_type: 'vuln',
        cmd: 'get_aggregate',
        filter: 'first=1',
        group_column: 'severity',
      },
    });
  });
});
