/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import {rendererWith, fireEvent, screen, wait, within} from 'web/testing';
import CollectionCounts from 'gmp/collection/collection-counts';
import Filter from 'gmp/models/filter';
import NVT from 'gmp/models/nvt';
import Override from 'gmp/models/override';
import {createSession} from 'gmp/testing';
import {currentSettingsDefaultResponse} from 'web/pages/__fixtures__/current-settings';
import DetailsPage from 'web/pages/nvts/DetailsPage';
import {entityLoadingActions} from 'web/store/entities/nvts';

const reloadInterval = -1;
const manualUrl = 'test/';

const nvt = NVT.fromElement({
  _id: '12345',
  owner: {
    name: '',
  },
  name: '12345',
  comment: '',
  creation_time: '2019-06-24T11:55:30Z',
  modification_time: '2019-06-24T10:12:27Z',
  timezone: 'UTC',
  writable: 0,
  in_use: 0,
  permissions: '',
  update_time: '2020-10-30T11:44:00.000+0000',
  nvt: {
    _oid: '12345',
    name: 'foo',
    family: 'A Family',
    cvss_base: 4.9,
    qod: {
      value: 80,
      type: 'remote_banner',
    },
    tags: 'cvss_base_vector=AV:N/AC:M/Au:S/C:P/I:N/A:P|summary=This is a CVSS description|solution_type=VendorFix|insight=An Insight|impact=An Impact|vuldetect=A VulDetect|affected=It is affected',
    solution: {
      _type: 'VendorFix',
      __text: 'This is a solution description',
    },
    epss: {
      max_severity: {
        score: 0.8765,
        percentile: 90.0,
        cve: {
          _id: 'CVE-2020-1234',
          severity: 10.0,
        },
      },
      max_epss: {
        score: 0.9876,
        percentile: 80.0,
        cve: {
          _id: 'CVE-2020-5678',
        },
      },
    },
    timeout: '',
    refs: {
      ref: [
        {_type: 'cve', _id: 'CVE-2020-1234'},
        {_type: 'cve', _id: 'CVE-2020-5678'},
      ],
    },
  },
});

const nativeNvtDetail = {
  id: '12345',
  oid: '12345',
  name: 'foo',
  comment: '',
  family: 'A Family',
  category: '3',
  discovery: 0,
  severity: 4.9,
  qod: 80,
  qod_type: 'remote_banner',
  solution_type: 'VendorFix',
  solution: 'This is a solution description',
  summary: 'This is a CVSS description',
  insight: 'An Insight',
  affected: 'It is affected',
  impact: 'An Impact',
  detection: 'A VulDetect',
  tags: 'cvss_base_vector=AV:N/AC:M/Au:S/C:P/I:N/A:P',
  cves: ['CVE-2020-1234', 'CVE-2020-5678'],
  max_epss: {
    score: 0.9876,
    percentile: 80.0,
    cve: 'CVE-2020-5678',
  },
  max_severity: {
    score: 0.8765,
    percentile: 90.0,
    cve: 'CVE-2020-1234',
    severity: 10.0,
  },
  created_at: '2019-06-24T11:55:30Z',
  modified_at: '2019-06-24T10:12:27Z',
  updated_at: '2020-10-30T11:44:00Z',
};

const override1 = Override.fromElement({
  _id: '5221d57f-3e62-4114-8e19-000000000001',
  active: 1,
  creation_time: '2021-01-14T05:35:57Z',
  hosts: '127.0.01.1',
  in_use: 0,
  end_time: '2021-03-13T11:35:20+01:00',
  modification_time: '2021-01-14T06:20:57Z',
  timezone: 'UTC',
  new_severity: -1,
  new_threat: 'False Positive',
  nvt: {
    _oid: '12345',
    name: 'foo',
    type: 'nvt',
  },
  orphan: 0,
  owner: {
    name: 'admin',
  },
  permissions: {
    permission: {
      name: 'everything',
    },
  },
  port: '',
  result: {
    _id: '',
  },
  severity: '',
  task: {
    _id: '',
    name: '',
    trash: 0,
  },
  text: 'test_override_1',
  threat: 'Internal Error',
  writable: 1,
});

const nativeOverrideItems = [
  {
    id: '5221d57f-3e62-4114-8e19-000000000001',
    owner: {name: 'admin'},
    nvt: {id: '12345', name: 'foo', type: 'nvt'},
    text: 'test_override_1',
    hosts: '127.0.01.1',
    port: '',
    severity: null,
    new_severity: -1,
    writable: true,
    in_use: false,
    orphan: false,
    active: true,
    end_time: '2021-03-13T11:35:20+01:00',
    task: {id: '', name: '', trash: false},
    result: {id: '', name: ''},
    permissions: ['everything'],
    created_at: '2021-01-14T05:35:57Z',
    modified_at: '2021-01-14T06:20:57Z',
  },
  {
    id: '5221d57f-3e62-4114-8e19-000000000000',
    owner: {name: 'admin'},
    nvt: {id: '12345', name: 'foo', type: 'nvt'},
    text: 'test_override_2',
    hosts: '127.0.01.1',
    port: '',
    severity: null,
    new_severity: 1,
    writable: true,
    in_use: false,
    orphan: false,
    active: true,
    end_time: '2021-02-13T12:35:20+01:00',
    task: {id: '', name: '', trash: false},
    result: {id: '', name: ''},
    permissions: ['everything'],
    created_at: '2020-01-14T06:35:57Z',
    modified_at: '2020-02-14T06:35:57Z',
  },
];

const override2 = Override.fromElement({
  _id: '5221d57f-3e62-4114-8e19-000000000000',
  active: 1,
  creation_time: '2020-01-14T06:35:57Z',
  hosts: '127.0.01.1',
  in_use: 0,
  end_time: '2021-02-13T12:35:20+01:00',
  modification_time: '2020-02-14T06:35:57Z',
  timezone: 'UTC',
  new_severity: 1,
  new_threat: 'Low',
  nvt: {
    _oid: '12345',
    name: 'foo',
    type: 'nvt',
  },
  orphan: 0,
  owner: {
    name: 'admin',
  },
  permissions: {
    permission: {
      name: 'everything',
    },
  },
  port: '',
  result: {
    _id: '',
  },
  severity: '',
  task: {
    _id: '',
    name: '',
    trash: 0,
  },
  text: 'test_override_2',
  threat: 'Internal Error',
  writable: 1,
});

const createGmp = ({
  buildUrl,
  exportNvt = testing.fn().mockResolvedValue({data: '<nvt oid="12345"/>'}),
  getNvt = testing.fn().mockResolvedValue({
    data: nvt,
  }),
  getOverrides = testing.fn().mockResolvedValue({
    data: [override1, override2],
    meta: {
      filter: Filter.fromString(),
      counts: new CollectionCounts(),
    },
  }),
  getEntities = testing.fn().mockResolvedValue({
    data: [],
    meta: {
      filter: Filter.fromString(),
      counts: new CollectionCounts(),
    },
  }),
  currentSettings = testing
    .fn()
    .mockResolvedValue(currentSettingsDefaultResponse),
} = {}) => {
  const resolvedBuildUrl =
    buildUrl ?? testing.fn((path, _params) => `https://turbovas.example/${path}`);
  if (buildUrl === undefined) {
    testing.stubGlobal(
      'fetch',
      testing.fn(url => {
        const path = String(url);
        const payload = path.includes('/api/v1/overrides')
          ? {
              page: {
                page: 1,
                page_size: 10,
                total: nativeOverrideItems.length,
                sort: 'text',
                filter: '',
              },
              items: nativeOverrideItems,
            }
          : nativeNvtDetail;
        return Promise.resolve({
          json: testing.fn().mockResolvedValue(payload),
          ok: true,
          status: 200,
        });
      }),
    );
  }
  return {
    buildUrl: resolvedBuildUrl,
    nvt: {
      export: exportNvt,
      get: getNvt,
    },
    settings: {
      manualUrl,
      reloadInterval,
      enableEPSS: true,
    },
    session: {
      ...createSession({timezone: 'UTC'}),
      token: 'test-token',
      jwt: 'jwt-token',
    },
    user: {
      currentSettings,
    },
    overrides: {
      get: getOverrides,
    },
  };
};

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('Nvt DetailsPage tests', () => {
  test('should render full DetailsPage', async () => {
    const gmp = createGmp();

    const {render, store} = rendererWith({
      capabilities: true,
      gmp,
      router: true,
      store: true,
    });

    store.dispatch(entityLoadingActions.success('12345', nvt));

    render(<DetailsPage id="12345" />);
    await wait();

    expect(
      screen.getByRole('heading', {name: /NVT: foo/i}),
    ).toBeInTheDocument();

    expect(screen.getByTitle('Help: NVTs')).toBeInTheDocument();
    expect(screen.getByTestId('manual-link')).toHaveAttribute(
      'href',
      'test/en/managing-secinfo.html#vulnerability-tests-vt',
    );

    expect(screen.getAllByTitle('NVT List')[0]).toBeInTheDocument();
    expect(screen.getByTestId('list-link-icon')).toHaveAttribute(
      'href',
      '/nvts',
    );

    const entityInfo = within(screen.getByTestId('entity-info'));
    expect(entityInfo.getByRole('row', {name: /ID:/})).toHaveTextContent(
      'ID:12345',
    );
    expect(entityInfo.getByRole('row', {name: /Created:/})).toHaveTextContent(
      'Mon, Jun 24, 2019 11:55 AM Coordinated Universal Time',
    );
    expect(entityInfo.getByRole('row', {name: /Modified:/})).toHaveTextContent(
      'Mon, Jun 24, 2019 10:12 AM Coordinated Universal Time',
    );
    expect(entityInfo.getByRole('row', {name: /Owner:/})).toHaveTextContent(
      'Owner:(Global Object)',
    );

    expect(
      screen.getByRole('tab', {name: /^information/i}),
    ).toBeInTheDocument();
    expect(screen.getByRole('tab', {name: /^user tags/i})).toBeInTheDocument();
    expect(
      screen.getByRole('tab', {name: /^preferences/i}),
    ).toBeInTheDocument();

    expect(
      screen.getByRole('heading', {name: /^summary/i}),
    ).toBeInTheDocument();
    expect(
      screen.getByText('This is a solution description'),
    ).toBeInTheDocument();

    expect(
      screen.getByRole('heading', {name: /^scoring/i}),
    ).toBeInTheDocument();
    expect(
      screen.getByRole('row', {name: /^cvss base 4\.9/i}),
    ).toHaveTextContent('4.9 (Medium)');
    expect(
      screen.getByRole('row', {name: /^cvss base vector/i}),
    ).toHaveTextContent('AV:N/AC:M/Au:S/C:P/I:N/A:P');
    expect(screen.getByRole('row', {name: /^cvss origin/i})).toHaveTextContent(
      'N/A',
    );

    expect(
      screen.getByRole('heading', {name: /^epss \(cve/i}),
    ).toHaveTextContent('EPSS (CVE with highest severity)');
    expect(
      screen.getByRole('row', {name: /^EPSS Score 87/i}),
    ).toHaveTextContent('87.650%');
    expect(
      screen.getByRole('row', {name: /^EPSS Percentile 9/i}),
    ).toHaveTextContent('90th');
    expect(
      screen.getByRole('heading', {name: /^epss \(highest/i}),
    ).toHaveTextContent('EPSS (highest EPSS score)');
    expect(
      screen.getByRole('row', {name: /^EPSS Score 98/i}),
    ).toHaveTextContent('98.760%');
    expect(
      screen.getByRole('row', {name: /^EPSS Percentile 8/i}),
    ).toHaveTextContent('80th');

    expect(
      screen.getByRole('heading', {name: /^insight/i}),
    ).toBeInTheDocument();
    expect(screen.getByText(/^An Insight$/)).toBeInTheDocument();

    expect(
      screen.getByRole('heading', {name: /^detection method/i}),
    ).toBeInTheDocument();
    expect(screen.getByText(/^A VulDetect$/)).toBeInTheDocument();

    expect(
      screen.getByRole('heading', {name: /^affected software\/os/i}),
    ).toBeInTheDocument();
    expect(screen.getByText(/^It is affected$/)).toBeInTheDocument();

    expect(screen.getByRole('heading', {name: /^impact/i})).toBeInTheDocument();
    expect(screen.getByText(/^An Impact$/)).toBeInTheDocument();

    expect(
      screen.getByRole('heading', {name: /^solution/i}),
    ).toBeInTheDocument();

    expect(screen.getByRole('heading', {name: /^family/i})).toBeInTheDocument();
    expect(screen.getByText('A Family')).toBeInTheDocument();

    expect(
      screen.getByRole('heading', {name: /^references/i}),
    ).toBeInTheDocument();
    const nvtReferences = within(screen.getByTestId('nvt-references'));
    expect(nvtReferences.getByText('CVE-2020-1234')).toBeInTheDocument();
    expect(nvtReferences.getByText('CVE-2020-5678')).toBeInTheDocument();

    expect(
      screen.getByRole('heading', {name: /^overrides$/i}),
    ).toBeInTheDocument();

    const overrideBox1 = screen.getByLabelText(
      /^Override from Any to False Positive/,
    );
    expect(overrideBox1).toHaveTextContent('test_override_1');
    expect(overrideBox1).toHaveTextContent('Active until');
    expect(overrideBox1).toHaveTextContent(
      'Sat, Mar 13, 2021 10:35 AM Coordinated Universal Time',
    );
    expect(overrideBox1).toHaveTextContent('Modified');
    expect(overrideBox1).toHaveTextContent(
      'Thu, Jan 14, 2021 6:20 AM Coordinated Universal Time',
    );

    const overrideBox2 = screen.getByLabelText(/^Override from Any to 1: Low/);
    expect(overrideBox2).toHaveTextContent('test_override_2');
    expect(overrideBox2).toHaveTextContent('Active until');
    expect(overrideBox2).toHaveTextContent(
      'Sat, Feb 13, 2021 11:35 AM Coordinated Universal Time',
    );
    expect(overrideBox2).toHaveTextContent('Modified');
    expect(overrideBox2).toHaveTextContent(
      'Fri, Feb 14, 2020 6:35 AM Coordinated Universal Time',
    );
  });

  test('should render preferences tab', () => {
    const gmp = createGmp();
    const {render, store} = rendererWith({
      gmp,
      capabilities: true,
      router: true,
      store: true,
    });

    store.dispatch(entityLoadingActions.success('12345', nvt));

    render(<DetailsPage id="12345" />);

    const preferencesTab = screen.getByRole('tab', {name: /^preferences/i});
    fireEvent.click(preferencesTab);

    expect(
      screen.getByRole('columnheader', {name: /^name/i}),
    ).toBeInTheDocument();
    expect(
      screen.getByRole('columnheader', {name: /^default value/i}),
    ).toBeInTheDocument();
    expect(
      screen.getByRole('row', {name: /^Timeout default/}),
    ).toBeInTheDocument();
  });

  test('should render user tags tab', () => {
    const gmp = createGmp();
    const {render, store} = rendererWith({
      capabilities: true,
      gmp,
      router: true,
      store: true,
    });

    store.dispatch(entityLoadingActions.success('12345', nvt));

    const {container} = render(<DetailsPage id="12345" />);

    const userTagsTab = screen.getByRole('tab', {name: /^user tags/i});
    fireEvent.click(userTagsTab);
    expect(container).toHaveTextContent('No user tags available');
  });

  test('should use native metadata export for downloads', async () => {
    const nativePayload = {
      id: '12345',
      oid: '12345',
      name: 'foo',
    };
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue(nativePayload),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const exportNvt = testing.fn().mockResolvedValue({data: '<nvt/>'});
    const buildUrl = testing.fn(
      (path, _params) => `https://turbovas.example/${path}`,
    );
    const gmp = createGmp({buildUrl, exportNvt});
    const {render, store} = rendererWith({
      capabilities: true,
      gmp,
      router: true,
      store: true,
    });

    store.dispatch(entityLoadingActions.success('12345', nvt));
    render(<DetailsPage id="12345" />);
    await wait();

    fetchMock.mockClear();
    fireEvent.click(screen.getByTitle('Export NVT'));
    await expect.poll(() => fetchMock.mock.calls.length).toBe(1);

    expect(exportNvt).not.toHaveBeenCalled();
    expect(buildUrl).toHaveBeenCalledWith('api/v1/nvts/12345/export', {
      token: 'test-token',
    });
    expect(fetchMock).toHaveBeenCalledExactlyOnceWith(
      'https://turbovas.example/api/v1/nvts/12345/export',
      expect.objectContaining({credentials: 'include'}),
    );
  });
});
