/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import {rendererWith, fireEvent, screen, wait} from 'web/testing';
import DfnCertAdv from 'gmp/models/dfn-cert';
import {createSession} from 'gmp/testing';
import {currentSettingsDefaultResponse} from 'web/pages/__fixtures__/current-settings';
import DetailsPage from 'web/pages/dfncert/DetailsPage';
import {entityLoadingActions} from 'web/store/entities/dfncerts';

const dfnCert = DfnCertAdv.fromElement({
  _id: 'DFN-CERT-2026-001',
  name: 'DFN-CERT-2026-001',
  creation_time: '2026-02-10T09:00:00Z',
  modification_time: '2026-02-10T10:00:00Z',
  dfn_cert_adv: {
    cve_refs: 1,
    severity: 9.1,
    title: 'Example DFN-CERT advisory',
    raw_data: {
      entry: {
        cve: ['CVE-2026-0002'],
        summary: {
          __text: 'Example summary',
        },
      },
    },
  },
});

const createGmp = ({
  buildUrl,
  exportDfnCert = testing.fn().mockResolvedValue({data: '<dfn_cert_adv/>'}),
  getDfnCert = testing.fn().mockResolvedValue({data: dfnCert}),
  currentSettings = testing
    .fn()
    .mockResolvedValue(currentSettingsDefaultResponse),
} = {}) => ({
  buildUrl,
  dfncert: {
    export: exportDfnCert,
    get: getDfnCert,
  },
  settings: {
    manualUrl: 'test/',
    reloadInterval: -1,
  },
  session: {
    ...createSession({timezone: 'UTC'}),
    token: 'test-token',
    jwt: 'jwt-token',
  },
  user: {
    currentSettings,
  },
});

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('DfnCert DetailsPage tests', () => {
  test('should use native metadata export for downloads', async () => {
    const nativePayload = {
      id: 'DFN-CERT-2026-001',
      name: 'DFN-CERT-2026-001',
      title: 'Example DFN-CERT advisory',
    };
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue(nativePayload),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const exportDfnCert = testing.fn().mockResolvedValue({data: '<dfn/>'});
    const buildUrl = testing.fn(
      (path, _params) => `https://yafvs.example/${path}`,
    );
    const gmp = createGmp({buildUrl, exportDfnCert});
    const {render, store} = rendererWith({
      capabilities: true,
      gmp,
      router: true,
      store: true,
    });

    store.dispatch(entityLoadingActions.success(dfnCert.id, dfnCert));
    render(<DetailsPage id={dfnCert.id} />);
    await wait();

    fetchMock.mockClear();
    fireEvent.click(screen.getByTitle('Export DFN-CERT Advisory'));
    await expect.poll(() => fetchMock.mock.calls.length).toBe(1);

    expect(exportDfnCert).not.toHaveBeenCalled();
    expect(buildUrl).toHaveBeenCalledWith(
      'api/v1/dfn-cert-advisories/DFN-CERT-2026-001/export',
      {token: 'test-token'},
    );
    expect(fetchMock).toHaveBeenCalledExactlyOnceWith(
      'https://yafvs.example/api/v1/dfn-cert-advisories/DFN-CERT-2026-001/export',
      expect.objectContaining({credentials: 'include'}),
    );
  });
});
