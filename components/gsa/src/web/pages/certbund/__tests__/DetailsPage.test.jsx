/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import {rendererWith, fireEvent, screen, wait} from 'web/testing';
import CertBundAdv from 'gmp/models/cert-bund';
import {createSession} from 'gmp/testing';
import {currentSettingsDefaultResponse} from 'web/pages/__fixtures__/current-settings';
import DetailsPage from 'web/pages/certbund/DetailsPage';
import {entityLoadingActions} from 'web/store/entities/certbund';

const certBund = CertBundAdv.fromElement({
  _id: 'CERT-Bund-2026-001',
  name: 'CERT-Bund-2026-001',
  creation_time: '2026-01-15T10:00:00Z',
  modification_time: '2026-01-15T11:00:00Z',
  cert_bund_adv: {
    cve_refs: 1,
    severity: 8.1,
    title: 'Example CERT-Bund advisory',
    summary: 'Example summary',
    raw_data: {
      Advisory: {
        CVEList: {
          CVE: ['CVE-2026-0001'],
        },
      },
    },
  },
});

const createGmp = ({
  buildUrl,
  exportCertBund = testing.fn().mockResolvedValue({data: '<cert_bund_adv/>'}),
  getCertBund = testing.fn().mockResolvedValue({data: certBund}),
  currentSettings = testing
    .fn()
    .mockResolvedValue(currentSettingsDefaultResponse),
} = {}) => ({
  buildUrl,
  certbund: {
    export: exportCertBund,
    get: getCertBund,
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

describe('CertBund DetailsPage tests', () => {
  test('should use native metadata export for downloads', async () => {
    const nativePayload = {
      id: 'CERT-Bund-2026-001',
      name: 'CERT-Bund-2026-001',
      title: 'Example CERT-Bund advisory',
    };
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue(nativePayload),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const exportCertBund = testing.fn().mockResolvedValue({data: '<cert/>'});
    const buildUrl = testing.fn(
      (path, _params) => `https://yafvs.example/${path}`,
    );
    const gmp = createGmp({buildUrl, exportCertBund});
    const {render, store} = rendererWith({
      capabilities: true,
      gmp,
      router: true,
      store: true,
    });

    store.dispatch(entityLoadingActions.success(certBund.id, certBund));
    render(<DetailsPage id={certBund.id} />);
    await wait();

    fetchMock.mockClear();
    fireEvent.click(screen.getByTitle('Export CERT-Bund Advisory'));
    await expect.poll(() => fetchMock.mock.calls.length).toBe(1);

    expect(exportCertBund).not.toHaveBeenCalled();
    expect(buildUrl).toHaveBeenCalledWith(
      'api/v1/cert-bund-advisories/CERT-Bund-2026-001/export',
      {token: 'test-token'},
    );
    expect(fetchMock).toHaveBeenCalledExactlyOnceWith(
      'https://yafvs.example/api/v1/cert-bund-advisories/CERT-Bund-2026-001/export',
      expect.objectContaining({credentials: 'include'}),
    );
  });
});
