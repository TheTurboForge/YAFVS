/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import TlsCertificate from 'gmp/models/tls-certificate';
import {createSession} from 'gmp/testing';
import {currentSettingsDefaultResponse} from 'web/pages/__fixtures__/current-settings';
import TlsCertificateComponent from 'web/pages/tlscertificates/TlsCertificateComponent';
import {rendererWith, wait} from 'web/testing';

const nativePayload = {
  id: 'c8f3d02d-5d1e-4e4f-9e27-7f8dcb8fd801',
  name: 'CN=example.invalid',
  subject_dn: 'CN=example.invalid',
};

const createGmp = ({
  currentSettings = testing
    .fn()
    .mockResolvedValue(currentSettingsDefaultResponse),
  exportTlsCertificate = testing.fn().mockResolvedValue({
    data: '<tls_certificate id="c8f3d02d-5d1e-4e4f-9e27-7f8dcb8fd801"/>',
  }),
  getTlsCertificate = testing.fn().mockResolvedValue({
    data: TlsCertificate.fromElement({_id: nativePayload.id}),
  }),
} = {}) => ({
  buildUrl: testing.fn((path, _params) => `https://yafvs.example/${path}`),
  session: {...createSession(), token: 'test-token', jwt: 'jwt-token'},
  user: {currentSettings},
  tlscertificate: {export: exportTlsCertificate, get: getTlsCertificate},
});

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('TLS Certificate Component tests', () => {
  test('should use native metadata export for XML export action', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue(nativePayload),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp();
    const tlsCertificate = TlsCertificate.fromElement({
      _id: nativePayload.id,
      subject_dn: nativePayload.subject_dn,
    });
    let exportClick;
    const onDownloaded = testing.fn();
    const onDownloadError = testing.fn();
    const {render} = rendererWith({gmp, capabilities: true});

    render(
      <TlsCertificateComponent
        onDownloadError={onDownloadError}
        onDownloaded={onDownloaded}
      >
        {({exportFunc}) => {
          exportClick = exportFunc;
          return <div>Some Content</div>;
        }}
      </TlsCertificateComponent>,
    );

    await wait();
    exportClick(tlsCertificate);
    await wait();

    expect(gmp.tlscertificate.export).not.toHaveBeenCalled();
    expect(gmp.buildUrl).toHaveBeenCalledWith(
      `api/v1/tls-certificates/${nativePayload.id}/export`,
      {token: 'test-token'},
    );
    expect(fetchMock).toHaveBeenCalledExactlyOnceWith(
      `https://yafvs.example/api/v1/tls-certificates/${nativePayload.id}/export`,
      expect.objectContaining({credentials: 'include'}),
    );
    expect(onDownloaded).toHaveBeenCalledWith({
      filename: `tlscertificate-${nativePayload.id}.json`,
      data: `${JSON.stringify(nativePayload, null, 2)}\n`,
    });
    expect(onDownloadError).not.toHaveBeenCalled();
  });
});
