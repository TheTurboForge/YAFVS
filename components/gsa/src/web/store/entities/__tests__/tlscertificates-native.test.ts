/* SPDX-FileCopyrightText: 2026 TurboVAS contributors
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, expect, test, testing} from '@gsa/testing';
import {fetchNativeTlsCertificates} from 'gmp/native-api/tls-certificates';

const createGmp = ({jwt, token = 'test-token'}: {jwt?: string; token?: string} = {}) => ({
  buildUrl: testing.fn((path: string) => `https://turbovas.example/${path}`),
  session: {jwt, token},
});

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('native API TLS certificates list', () => {
  test('fetches top-level TLS certificates as inherited TlsCertificate models', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 25, total: 1, sort: '-last_seen', filter: ''},
        items: [
          {
            id: 'a4d44986-29ce-4b85-9def-0ac63108d198',
            name: 'CN=example.local',
            comment: 'observed certificate',
            subject_dn: 'CN=example.local',
            issuer_dn: 'CN=Example Issuer',
            serial: '00FAF93A4C7FB6B9CC',
            md5_fingerprint: 'md5-value',
            sha256_fingerprint: 'sha256-value',
            activation_time: '2026-06-18T18:00:00Z',
            expiration_time: '2027-06-18T18:00:00Z',
            last_seen: '2026-06-18T20:00:00Z',
            source_host_count: 1,
            source_port_count: 2,
            source_count: 2,
            in_use: true,
            created_at: '2026-06-18T17:00:00Z',
            modified_at: '2026-06-18T20:00:00Z',
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp({jwt: 'jwt-token'});

    const response = await fetchNativeTlsCertificates(gmp, {
      page: 1,
      pageSize: 25,
      sort: '-last_seen',
      filter: '',
    });

    const certificate = response.tlsCertificates[0];
    expect(response.counts.filtered).toEqual(1);
    expect(certificate.id).toEqual('a4d44986-29ce-4b85-9def-0ac63108d198');
    expect(certificate.name).toEqual('CN=example.local');
    expect(certificate.comment).toEqual('observed certificate');
    expect(certificate.subjectDn).toEqual('CN=example.local');
    expect(certificate.issuerDn).toEqual('CN=Example Issuer');
    expect(certificate.serial).toEqual('00FAF93A4C7FB6B9CC');
    expect(certificate.md5Fingerprint).toEqual('md5-value');
    expect(certificate.sha256Fingerprint).toEqual('sha256-value');
    expect(certificate.isInUse()).toEqual(true);
    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/tls-certificates', {
      token: 'test-token',
      page: 1,
      page_size: 25,
      sort: '-last_seen',
      filter: '',
    });
    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/tls-certificates',
      {
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          Authorization: 'Bearer jwt-token',
        },
      },
    );
  });
});
