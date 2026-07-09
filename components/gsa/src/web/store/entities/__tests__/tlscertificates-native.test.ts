/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, expect, test, testing} from '@gsa/testing';
import {
  fetchNativeTlsCertificate,
  fetchNativeTlsCertificates,
} from 'gmp/native-api/tls-certificates';
import Filter from 'gmp/models/filter';
import TlsCertificate from 'gmp/models/tls-certificate';
import {loadEntities, loadEntity} from 'web/store/entities/tlscertificates';
import {createState} from 'web/store/entities/utils/testing';
import {filterIdentifier} from 'web/store/utils';

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

  test('fetches one TLS certificate from the native detail endpoint', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
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
        valid: true,
        trust: false,
        time_status: 'valid',
        user_tags: [
          {
            id: 'tag-1',
            name: 'Watched Certificate',
            value: 'true',
            comment: 'operator review',
          },
        ],
        sources: [
          {
            id: 'source-1',
            timestamp: '2026-06-18T20:00:00Z',
            tls_versions: 'TLSv1.2,TLSv1.3',
            location: {
              id: 'location-1',
              host_ip: '192.168.178.42',
              port: '443/tcp',
              host_asset_id: 'host-1',
            },
            origin: {
              id: 'origin-1',
              origin_type: 'Report',
              origin_id: 'report-1',
              origin_data: '1.3.6.1.4.1.25623.1.0.103692',
            },
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp({jwt: 'jwt-token'});

    const response = await fetchNativeTlsCertificate(
      gmp,
      'a4d44986-29ce-4b85-9def-0ac63108d198',
    );

    const certificate = response.tlsCertificate;
    expect(certificate.id).toEqual('a4d44986-29ce-4b85-9def-0ac63108d198');
    expect(certificate.name).toEqual('CN=example.local');
    expect(certificate.subjectDn).toEqual('CN=example.local');
    expect(certificate.issuerDn).toEqual('CN=Example Issuer');
    expect(certificate.serial).toEqual('00FAF93A4C7FB6B9CC');
    expect(certificate.sha256Fingerprint).toEqual('sha256-value');
    expect(certificate.valid).toEqual(true);
    expect(certificate.trust).toEqual(false);
    expect(certificate.timeStatus).toEqual('valid');
    expect(certificate.isWritable()).toEqual(true);
    expect(certificate.userTags?.[0].name).toEqual('Watched Certificate');
    expect(certificate.sourceHosts).toEqual([
      {id: 'host-1', ip: '192.168.178.42'},
    ]);
    expect(certificate.sourcePorts).toEqual(['443/tcp']);
    expect(certificate.sourceReports?.[0].id).toEqual('report-1');
    expect(certificate.certificate).toBeUndefined();
    expect(gmp.buildUrl).toHaveBeenCalledWith(
      'api/v1/tls-certificates/a4d44986-29ce-4b85-9def-0ac63108d198',
      {token: 'test-token'},
    );
  });

  test('loads the TLS certificate store through same-origin native API', async () => {
    const filter = Filter.fromString('first=1 rows=10 sort-reverse=last_seen');
    const rootState = createState('tlscertificate', {
      isLoading: {
        [filterIdentifier(filter)]: false,
      },
    });
    const getState = testing.fn().mockReturnValue(rootState);
    const dispatch = testing.fn();
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        page: {page: 1, page_size: 10, total: 1, sort: '-last_seen', filter: ''},
        items: [
          {
            id: 'a4d44986-29ce-4b85-9def-0ac63108d198',
            name: 'CN=example.local',
            subject_dn: 'CN=example.local',
            issuer_dn: 'CN=Example Issuer',
            sha256_fingerprint: 'sha256-value',
            in_use: true,
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp({jwt: 'jwt-token'});

    await loadEntities(gmp)(filter)(dispatch, getState);

    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/tls-certificates', {
      token: 'test-token',
      page: 1,
      page_size: 10,
      sort: '-last_seen',
      filter: '',
    });
    expect(dispatch).toHaveBeenCalledTimes(2);
    const successAction = dispatch.mock.calls[1][0];
    expect(successAction.type).toEqual('ENTITIES_LOADING_SUCCESS');
    expect(successAction.counts.filtered).toEqual(1);
    expect(successAction.data[0]).toBeInstanceOf(TlsCertificate);
    expect(successAction.data[0].name).toEqual('CN=example.local');
  });

  test('loads native detail without inherited GMP detail request', async () => {
    const id = 'a4d44986-29ce-4b85-9def-0ac63108d198';
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue({
        id,
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
        in_use: true,
        valid: true,
        trust: false,
        time_status: 'valid',
        user_tags: [
          {
            id: 'tag-1',
            name: 'Watched Certificate',
            value: 'true',
            comment: 'operator review',
          },
        ],
        sources: [
          {
            id: 'source-1',
            timestamp: '2026-06-18T20:00:00Z',
            tls_versions: 'TLSv1.3',
            location: {
              id: 'location-1',
              host_ip: '192.168.178.42',
              port: '443/tcp',
              host_asset_id: 'host-1',
            },
            origin: {
              id: 'origin-1',
              origin_type: 'Report',
              origin_id: 'report-1',
              origin_data: '1.3.6.1.4.1.25623.1.0.103692',
            },
          },
        ],
      }),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = {
      ...createGmp({jwt: 'jwt-token'}),
      tlscertificate: {
        get: testing.fn(),
      },
    };
    const actions: Array<{type: string; data?: TlsCertificate}> = [];
    const dispatch = testing.fn(action => {
      actions.push(action);
      return action;
    });
    const getState = () => ({
      entities: {
        tlscertificate: {
          byId: {},
          errors: {},
          isLoading: {},
        },
      },
    });

    await loadEntity(gmp)(id)(dispatch, getState);

    const success = actions.find(
      action => action.type === 'ENTITY_LOADING_SUCCESS',
    );
    const certificate = success?.data;
    expect(gmp.tlscertificate.get).not.toHaveBeenCalled();
    expect(certificate).toBeInstanceOf(TlsCertificate);
    expect(certificate?.name).toEqual('CN=example.local');
    expect(certificate?.subjectDn).toEqual('CN=example.local');
    expect(certificate?.issuerDn).toEqual('CN=Example Issuer');
    expect(certificate?.sha256Fingerprint).toEqual('sha256-value');
    expect(certificate?.certificate).toBeUndefined();
    expect(certificate?.valid).toEqual(true);
    expect(certificate?.trust).toEqual(false);
    expect(certificate?.isWritable()).toEqual(true);
    expect(certificate?.userTags?.length).toEqual(1);
    expect(certificate?.userTags?.[0].name).toEqual('Watched Certificate');
    expect(certificate?.sourceHosts).toEqual([
      {id: 'host-1', ip: '192.168.178.42'},
    ]);
    expect(certificate?.sourcePorts).toEqual(['443/tcp']);
    expect(certificate?.sourceReports?.[0].id).toEqual('report-1');
  });
});
