/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import AuthenticationCommand from 'gmp/commands/auth';
import {createHttp} from 'gmp/commands/testing';
import {createSession} from 'gmp/testing';

afterEach(() => {
  testing.unstubAllGlobals();
});

const createNativeHttp = () => {
  const fakeHttp = createHttp() as ReturnType<typeof createHttp> & {
    buildUrl: ReturnType<typeof testing.fn>;
    session: ReturnType<typeof createSession>;
  };
  fakeHttp.buildUrl = testing.fn(
    (path: string) => `https://turbovas.example/${path}`,
  );
  fakeHttp.session = createSession();
  fakeHttp.session.token = 'test-token';
  fakeHttp.session.jwt = 'jwt-token';
  return fakeHttp;
};

const stubSuccessfulFetch = () => {
  const fetchMock = testing.fn().mockResolvedValue({ok: true, status: 204});
  testing.stubGlobal('fetch', fetchMock);
  return fetchMock;
};

describe('AuthenticationCommand tests', () => {
  test('should preserve LDAP allow-plaintext when saving settings', async () => {
    const fetchMock = stubSuccessfulFetch();
    const cmd = new AuthenticationCommand(createNativeHttp());

    await cmd.saveLdap({
      allowPlaintext: true,
      authdn: 'cn=%s,dc=devel,dc=foo,dc=bar',
      ldapEnabled: true,
      ldapHost: 'foo.bar',
      ldapsOnly: true,
    });

    expect(fetchMock).toHaveBeenCalledWith(
      'https://turbovas.example/api/v1/authentication-settings/ldap',
      expect.objectContaining({
        method: 'PUT',
        body: JSON.stringify({
          enabled: true,
          host: 'foo.bar',
          auth_dn: 'cn=%s,dc=devel,dc=foo,dc=bar',
          allow_plaintext: true,
          ldaps_only: true,
        }),
      }),
    );
  });

  test('should read an LDAP certificate file as PEM text', async () => {
    const fetchMock = stubSuccessfulFetch();
    const cmd = new AuthenticationCommand(createNativeHttp());

    await cmd.saveLdap({
      allowPlaintext: false,
      authdn: 'cn=admin',
      certificate: new File(['certificate pem'], 'ca.pem'),
      ldapEnabled: false,
      ldapHost: 'ldap.example',
      ldapsOnly: false,
    });

    expect(JSON.parse(fetchMock.mock.calls[0][1].body)).toEqual({
      enabled: false,
      host: 'ldap.example',
      auth_dn: 'cn=admin',
      allow_plaintext: false,
      ldaps_only: false,
      ca_certificate_pem: 'certificate pem',
    });
  });

  test('should send a new RADIUS secret without exposing the mask', async () => {
    const fetchMock = stubSuccessfulFetch();
    const cmd = new AuthenticationCommand(createNativeHttp());

    await cmd.saveRadius({
      radiusEnabled: true,
      radiusHost: 'radius.example',
      radiusKey: 'new-secret',
    });

    expect(JSON.parse(fetchMock.mock.calls[0][1].body)).toEqual({
      enabled: true,
      host: 'radius.example',
      secret: 'new-secret',
    });
  });

  test('should omit an unchanged empty RADIUS secret from updates', async () => {
    const fetchMock = stubSuccessfulFetch();
    const cmd = new AuthenticationCommand(createNativeHttp());

    await cmd.saveRadius({
      radiusEnabled: false,
      radiusHost: 'radius.example',
      radiusKey: '',
    });

    expect(JSON.parse(fetchMock.mock.calls[0][1].body)).toEqual({
      enabled: false,
      host: 'radius.example',
    });
  });

  test('should allow a literal eight-asterisk RADIUS secret', async () => {
    const fetchMock = stubSuccessfulFetch();
    const cmd = new AuthenticationCommand(createNativeHttp());

    await cmd.saveRadius({
      radiusEnabled: true,
      radiusHost: 'radius.example',
      radiusKey: '********',
    });

    expect(JSON.parse(fetchMock.mock.calls[0][1].body)).toEqual({
      enabled: true,
      host: 'radius.example',
      secret: '********',
    });
  });

  test('should preserve structured native mutation errors', async () => {
    testing.stubGlobal(
      'fetch',
      testing.fn().mockResolvedValue({
        json: testing.fn().mockResolvedValue({
          error: {
            code: 'mutation_outcome_indeterminate',
            message: 'Mutation outcome is indeterminate.',
          },
        }),
        ok: false,
        status: 502,
      }),
    );
    const cmd = new AuthenticationCommand(createNativeHttp());

    await expect(
      cmd.saveRadius({
        radiusEnabled: true,
        radiusHost: 'radius.example',
        radiusKey: '',
      }),
    ).rejects.toMatchObject({
      code: 'mutation_outcome_indeterminate',
    });
  });
});
