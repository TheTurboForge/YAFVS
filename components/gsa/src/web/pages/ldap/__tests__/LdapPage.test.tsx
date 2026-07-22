/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {describe, test, expect, testing} from '@gsa/testing';
import {fireEvent, rendererWith, screen, wait} from 'web/testing';
import Settings from 'gmp/models/settings';
import {createSession} from 'gmp/testing';
import LdapAuthentication from 'web/pages/ldap/LdapPage';

const createSettings = () => {
  const settings = new Settings();
  settings.set('method:ldap_connect', {
    allowPlaintext: true,
    authdn: 'cn=admin',
    certificateInfo: {
      issuer: 'Example CA',
      sha256Fingerprint: 'sha256-value',
    },
    enabled: true,
    ldaphost: 'ldap.example',
    ldapsOnly: true,
  });
  return settings;
};

describe('LDAP page renders', () => {
  test('should display the SHA-256 certificate fingerprint', async () => {
    const gmp = {
      auth: {saveLdap: testing.fn()},
      session: createSession(),
      settings: {manualUrl: 'http://docs.greenbone.net/GSM-Manual/gos-5/'},
      user: {
        currentAuthSettings: testing.fn().mockResolvedValue({
          data: createSettings(),
        }),
      },
    };

    const {render} = rendererWith({gmp, store: true});
    render(<LdapAuthentication />);
    await wait();

    expect(screen.getByText('SHA-256 Fingerprint')).toBeInTheDocument();
    expect(screen.getByText('sha256-value')).toBeInTheDocument();
    expect(screen.queryByText('MD5 Fingerprint')).not.toBeInTheDocument();
  });

  test('should pass hidden allow-plaintext state when saving', async () => {
    const saveLdap = testing.fn().mockResolvedValue(undefined);
    const gmp = {
      auth: {saveLdap},
      session: createSession(),
      settings: {manualUrl: 'http://docs.greenbone.net/GSM-Manual/gos-5/'},
      user: {
        currentAuthSettings: testing.fn().mockResolvedValue({
          data: createSettings(),
        }),
      },
    };

    const {render} = rendererWith({gmp, store: true});
    render(<LdapAuthentication />);
    await wait();
    fireEvent.click(screen.getByTitle('Edit LDAP per-User Authentication'));
    fireEvent.click(screen.getByRole('button', {name: 'Save'}));

    expect(saveLdap).toHaveBeenCalledWith(
      expect.objectContaining({allowPlaintext: true, ldapsOnly: true}),
    );
  });
});
