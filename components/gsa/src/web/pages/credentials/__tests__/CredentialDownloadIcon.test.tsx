/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {describe, test, expect, testing} from '@gsa/testing';
import {fireEvent, render, screen} from 'web/testing';
import Credential, {
  type CredentialType,
  CERTIFICATE_CREDENTIAL_TYPE,
  KRB5_CREDENTIAL_TYPE,
  PASSWORD_ONLY_CREDENTIAL_TYPE,
  PGP_CREDENTIAL_TYPE,
  SMIME_CREDENTIAL_TYPE,
  SNMP_CREDENTIAL_TYPE,
  USERNAME_PASSWORD_CREDENTIAL_TYPE,
  USERNAME_SSH_KEY_CREDENTIAL_TYPE,
} from 'gmp/models/credential';
import CredentialDownloadIcon from 'web/pages/credentials/CredentialDownloadIcon';

describe('CredentialDownloadIcon tests', () => {
  test('should allow to download ssh key credential files', async () => {
    const handleDownload = testing.fn();
    const credential = new Credential({
      id: 'cred-ssh-key',
      name: 'SSH Key Credential',
      credentialType: USERNAME_SSH_KEY_CREDENTIAL_TYPE,
    });
    render(
      <CredentialDownloadIcon
        credential={credential}
        onDownload={handleDownload}
      />,
    );

    fireEvent.click(screen.getByTitle('Download Public Key'));
    expect(handleDownload).toHaveBeenCalledWith(credential, 'key');

    expect(
      screen.queryByTitle('Download Windows Executable (.exe)'),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByTitle('Download RPM (.rpm) Package'),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByTitle('Download Debian (.deb) Package'),
    ).not.toBeInTheDocument();
  });

  test('should not advertise username/password credential installers', async () => {
    const handleDownload = testing.fn();
    const credential = new Credential({
      id: 'cred-username-password',
      name: 'Username/Password Credential',
      credentialType: USERNAME_PASSWORD_CREDENTIAL_TYPE,
    });
    render(
      <CredentialDownloadIcon
        credential={credential}
        onDownload={handleDownload}
      />,
    );

    expect(
      screen.queryByTitle('Download RPM (.rpm) Package'),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByTitle('Download Debian (.deb) Package'),
    ).not.toBeInTheDocument();
    expect(screen.queryByTitle('Download Public Key')).not.toBeInTheDocument();
    expect(
      screen.queryByTitle('Download Windows Executable (.exe)'),
    ).not.toBeInTheDocument();
    expect(handleDownload).not.toHaveBeenCalled();
  });

  test('should allow to download client certificates', async () => {
    const handleDownload = testing.fn();
    const credential = new Credential({
      id: 'cred-certificate',
      name: 'Client Certificate',
      credentialType: CERTIFICATE_CREDENTIAL_TYPE,
    });
    render(
      <CredentialDownloadIcon
        credential={credential}
        onDownload={handleDownload}
      />,
    );

    fireEvent.click(screen.getByTitle('Download Client Certificate'));
    expect(handleDownload).toHaveBeenCalledWith(credential, 'pem');
  });

  test.each([
    {name: 'SNMP', credentialType: SNMP_CREDENTIAL_TYPE},
    {name: 'Kerberos', credentialType: KRB5_CREDENTIAL_TYPE},
    {name: 'Password Only', credentialType: PASSWORD_ONLY_CREDENTIAL_TYPE},
    {name: 'PGP Key', credentialType: PGP_CREDENTIAL_TYPE},
    {name: 'SMIME', credentialType: SMIME_CREDENTIAL_TYPE},
  ] as {name: string; credentialType: CredentialType}[])(
    'should render nothing for $name credential type',
    async ({name, credentialType}) => {
      const credential = new Credential({
        id: 'cred-other',
        name,
        credentialType,
      });
      render(<CredentialDownloadIcon credential={credential} />);

      expect(
        screen.queryByTitle('Download RPM (.rpm) Package'),
      ).not.toBeInTheDocument();
      expect(
        screen.queryByTitle('Download Debian (.deb) Package'),
      ).not.toBeInTheDocument();
      expect(
        screen.queryByTitle('Download Public Key'),
      ).not.toBeInTheDocument();
      expect(
        screen.queryByTitle('Download Windows Executable (.exe)'),
      ).not.toBeInTheDocument();
    },
  );
});
