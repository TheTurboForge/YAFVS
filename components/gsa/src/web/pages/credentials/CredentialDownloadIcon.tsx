/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * YAFVS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {type CredentialDownloadFormat} from 'gmp/commands/credential';
import {
  CERTIFICATE_CREDENTIAL_TYPE,
  type default as Credential,
  USERNAME_SSH_KEY_CREDENTIAL_TYPE,
} from 'gmp/models/credential';
import {isDefined} from 'gmp/utils/identity';
import {DownloadKeyIcon} from 'web/components/icon';
import IconDivider from 'web/components/layout/IconDivider';
import useTranslation from 'web/hooks/useTranslation';

interface CredentialDownloadIconProps {
  credential: Credential;
  onDownload?: (
    credential: Credential,
    format: CredentialDownloadFormat,
  ) => void;
}

const CredentialDownloadIcon = ({
  credential,
  onDownload,
}: CredentialDownloadIconProps) => {
  const [_] = useTranslation();
  const type = credential.credentialType;
  return (
    <IconDivider align={['center', 'center']}>
      {type === USERNAME_SSH_KEY_CREDENTIAL_TYPE && (
        <DownloadKeyIcon
          title={_('Download Public Key')}
          value={credential}
          onClick={
            isDefined(onDownload) ? cred => onDownload(cred, 'key') : undefined
          }
        />
      )}
      {type === CERTIFICATE_CREDENTIAL_TYPE && (
        <DownloadKeyIcon
          title={_('Download Client Certificate')}
          value={credential}
          onClick={
            isDefined(onDownload) ? cred => onDownload(cred, 'pem') : undefined
          }
        />
      )}
    </IconDivider>
  );
};

export default CredentialDownloadIcon;
