/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {useState} from 'react';
import {
  type default as Credential,
  SMB_CREDENTIAL_TYPES,
  smb_credential_filter,
} from 'gmp/models/credential';
import type ReportFormat from 'gmp/models/report-format';
import {selectSaveId} from 'gmp/utils/id';
import FormGroup from 'web/components/form/FormGroup';
import Select from 'web/components/form/Select';
import TextField from 'web/components/form/TextField';
import {NewIcon} from 'web/components/icon';
import useCapabilities from 'web/hooks/useCapabilities';
import useTranslation from 'web/hooks/useTranslation';
import addPrefix from 'web/utils/add-prefix';
import {
  type RenderSelectItemProps,
  renderSelectItems,
  UNSET_VALUE,
} from 'web/utils/Render';

interface SmbMethodPartProps {
  prefix?: string;
  credentials?: Credential[];
  reportFormats?: ReportFormat[];
  smbCredential?: string;
  smbSharePath?: string;
  smbFilePath?: string;
  smbMaxProtocol?: string;
  smbReportFormat?: string;
  onChange: (value: string | number, name?: string) => void;
  onCredentialChange: (value: string, name?: string) => void;
  onNewCredentialClick: () => void;
}

const SmbMethodPart = ({
  prefix: initialPrefix,
  credentials = [],
  reportFormats = [],
  smbCredential,
  smbFilePath,
  smbMaxProtocol,
  smbReportFormat,
  smbSharePath,
  onChange,
  onNewCredentialClick,
  onCredentialChange,
}: SmbMethodPartProps) => {
  const [_] = useTranslation();
  const [reportFormatId, setReportFormatId] = useState(
    selectSaveId(reportFormats, smbReportFormat),
  );
  const prefix = addPrefix(initialPrefix);
  const handleReportFormatIdChange = (value: string, name?: string) => {
    setReportFormatId(value);
    onChange(value, name);
  };

  const smbMaxProtocolItems = [
    {label: _('Default'), value: ''},
    {label: 'NT1', value: 'NT1'},
    {label: 'SMB2', value: 'SMB2'},
    {label: 'SMB3', value: 'SMB3'},
  ];
  credentials = credentials.filter(smb_credential_filter);
  return (
    <>
      <FormGroup title=" ">
        <span>
          {_(
            'Security note: The SMB protocol does not offer a ' +
              'fingerprint to establish complete mutual trust. Thus a ' +
              'man-in-the-middle attack can not be fully prevented.',
          )}
        </span>
      </FormGroup>

      <FormGroup
        direction="row"
        htmlFor="smb-credential"
        title={_('Credential')}
      >
        <Select
          grow="1"
          id="smb-credential"
          items={renderSelectItems(credentials as RenderSelectItemProps[])}
          name={prefix('smb_credential')}
          value={smbCredential}
          onChange={onCredentialChange}
        />
        <NewIcon
          size="small"
          title={_('Create a credential')}
          value={SMB_CREDENTIAL_TYPES}
          onClick={onNewCredentialClick}
        />
      </FormGroup>

      <FormGroup>
        <TextField
          grow="1"
          name={prefix('smb_share_path')}
          title={_('Share path')}
          value={smbSharePath}
          onChange={onChange}
        />
      </FormGroup>

      <FormGroup>
        <TextField
          grow="1"
          name={prefix('smb_file_path')}
          title={_('File path')}
          value={smbFilePath}
          onChange={onChange}
        />
      </FormGroup>

      <FormGroup>
        <Select
          items={renderSelectItems(reportFormats as RenderSelectItemProps[])}
          label={_('Report Format')}
          name={prefix('smb_report_format')}
          value={reportFormatId}
          onChange={handleReportFormatIdChange}
        />
      </FormGroup>

      <FormGroup>
        <Select
          items={smbMaxProtocolItems}
          label={_('Max Protocol')}
          name={prefix('smb_max_protocol')}
          value={smbMaxProtocol}
          onChange={onChange}
        />
      </FormGroup>
    </>
  );
};

export default SmbMethodPart;
