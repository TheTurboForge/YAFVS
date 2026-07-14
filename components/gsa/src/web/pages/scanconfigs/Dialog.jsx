/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import React from 'react';
import {
  FULL_AND_FAST_SCAN_CONFIG_ID,
  EMPTY_SCAN_CONFIG_ID,
  BASE_SCAN_CONFIG_ID,
} from 'gmp/models/scan-config';
import SaveDialog from 'web/components/dialog/SaveDialog';
import FormGroup from 'web/components/form/FormGroup';
import Radio from 'web/components/form/Radio';
import TextField from 'web/components/form/TextField';
import useTranslation from 'web/hooks/useTranslation';
import PropTypes from 'web/utils/PropTypes';

const CreateScanConfigDialog = ({
  baseScanConfig = BASE_SCAN_CONFIG_ID,
  comment = '',
  name,
  title,
  onClose,
  onSave,
}) => {
  const [_] = useTranslation();
  name = name || _('Unnamed');
  title = title || _('New Scan Config');
  const defaultValues = {
    baseScanConfig,
    comment,
    name,
  };
  return (
    <SaveDialog
      defaultValues={defaultValues}
      title={title}
      width="auto"
      onClose={onClose}
      onSave={onSave}
    >
      {({values: state, onValueChange}) => {
        return (
          <>
            <FormGroup title={_('Name')}>
              <TextField
                name="name"
                value={state.name}
                onChange={onValueChange}
              />
            </FormGroup>

            <FormGroup title={_('Comment')}>
              <TextField
                name="comment"
                value={state.comment}
                onChange={onValueChange}
              />
            </FormGroup>

            <FormGroup title={_('Base')}>
              <Radio
                checked={state.baseScanConfig === BASE_SCAN_CONFIG_ID}
                name="baseScanConfig"
                title={_('Base with a minimum set of NVTs')}
                value={BASE_SCAN_CONFIG_ID}
                onChange={onValueChange}
              />
              <Radio
                checked={state.baseScanConfig === EMPTY_SCAN_CONFIG_ID}
                name="baseScanConfig"
                title={_('Empty, static and fast')}
                value={EMPTY_SCAN_CONFIG_ID}
                onChange={onValueChange}
              />
              <Radio
                checked={state.baseScanConfig === FULL_AND_FAST_SCAN_CONFIG_ID}
                name="baseScanConfig"
                title={_('Full and fast')}
                value={FULL_AND_FAST_SCAN_CONFIG_ID}
                onChange={onValueChange}
              />
            </FormGroup>
          </>
        );
      }}
    </SaveDialog>
  );
};

CreateScanConfigDialog.propTypes = {
  baseScanConfig: PropTypes.oneOf([
    FULL_AND_FAST_SCAN_CONFIG_ID,
    EMPTY_SCAN_CONFIG_ID,
    BASE_SCAN_CONFIG_ID,
  ]),
  comment: PropTypes.string,
  name: PropTypes.string,
  title: PropTypes.string,
  onClose: PropTypes.func.isRequired,
  onSave: PropTypes.func.isRequired,
};

export default CreateScanConfigDialog;
