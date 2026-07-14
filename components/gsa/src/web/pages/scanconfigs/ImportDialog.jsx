/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import React from 'react';
import SaveDialog from 'web/components/dialog/SaveDialog';
import FileField from 'web/components/form/FileField';
import FormGroup from 'web/components/form/FormGroup';
import useTranslation from 'web/hooks/useTranslation';
import PropTypes from 'web/utils/PropTypes';

const ImportDialog = ({title, text, onClose, onSave}) => {
  const [_] = useTranslation();
  return (
    <SaveDialog
      buttonTitle={_('Import')}
      title={title}
      width="500"
      onClose={onClose}
      onSave={onSave}
    >
      {({values, onValueChange}) => (
        <FormGroup title={text}>
          <FileField
            accept="application/json,.json"
            grow="1"
            name="jsonFile"
            value={values.jsonFile}
            onChange={onValueChange}
          />
        </FormGroup>
      )}
    </SaveDialog>
  );
};

ImportDialog.propTypes = {
  text: PropTypes.string,
  title: PropTypes.string,
  onClose: PropTypes.func.isRequired,
  onSave: PropTypes.func.isRequired,
};

export default ImportDialog;
