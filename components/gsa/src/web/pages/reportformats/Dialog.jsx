/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import React from 'react';
import {isDefined} from 'gmp/utils/identity';
import SaveDialog from 'web/components/dialog/SaveDialog';
import FileField from 'web/components/form/FileField';
import FormGroup from 'web/components/form/FormGroup';
import TextField from 'web/components/form/TextField';
import YesNoRadio from 'web/components/form/YesNoRadio';
import useTranslation from 'web/hooks/useTranslation';
import PropTypes from 'web/utils/PropTypes';

const Dialog = ({
  reportformat: reportFormat,
  title,
  onClose,
  onError,
  error,
  onSave,
}) => {
  const [_] = useTranslation();

  title = title || _('Import Report Format');

  if (isDefined(reportFormat)) {
    return (
      <SaveDialog
        defaultValues={reportFormat}
        error={error}
        title={title}
        onClose={onClose}
        onError={onError}
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

              <FormGroup title={_('Summary')}>
                <TextField
                  name="summary"
                  value={state.summary}
                  onChange={onValueChange}
                />
              </FormGroup>

              <FormGroup title={_('Active')}>
                <YesNoRadio
                  name="active"
                  value={state.active}
                  onChange={onValueChange}
                />
              </FormGroup>
            </>
          );
        }}
      </SaveDialog>
    );
  }
  return (
    <SaveDialog
      error={error}
      title={title}
      onClose={onClose}
      onError={onError}
      onSave={onSave}
    >
      {({values, onValueChange}) => {
        return (
          <FormGroup title={_('Import XML Report Format')}>
            <FileField
              name="xml_file"
              value={values.xml_file}
              onChange={onValueChange}
            />
          </FormGroup>
        );
      }}
    </SaveDialog>
  );
};

Dialog.propTypes = {
  error: PropTypes.string,
  reportformat: PropTypes.model,
  title: PropTypes.string,
  onClose: PropTypes.func.isRequired,
  onError: PropTypes.func,
  onSave: PropTypes.func.isRequired,
};
export default Dialog;
