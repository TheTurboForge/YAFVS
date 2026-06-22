/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {
  AUTH_METHOD_LDAP,
  AUTH_METHOD_NEW_PASSWORD,
  AUTH_METHOD_PASSWORD,
  AUTH_METHOD_RADIUS,
} from 'gmp/models/user';
import {isDefined} from 'gmp/utils/identity';
import SaveDialog from 'web/components/dialog/SaveDialog';
import FormGroup from 'web/components/form/FormGroup';
import PasswordField from 'web/components/form/PasswordField';
import Radio from 'web/components/form/Radio';
import TextField from 'web/components/form/TextField';
import Row from 'web/components/layout/Row';
import useTranslation from 'web/hooks/useTranslation';
import PropTypes from 'web/utils/PropTypes';

const Dialog = ({
  comment = '',
  name,
  oldName,
  password = '',
  settings,
  title,
  user,
  onClose,
  onSave,
}) => {
  const [_] = useTranslation();

  name = name || _('Unnamed');
  title = title || _('New User');

  const isEdit = isDefined(user);

  const data = {
    ...user,
    auth_method:
      isEdit && isDefined(user.authMethod)
        ? user.authMethod
        : AUTH_METHOD_PASSWORD,
    comment,
    name,
    old_name: oldName,
    password,
  };

  const hasLdapEnabled = settings.get('method:ldap_connect').enabled;
  const hasRadiusEnabled = settings.get('method:radius_connect').enabled;

  return (
    <SaveDialog
      defaultValues={data}
      title={title}
      onClose={onClose}
      onSave={onSave}
    >
      {({values: state, onValueChange}) => (
        <>
          <FormGroup title={_('Login Name')}>
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

          {!isEdit && (
            <FormGroup flex="column" title={_('Authentication')}>
              <Row>
                <Radio
                  checked={state.auth_method === AUTH_METHOD_PASSWORD}
                  name="auth_method"
                  title={_('Password')}
                  value={AUTH_METHOD_PASSWORD}
                  onChange={onValueChange}
                />
                <PasswordField
                  autoComplete="new-password"
                  grow="1"
                  name="password"
                  value={state.password}
                  onChange={onValueChange}
                />
              </Row>
              {hasLdapEnabled && (
                <Radio
                  checked={state.auth_method === AUTH_METHOD_LDAP}
                  name="auth_method"
                  title={_('LDAP Authentication Only')}
                  value={AUTH_METHOD_LDAP}
                  onChange={onValueChange}
                />
              )}
              {hasRadiusEnabled && (
                <Radio
                  checked={state.auth_method === AUTH_METHOD_RADIUS}
                  name="auth_method"
                  title={_('RADIUS Authentication Only')}
                  value={AUTH_METHOD_RADIUS}
                  onChange={onValueChange}
                />
              )}
            </FormGroup>
          )}

          {isEdit && (
            <FormGroup title={_('Authentication')}>
              <Radio
                checked={state.auth_method === AUTH_METHOD_PASSWORD}
                name="auth_method"
                title={_('Password: Use existing Password')}
                value={AUTH_METHOD_PASSWORD}
                onChange={onValueChange}
              />
              <Row>
                <Radio
                  checked={state.auth_method === AUTH_METHOD_NEW_PASSWORD}
                  name="auth_method"
                  title={_('New Password')}
                  value={AUTH_METHOD_NEW_PASSWORD}
                  onChange={onValueChange}
                />
                <PasswordField
                  autoComplete="new-password"
                  disabled={state.auth_method !== AUTH_METHOD_NEW_PASSWORD}
                  grow="1"
                  name="password"
                  value={state.password}
                  onChange={onValueChange}
                />
              </Row>
              {hasLdapEnabled && (
                <Radio
                  checked={state.auth_method === AUTH_METHOD_LDAP}
                  name="auth_method"
                  title={_('LDAP Authentication Only')}
                  value={AUTH_METHOD_LDAP}
                  onChange={onValueChange}
                />
              )}
              {hasRadiusEnabled && (
                <Radio
                  checked={state.auth_method === AUTH_METHOD_RADIUS}
                  name="auth_method"
                  title={_('RADIUS Authentication Only')}
                  value={AUTH_METHOD_RADIUS}
                  onChange={onValueChange}
                />
              )}
            </FormGroup>
          )}
        </>
      )}
    </SaveDialog>
  );
};

Dialog.propTypes = {
  authMethod: PropTypes.oneOf([
    AUTH_METHOD_LDAP,
    AUTH_METHOD_NEW_PASSWORD,
    AUTH_METHOD_PASSWORD,
    AUTH_METHOD_RADIUS,
  ]),
  comment: PropTypes.string,
  id: PropTypes.id,
  name: PropTypes.string,
  oldName: PropTypes.string,
  password: PropTypes.string,
  settings: PropTypes.settings.isRequired,
  title: PropTypes.string,
  user: PropTypes.model,
  onClose: PropTypes.func.isRequired,
  onSave: PropTypes.func.isRequired,
};

export default Dialog;
