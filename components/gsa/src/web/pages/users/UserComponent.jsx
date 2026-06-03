/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * Modified by TurboVAS contributors, 2026.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {useState} from 'react';
import {isDefined} from 'gmp/utils/identity';
import EntityComponent from 'web/entity/EntityComponent';
import useGmp from 'web/hooks/useGmp';
import useTranslation from 'web/hooks/useTranslation';
import UserDialog from 'web/pages/users/Dialog';
import PropTypes from 'web/utils/PropTypes';

const UserComponent = props => {
  const {
    children,
    onCloned,
    onCloneError,
    onCreated,
    onCreateError,
    onDeleted,
    onDeleteError,
    onDownloaded,
    onDownloadError,
    onSaved,
    onSaveError,
  } = props;
  const gmp = useGmp();
  const [_] = useTranslation();

  const [dialogVisible, setDialogVisible] = useState(false);
  const [comment, setComment] = useState();
  const [name, setName] = useState();
  const [oldName, setOldName] = useState();
  const [settings, setSettings] = useState();
  const [title, setTitle] = useState();
  const [user, setUser] = useState();

  const closeUserDialog = () => {
    setDialogVisible(false);
  };

  const handleCloseUserDialog = () => {
    closeUserDialog();
  };

  const openUserDialog = async user => {
    try {
      const authSettingsResponse = await gmp.user.currentAuthSettings();
      setSettings(authSettingsResponse.data);
      setDialogVisible(true);

      if (isDefined(user)) {
        setComment(user.comment);
        setName(user.name);
        setOldName(user.name);
        setTitle(_('Edit User {{- name}}', user));
        setUser(user);
      } else {
        setComment(undefined);
        setName(undefined);
        setOldName(undefined);
        setTitle(undefined);
        setUser(undefined);
      }
    } catch (error) {
      console.error('Error loading user dialog data:', error);
    }
  };

  return (
    <EntityComponent
      name="user"
      onCloneError={onCloneError}
      onCloned={onCloned}
      onCreateError={onCreateError}
      onCreated={onCreated}
      onDeleteError={onDeleteError}
      onDeleted={onDeleted}
      onDownloadError={onDownloadError}
      onDownloaded={onDownloaded}
      onSaveError={onSaveError}
      onSaved={onSaved}
    >
      {({save, create, ...other}) => (
        <>
          {children({
            ...other,
            create: openUserDialog,
            edit: openUserDialog,
          })}
          {dialogVisible && (
            <UserDialog
              comment={comment}
              name={name}
              oldName={oldName}
              settings={settings}
              title={title}
              user={user}
              onClose={handleCloseUserDialog}
              onSave={d => {
                const promise = isDefined(d.id) ? save(d) : create(d);
                return promise.then(() => closeUserDialog());
              }}
            />
          )}
        </>
      )}
    </EntityComponent>
  );
};

UserComponent.propTypes = {
  children: PropTypes.func.isRequired,
  onCloneError: PropTypes.func,
  onCloned: PropTypes.func,
  onCreateError: PropTypes.func,
  onCreated: PropTypes.func,
  onDeleteError: PropTypes.func,
  onDeleted: PropTypes.func,
  onDownloadError: PropTypes.func,
  onDownloaded: PropTypes.func,
  onSaveError: PropTypes.func,
  onSaved: PropTypes.func,
};

export default UserComponent;
