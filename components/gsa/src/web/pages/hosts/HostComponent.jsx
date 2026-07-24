/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {useRef, useState} from 'react';
import {exportNativeHostMetadata} from 'gmp/native-api/hosts';
import {isDefined} from 'gmp/utils/identity';
import {shorten} from 'gmp/utils/string';
import EntityComponent from 'web/entity/EntityComponent';
import useGmp from 'web/hooks/useGmp';
import useTranslation from 'web/hooks/useTranslation';
import HostDialog from 'web/pages/hosts/Dialog';
import TargetComponent from 'web/pages/targets/TargetComponent';
import PropTypes from 'web/utils/PropTypes';
import SelectionType from 'web/utils/SelectionType';

const canUseNativeApi = gmp => typeof gmp?.buildUrl === 'function';

const exportHost = (gmp, host) => {
  if (canUseNativeApi(gmp)) {
    return exportNativeHostMetadata(gmp, host.id);
  }
  return gmp.host.export(host);
};

const HostComponent = ({
  children,
  createtarget,
  onIdentifierDeleted,
  onIdentifierDeleteError,
  onCreateError,
  onCreated,
  onDeleteError,
  onDeleted,
  onDownloadError,
  onDownloaded,
  onTargetCreateError,

  onSaveError,
  onSaved,
  ...props
}) => {
  const gmp = useGmp();
  const [_] = useTranslation();

  const [dialogVisible, setDialogVisible] = useState(false);
  const [host, setHost] = useState();
  const [title, setTitle] = useState();
  const [targetSourceLoading, setTargetSourceLoading] = useState(false);
  const targetSourceLoadingRef = useRef(false);

  const handleIdentifierDelete = identifier => {
    return gmp.host
      .deleteIdentifier(identifier)
      .then(onIdentifierDeleted, onIdentifierDeleteError);
  };

  const openHostDialog = host => {
    let dialogTitle;

    if (isDefined(host)) {
      dialogTitle = _('Edit Host {{name}}', {name: shorten(host.name)});
    }

    setDialogVisible(true);
    setHost(host);
    setTitle(dialogTitle);
  };

  const closeHostDialog = () => {
    setDialogVisible(false);
  };

  const handleCloseHostDialog = () => {
    closeHostDialog();
  };

  const openCreateTargetDialog = async host => {
    if (targetSourceLoadingRef.current) {
      return;
    }
    targetSourceLoadingRef.current = true;
    setTargetSourceLoading(true);
    try {
      await _openTargetDialog([host.id], `Target for host ${host.name}`);
    } catch (error) {
      onTargetCreateError(
        error instanceof Error
          ? error
          : new Error('Could not prepare the host asset for target creation'),
      );
    } finally {
      targetSourceLoadingRef.current = false;
      setTargetSourceLoading(false);
    }
  };

  const openCreateTargetSelectionDialog = async data => {
    const {entities, entitiesSelected, selectionType, filter} = data;
    if (targetSourceLoadingRef.current) {
      return;
    }
    targetSourceLoadingRef.current = true;
    setTargetSourceLoading(true);
    try {
      if (selectionType === SelectionType.SELECTION_USER) {
        await _openTargetDialog([...entitiesSelected].map(host => host.id));
      } else if (selectionType === SelectionType.SELECTION_PAGE_CONTENTS) {
        await _openTargetDialog(entities.map(host => host.id));
      } else {
        const hostAssetIds = await gmp.hosts.getStableTargetSourceIds(filter);
        await _openTargetDialog(hostAssetIds);
      }
    } catch (error) {
      onTargetCreateError(
        error instanceof Error
          ? error
          : new Error('Could not prepare host assets for target creation'),
      );
    } finally {
      targetSourceLoadingRef.current = false;
      setTargetSourceLoading(false);
    }
  };

  const _openTargetDialog = (hostAssetIds, name) => {
    const uniqueIds = [...new Set(hostAssetIds)];
    if (
      uniqueIds.length === 0 ||
      uniqueIds.length > 4095 ||
      uniqueIds.some(id => typeof id !== 'string' || id.trim().length === 0)
    ) {
      throw new Error(
        'Host-asset target creation requires 1 to 4095 unique host asset IDs',
      );
    }
    return createtarget({
      targetSource: 'asset_hosts',
      hostsCount: uniqueIds.length,
      hostAssetIds: uniqueIds,
      name,
    });
  };

  return (
    <EntityComponent
      download={entity => exportHost(gmp, entity)}
      downloadOptions={canUseNativeApi(gmp) ? {extension: 'json'} : undefined}
      name="host"
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
            create: openHostDialog,
            edit: openHostDialog,
            deleteidentifier: handleIdentifierDelete,
            createtargetfromselection: openCreateTargetSelectionDialog,
            createtargetfromhost: openCreateTargetDialog,
            targetSourceLoading,
          })}
          {dialogVisible && (
            <HostDialog
              host={host}
              title={title}
              onClose={handleCloseHostDialog}
              onSave={d => {
                const promise = isDefined(d.id) ? save(d) : create(d);
                return promise.then(() => closeHostDialog());
              }}
            />
          )}
        </>
      )}
    </EntityComponent>
  );
};

HostComponent.propTypes = {
  children: PropTypes.func.isRequired,
  createtarget: PropTypes.func.isRequired,
  onCreateError: PropTypes.func,
  onCreated: PropTypes.func,
  onDeleteError: PropTypes.func,
  onDeleted: PropTypes.func,
  onDownloadError: PropTypes.func,
  onDownloaded: PropTypes.func,
  onIdentifierDeleteError: PropTypes.func,
  onIdentifierDeleted: PropTypes.func,
  onTargetCreateError: PropTypes.func.isRequired,
  onSaveError: PropTypes.func,
  onSaved: PropTypes.func,
};

const HostComponentWrapper = HostComponent;

const HostWithTargetComponent = ({
  onTargetCreated,
  onTargetCreateError,
  ...props
}) => {
  return (
    <TargetComponent
      onCreateError={onTargetCreateError}
      onCreated={onTargetCreated}
    >
      {({create}) => (
        <HostComponentWrapper
          {...props}
          createtarget={create}
          onTargetCreateError={onTargetCreateError}
        />
      )}
    </TargetComponent>
  );
};

HostWithTargetComponent.propTypes = {
  onTargetCreateError: PropTypes.func.isRequired,
  onTargetCreated: PropTypes.func.isRequired,
};

export default HostWithTargetComponent;
