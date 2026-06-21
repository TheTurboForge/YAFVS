/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * Modified by TurboVAS contributors, 2026.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import React, {useState} from 'react';
import {fetchNativeReportConfig} from 'gmp/native-api/report-configs';
import {fetchNativeReportFormats} from 'gmp/native-api/report-formats';
import {isDefined} from 'gmp/utils/identity';
import EntityComponent from 'web/entity/EntityComponent';
import useGmp from 'web/hooks/useGmp';
import useTranslation from 'web/hooks/useTranslation';
import ReportConfigDialog from 'web/pages/reportconfigs/Dialog';
import PropTypes from 'web/utils/PropTypes';

const canUseNativeApi = gmp => typeof gmp?.buildUrl === 'function';

const fetchReportConfig = (gmp, reportConfigData) => {
  if (canUseNativeApi(gmp)) {
    return fetchNativeReportConfig(gmp, reportConfigData.id);
  }
  return gmp.reportconfig.get(reportConfigData).then(response => response.data);
};

const fetchAllReportFormats = async gmp => {
  if (!canUseNativeApi(gmp)) {
    const response = await gmp.reportformats.getAll();
    return response.data;
  }

  const pageSize = 200;
  const formats = [];
  let page = 1;
  let total = 0;
  do {
    const response = await fetchNativeReportFormats(gmp, {
      page,
      pageSize,
      sort: 'name',
      filter: '',
    });
    formats.push(...response.reportFormats);
    total = response.page.total;
    page += 1;
  } while (formats.length < total);
  return formats;
};

const ReportConfigComponent = ({
  children,
  onCloneError,
  onCloned,
  onCreateError,
  onCreated,
  onDeleteError,
  onDeleted,
  onDownloadError,
  onDownloaded,
  onSaved,
  onSaveError,
}) => {
  const gmp = useGmp();
  const [_] = useTranslation();

  const [dialogVisible, setDialogVisible] = useState(false);

  const [reportConfig, setReportConfig] = useState();
  const [formats, setFormats] = useState();
  const [preferences, setPreferences] = useState();
  const [title, setTitle] = useState();

  const closeReportConfigDialog = () => {
    setDialogVisible(false);
  };

  const handleCloseReportConfigDialog = () => {
    closeReportConfigDialog();
  };

  const openReportConfigDialog = reportConfigData => {
    if (isDefined(reportConfigData)) {
      // (re-)load report config to get params
      fetchReportConfig(gmp, reportConfigData).then(config => {
        const preferencesData = {};

        config.params.forEach(param => {
          preferencesData[param.name] = param.value;
        });

        const p2 = fetchAllReportFormats(gmp);

        p2.then(formatsData => {
          setDialogVisible(true);
          setFormats(formatsData);
          setPreferences(preferencesData);
          setReportConfig(config);
          setTitle(_('Edit Report Config {{- name}}', {name: config.name}));
        });
      });
    } else {
      fetchAllReportFormats(gmp).then(formatsData => {
        setDialogVisible(true);
        setReportConfig(undefined);
        setFormats(formatsData);
        setTitle(_('New Report Config'));
      });
    }
  };

  const handleSave = data => {
    if (isDefined(data.id)) {
      return gmp.reportconfig
        .save(data)
        .then(onSaved, onSaveError)
        .then(() => closeReportConfigDialog());
    }

    return gmp.reportconfig
      .create(data)
      .then(onCreated, onCreateError)
      .then(() => closeReportConfigDialog());
  };

  return (
    <EntityComponent
      name="reportconfig"
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
      {other => (
        <>
          {children({
            ...other,
            create: openReportConfigDialog,
            edit: openReportConfigDialog,
          })}
          {dialogVisible && (
            <ReportConfigDialog
              formats={formats}
              preferences={preferences}
              reportConfig={reportConfig}
              title={title}
              onClose={handleCloseReportConfigDialog}
              onSave={handleSave}
            />
          )}
        </>
      )}
    </EntityComponent>
  );
};

ReportConfigComponent.propTypes = {
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

export default ReportConfigComponent;
