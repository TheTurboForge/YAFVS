/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import React, {useState, useRef, useCallback} from 'react';
import {useDispatch} from 'react-redux';
import {
  email_credential_filter,
  smb_credential_filter,
} from 'gmp/models/credential';
import {fetchNativeCredentials} from 'gmp/native-api/credentials';
import {parseInt, parseSeverity, parseYesNo, NO_VALUE} from 'gmp/parser';
import {selectSaveId} from 'gmp/utils/id';
import {isDefined} from 'gmp/utils/identity';
import {capitalizeFirstLetter, shorten} from 'gmp/utils/string';
import {fetchNativeFilters} from 'gmp/native-api/filters';
import {fetchNativeReportConfigs} from 'gmp/native-api/report-configs';
import {fetchNativeReportFormats} from 'gmp/native-api/report-formats';
import {fetchNativeTasks} from 'gmp/native-api/tasks';
import FootNote from 'web/components/footnote/Footnote';
import Layout from 'web/components/layout/Layout';
import EntityComponent from 'web/entity/EntityComponent';
import useGmp from 'web/hooks/useGmp';
import useShallowEqualSelector from 'web/hooks/useShallowEqualSelector';
import useTranslation from 'web/hooks/useTranslation';
import ContentComposerDialog from 'web/pages/alerts/ContentComposerDialog';
import AlertDialog, {
  ATTACH_MESSAGE_DEFAULT,
  ATTACH_MESSAGE_SECINFO,
  DEFAULT_DETAILS_URL,
  DEFAULT_DIRECTION,
  DEFAULT_EVENT_STATUS,
  DEFAULT_NOTICE,
  DEFAULT_NOTICE_ATTACH_FORMAT,
  DEFAULT_NOTICE_REPORT_FORMAT,
  DEFAULT_SCP_PATH,
  DEFAULT_SECINFO_TYPE,
  DEFAULT_SEVERITY,
  INCLUDE_MESSAGE_DEFAULT,
  INCLUDE_MESSAGE_SECINFO,
  NOTICE_ATTACH,
  SECINFO_SUBJECT,
  TASK_SUBJECT,
} from 'web/pages/alerts/Dialog';
import CredentialDialog from 'web/pages/credentials/CredentialDialog';
import {
  loadReportComposerDefaults,
  saveReportComposerDefaults,
} from 'web/store/usersettings/actions';
import {getReportComposerDefaults} from 'web/store/usersettings/selectors';
import PropTypes from 'web/utils/PropTypes';
import {UNSET_VALUE} from 'web/utils/Render';

const getValue = (data = {}, def = undefined) => {
  const {value: val = def} = data;
  return val;
};

const filterResultsFilter = filter => filter.filter_type === 'result';
const filterSecinfoFilter = filter => filter.filter_type === 'info';
const ALERT_DIALOG_NATIVE_PAGE_SIZE = 500;
const ALERT_CREDENTIAL_NATIVE_PAGE_SIZE = 500;

const canUseNativeApi = gmp => typeof gmp?.buildUrl === 'function';

const nativeDialogQuery = page => ({
  page,
  pageSize: ALERT_DIALOG_NATIVE_PAGE_SIZE,
  sort: 'name',
  filter: '',
});

const fetchAllNativeDialogItems = async (fetchPage, key) => {
  const items = [];
  for (let page = 1; ; page += 1) {
    const response = await fetchPage(page);
    const pageItems = response[key] ?? [];
    items.push(...pageItems);
    const total = response.page?.total ?? items.length;
    if (pageItems.length === 0 || items.length >= total) {
      break;
    }
  }
  return items;
};

export const fetchNativeAlertCredentials = async gmp => {
  const credentials = [];
  for (let page = 1; ; page += 1) {
    const response = await fetchNativeCredentials(gmp, {
      page,
      pageSize: ALERT_CREDENTIAL_NATIVE_PAGE_SIZE,
      sort: 'name',
      filter: '',
    });
    credentials.push(...response.credentials);
    const total = response.page?.total ?? credentials.length;
    if (response.credentials.length === 0 || credentials.length >= total) {
      break;
    }
  }
  return credentials;
};

export const fetchNativeAlertDialogLookups = async gmp => {
  const [reportFormats, reportConfigs, filters, tasks] = await Promise.all([
    fetchAllNativeDialogItems(
      page => fetchNativeReportFormats(gmp, nativeDialogQuery(page)),
      'reportFormats',
    ),
    fetchAllNativeDialogItems(
      page => fetchNativeReportConfigs(gmp, nativeDialogQuery(page)),
      'reportConfigs',
    ),
    fetchAllNativeDialogItems(
      page => fetchNativeFilters(gmp, nativeDialogQuery(page)),
      'filters',
    ),
    fetchAllNativeDialogItems(
      page => fetchNativeTasks(gmp, nativeDialogQuery(page)),
      'tasks',
    ),
  ]);
  return {reportFormats, reportConfigs, filters, tasks};
};

const fetchInheritedAlertDialogLookups = async gmp => {
  const [reportFormats, reportConfigs, filters, tasks] = await Promise.all([
    gmp.reportformats.getAll().then(r => r.data),
    gmp.reportconfigs.getAll().then(r => r.data),
    gmp.filters.getAll().then(r => r.data),
    gmp.tasks.getAll({schedulesOnly: true}).then(r => r.data),
  ]);
  return {reportFormats, reportConfigs, filters, tasks};
};

const fetchAlertDialogLookups = gmp =>
  canUseNativeApi(gmp)
    ? fetchNativeAlertDialogLookups(gmp)
    : fetchInheritedAlertDialogLookups(gmp);

const fetchAlertCredentials = gmp =>
  canUseNativeApi(gmp)
    ? fetchNativeAlertCredentials(gmp)
    : gmp.credentials.getAll().then(r => r.data);

const AlertComponent = ({
  children,
  onError,
  onCloned,
  onCloneError = onError,
  onCreated,
  onCreateError = onError,
  onDeleted,
  onDeleteError = onError,
  onDownloaded,
  onDownloadError = onError,
  onSaved,
  onSaveError = onError,
  onTestSuccess,
  onTestError,
  ...props
}) => {
  const [_] = useTranslation();
  const gmp = useGmp();
  const dispatch = useDispatch();

  const reportComposerDefaults = useShallowEqualSelector(
    getReportComposerDefaults,
  );
  const loadDefaults = useCallback(() => {
    dispatch(loadReportComposerDefaults(gmp)());
  }, [dispatch, gmp]);

  const saveDefaults = useCallback(
    defaults => {
      dispatch(saveReportComposerDefaults(gmp)(defaults));
    },
    [dispatch, gmp],
  );
  const [alertDialogVisible, setAlertDialogVisible] = useState(false);
  const [credentialDialogVisible, setCredentialDialogVisible] = useState(false);
  const [contentComposerDialogVisible, setContentComposerDialogVisible] =
    useState(false);
  const [credentialDialogTitle, setCredentialDialogTitle] = useState('');
  const [credentialTypes, setCredentialTypes] = useState([]);

  const [id, setId] = useState(undefined);
  const [alert, setAlert] = useState(undefined);
  const [active, setActive] = useState(undefined);
  const [name, setName] = useState(undefined);
  const [comment, setComment] = useState(undefined);
  const [filters, setFilters] = useState([]);
  const [filterId, setFilterId] = useState(undefined);
  const [composerFilterId, setComposerFilterId] = useState(undefined);
  const [composerIgnorePagination, setComposerIgnorePagination] =
    useState(undefined);
  const [composerIncludeOverrides, setComposerIncludeOverrides] =
    useState(undefined);
  const [composerStoreAsDefault, setComposerStoreAsDefault] =
    useState(NO_VALUE);
  const [credentials, setCredentials] = useState([]);
  const [resultFilters, setResultFilters] = useState([]);
  const [secinfoFilters, setSecinfoFilters] = useState([]);
  const [reportFormats, setReportFormats] = useState([]);
  const [reportConfigs, setReportConfigs] = useState([]);
  const [tasks, setTasks] = useState([]);
  const [title, setTitle] = useState('');

  const [condition, setCondition] = useState(undefined);
  const [conditionDataCount, setConditionDataCount] = useState(undefined);
  const [conditionDataDirection, setConditionDataDirection] =
    useState(undefined);
  const [conditionDataFilters, setConditionDataFilters] = useState(undefined);
  const [conditionDataFilterId, setConditionDataFilterId] = useState(undefined);
  const [conditionDataAtLeast, setConditionDataAtLeast] = useState([
    undefined,
    undefined,
  ]);
  const [conditionDataAtLeastFilterId, conditionDataAtLeastCount] =
    conditionDataAtLeast;
  const [conditionDataSeverity, setConditionDataSeverity] = useState(undefined);

  const [event, setEvent] = useState(undefined);
  const [eventDataStatus, setEventDataStatus] = useState(DEFAULT_EVENT_STATUS);
  const [eventDataFeedEvent, setEventDataFeedEvent] = useState(undefined);
  const [eventDataSecinfoType, setEventDataSecinfoType] = useState(undefined);

  const [method, setMethod] = useState(undefined);
  const [
    methodDataComposerIgnorePagination,
    setMethodDataComposerIgnorePagination,
  ] = useState(undefined);
  const [
    methodDataComposerIncludeOverrides,
    setMethodDataComposerIncludeOverrides,
  ] = useState(undefined);
  const [methodDataDetailsUrl, setMethodDataDetailsUrl] = useState(undefined);
  const [methodDataToAddress, setMethodDataToAddress] = useState(undefined);
  const [methodDataFromAddress, setMethodDataFromAddress] = useState(undefined);
  const [methodDataSubject, setMethodDataSubject] = useState(undefined);
  const [methodDataMessage, setMethodDataMessage] = useState(undefined);
  const [methodDataMessageAttach, setMethodDataMessageAttach] =
    useState(undefined);
  const [methodDataNotice, setMethodDataNotice] = useState(undefined);
  const [methodDataNoticeReportFormat, setMethodDataNoticeReportFormat] =
    useState(undefined);
  const [methodDataNoticeReportConfig, setMethodDataNoticeReportConfig] =
    useState(undefined);
  const [methodDataNoticeAttachFormat, setMethodDataNoticeAttachFormat] =
    useState(undefined);
  const [methodDataNoticeAttachConfig, setMethodDataNoticeAttachConfig] =
    useState(undefined);
  const [methodDataRecipientCredential, setMethodDataRecipientCredential] =
    useState(UNSET_VALUE);
  const [methodDataScpCredential, setMethodDataScpCredential] =
    useState(undefined);
  const [methodDataScpReportConfig, setMethodDataScpReportConfig] =
    useState(undefined);
  const [methodDataScpReportFormat, setMethodDataScpReportFormat] =
    useState(undefined);
  const [methodDataScpPath, setMethodDataScpPath] = useState(DEFAULT_SCP_PATH);
  const [methodDataScpHost, setMethodDataScpHost] = useState(undefined);
  const [methodDataScpPort, setMethodDataScpPort] = useState(22);
  const [methodDataScpKnownHosts, setMethodDataScpKnownHosts] =
    useState(undefined);
  const [methodDataSmbCredential, setMethodDataSmbCredential] =
    useState(undefined);
  const [methodDataSmbFilePath, setMethodDataSmbFilePath] = useState(undefined);
  const [methodDataSmbFilePathType, setMethodDataSmbFilePathType] =
    useState(undefined);
  const [methodDataSmbMaxProtocol, setMethodDataSmbMaxProtocol] =
    useState(undefined);
  const [methodDataSmbReportConfig, setMethodDataSmbReportConfig] =
    useState(undefined);
  const [methodDataSmbReportFormat, setMethodDataSmbReportFormat] =
    useState(undefined);
  const [methodDataSmbSharePath, setMethodDataSmbSharePath] =
    useState(undefined);
  const [methodDataSnmpAgent, setMethodDataSnmpAgent] = useState(undefined);
  const [methodDataSnmpCommunity, setMethodDataSnmpCommunity] =
    useState(undefined);
  const [methodDataSnmpMessage, setMethodDataSnmpMessage] = useState(undefined);
  const [methodDataStartTaskTask, setMethodDataStartTaskTask] =
    useState(undefined);

  const credentialTypeRef = useRef(null);

  const handleCreateCredential = credentialData => {
    let credentialId;
    return gmp.credential
      .create(credentialData)
      .then(response => {
        credentialId = response.data.id;
        setCredentialDialogVisible(false);
      })
      .then(() => fetchAlertCredentials(gmp))
      .then(newCredentials => {
        setCredentials(newCredentials);
        if (String(credentialTypeRef.current) === 'scp') {
          setMethodDataScpCredential(credentialId);
        } else if (String(credentialTypeRef.current) === 'smb') {
          setMethodDataSmbCredential(credentialId);
        } else if (String(credentialTypeRef.current) === 'email') {
          setMethodDataRecipientCredential(credentialId);
        }
      });
  };

  const openCredentialDialog = ({type, types}) => {
    credentialTypeRef.current = type;
    setCredentialDialogVisible(true);
    setCredentialDialogTitle(_('New Credential'));
    setCredentialTypes(types);
  };

  const closeCredentialDialog = () => {
    setCredentialDialogVisible(false);
  };

  const handleCloseCredentialDialog = () => {
    closeCredentialDialog();
  };

  const openContentComposerDialog = () => {
    setContentComposerDialogVisible(true);
  };

  const handleOpenContentComposerDialog = () => {
    openContentComposerDialog();
  };

  const closeContentComposerDialog = () => {
    setComposerIgnorePagination(methodDataComposerIgnorePagination);
    setComposerIncludeOverrides(methodDataComposerIncludeOverrides);
    setComposerFilterId(filterId);
    setComposerStoreAsDefault(NO_VALUE);
    setContentComposerDialogVisible(false);
  };

  const handleSaveComposerContent = ({
    ignorePagination,
    includeOverrides,
    filterId,
    storeAsDefault,
  }) => {
    if (storeAsDefault) {
      const defaults = {
        ...reportComposerDefaults,
        reportResultFilterId: filterId === UNSET_VALUE ? undefined : filterId,
        ignorePagination,
        includeOverrides,
      };
      saveDefaults(defaults);
    }

    setFilterId(filterId);
    setMethodDataComposerIgnorePagination(ignorePagination);
    setMethodDataComposerIncludeOverrides(includeOverrides);
    setComposerStoreAsDefault(NO_VALUE);
    setContentComposerDialogVisible(false);
  };

  const openScpCredentialDialog = types => {
    openCredentialDialog({type: 'scp', types});
  };

  const openSmbCredentialDialog = types => {
    openCredentialDialog({type: 'smb', types});
  };

  const openEmailCredentialDialog = types => {
    openCredentialDialog({type: 'email', types});
  };

  const openAlertDialog = async alertObj => {
    const credentialsPromise = fetchAlertCredentials(gmp);
    const lookupsPromise = fetchAlertDialogLookups(gmp);
    loadDefaults();

    if (isDefined(alertObj)) {
      const alertPromise = gmp.alert.get({id: alertObj.id}).then(r => r.data);
      const [credentials, lalert, lookups] = await Promise.all([
        credentialsPromise,
        alertPromise,
        lookupsPromise,
      ]);
      const {reportFormats, reportConfigs, filters, tasks} = lookups;
      const {method, condition, event} = lalert;

      const emailCredentials = credentials.filter(email_credential_filter);
      const resultFilters = filters.filter(filterResultsFilter);
      const secinfoFilters = filters.filter(filterSecinfoFilter);

      let conditionDataFilters;
      const conditionDataFilterId = getValue(condition.data.filter_id);

      let methodDataMessage;
      let methodDataMessageAttach;
      const methodDataNotice = getValue(method.data.notice, DEFAULT_NOTICE);

      let methodDataSubject;
      let feedEvent;
      let eventType = event.type;

      if (eventType === 'Task run status changed') {
        conditionDataFilters = resultFilters;
        methodDataSubject = getValue(method.data.subject, TASK_SUBJECT);

        if (methodDataNotice === NOTICE_ATTACH) {
          methodDataMessageAttach = getValue(
            method.data.message,
            ATTACH_MESSAGE_DEFAULT,
          );
          methodDataMessage = INCLUDE_MESSAGE_DEFAULT;
        } else {
          methodDataMessage = getValue(
            method.data.message,
            INCLUDE_MESSAGE_DEFAULT,
          );
          methodDataMessageAttach = ATTACH_MESSAGE_DEFAULT;
        }
      } else {
        conditionDataFilters = secinfoFilters;
        methodDataSubject = getValue(method.data.subject, SECINFO_SUBJECT);

        if (methodDataNotice === NOTICE_ATTACH) {
          methodDataMessageAttach = getValue(
            method.data.message,
            ATTACH_MESSAGE_SECINFO,
          );
          methodDataMessage = INCLUDE_MESSAGE_SECINFO;
        } else {
          methodDataMessage = getValue(
            method.data.message,
            INCLUDE_MESSAGE_SECINFO,
          );
          methodDataMessageAttach = ATTACH_MESSAGE_SECINFO;
        }
      }

      if (event.type === 'Updated SecInfo arrived') {
        eventType = 'New SecInfo arrived';
        feedEvent = 'updated';
      } else {
        feedEvent = 'new';
      }

      const scpCredentialId = isDefined(method.data.scp_credential)
        ? method.data.scp_credential.credential.id
        : undefined;

      const recipientCredentialId = isDefined(method.data.recipient_credential)
        ? getValue(method.data.recipient_credential)
        : undefined;

      setAlertDialogVisible(true);
      setId(alertObj.id);
      setAlert(alertObj);
      setActive(alertObj.active);
      setName(alertObj.name);
      setComment(alertObj.comment);
      setFilters(filters);
      setFilterId(isDefined(alertObj.filter) ? alertObj.filter.id : undefined);
      setComposerFilterId(
        isDefined(alertObj.filter) ? alertObj.filter.id : undefined,
      );
      setComposerIgnorePagination(
        getValue(method.data.composer_ignore_pagination),
      );
      setComposerIncludeOverrides(
        getValue(method.data.composer_include_overrides),
      );
      setComposerStoreAsDefault(NO_VALUE);
      setCredentials(credentials);
      setResultFilters(resultFilters);
      setSecinfoFilters(secinfoFilters);
      setReportFormats(reportFormats);
      setReportConfigs(reportConfigs);

      setCondition(condition.type);
      setConditionDataCount(parseInt(getValue(condition.data.count, 1)));
      setConditionDataDirection(
        getValue(condition.data.direction, DEFAULT_DIRECTION),
      );
      setConditionDataFilters(conditionDataFilters);
      setConditionDataFilterId(conditionDataFilterId);
      setConditionDataAtLeast([
        conditionDataFilterId,
        parseInt(getValue(condition.data.count, 1)),
      ]);
      setConditionDataSeverity(
        parseSeverity(getValue(condition.data.severity, DEFAULT_SEVERITY)),
      );

      setEvent(eventType);
      setEventDataStatus(getValue(event.data.status, DEFAULT_EVENT_STATUS));
      setEventDataFeedEvent(feedEvent);
      setEventDataSecinfoType(
        getValue(event.data.secinfo_type, DEFAULT_SECINFO_TYPE),
      );

      setMethod(alertObj.method.type);

      setMethodDataComposerIgnorePagination(
        getValue(method.data.composer_ignore_pagination),
      );
      setMethodDataComposerIncludeOverrides(
        getValue(method.data.composer_include_overrides),
      );
      setMethodDataDetailsUrl(
        getValue(method.data.details_url, DEFAULT_DETAILS_URL),
      );
      setMethodDataRecipientCredential(
        selectSaveId(emailCredentials, recipientCredentialId, UNSET_VALUE),
      );
      setMethodDataToAddress(getValue(alertObj.method.data.to_address, ''));
      setMethodDataFromAddress(getValue(alertObj.method.data.from_address, ''));
      setMethodDataSubject(methodDataSubject);
      setMethodDataMessage(methodDataMessage);
      setMethodDataMessageAttach(methodDataMessageAttach);
      setMethodDataNotice(methodDataNotice);
      setMethodDataNoticeReportFormat(
        selectSaveId(
          reportFormats,
          getValue(
            method.data.notice_report_format,
            DEFAULT_NOTICE_REPORT_FORMAT,
          ),
        ),
      );
      setMethodDataNoticeReportConfig(
        selectSaveId(
          reportConfigs,
          getValue(method.data.notice_report_config, UNSET_VALUE),
          UNSET_VALUE,
        ),
      );
      setMethodDataNoticeAttachFormat(
        selectSaveId(
          reportFormats,
          getValue(
            method.data.notice_attach_format,
            DEFAULT_NOTICE_ATTACH_FORMAT,
          ),
        ),
      );
      setMethodDataNoticeAttachConfig(
        selectSaveId(
          reportConfigs,
          getValue(method.data.notice_attach_config, UNSET_VALUE),
          UNSET_VALUE,
        ),
      );
      setMethodDataScpCredential(selectSaveId(credentials, scpCredentialId));
      setMethodDataScpReportConfig(
        selectSaveId(
          reportConfigs,
          getValue(method.data.scp_report_config, UNSET_VALUE),
          UNSET_VALUE,
        ),
      );
      setMethodDataScpReportFormat(
        selectSaveId(reportFormats, getValue(method.data.scp_report_format)),
      );
      setMethodDataScpPath(getValue(method.data.scp_path, DEFAULT_SCP_PATH));
      setMethodDataScpHost(getValue(method.data.scp_host, ''));
      setMethodDataScpPort(getValue(method.data.scp_port, 22));
      setMethodDataScpKnownHosts(getValue(method.data.scp_known_hosts, ''));
      setMethodDataSmbCredential(getValue(method.data.smb_credential, ''));
      setMethodDataSmbFilePath(getValue(method.data.smb_file_path, ''));
      setMethodDataSmbFilePathType(
        getValue(method.data.smb_file_path_type, ''),
      );
      setMethodDataSmbMaxProtocol(getValue(method.data.smb_max_protocol, ''));
      setMethodDataSmbReportConfig(
        selectSaveId(
          reportConfigs,
          getValue(method.data.smb_report_config, UNSET_VALUE),
          UNSET_VALUE,
        ),
      );
      setMethodDataSmbReportFormat(
        selectSaveId(reportFormats, getValue(method.data.smb_report_format)),
      );
      setMethodDataSmbSharePath(getValue(method.data.smb_share_path, ''));
      setMethodDataSnmpAgent(getValue(method.data.snmp_agent, ''));
      setMethodDataSnmpCommunity(getValue(method.data.snmp_community, ''));
      setMethodDataSnmpMessage(getValue(method.data.snmp_message, ''));
      setMethodDataStartTaskTask(
        selectSaveId(tasks, getValue(method.data.start_task_task)),
      );
      setTasks(tasks);
      setTitle(_('Edit Alert {{- name}}', {name: shorten(alertObj.name)}));
    } else {
      const [credentials, lookups] = await Promise.all([
        credentialsPromise,
        lookupsPromise,
      ]);
      const {reportFormats, reportConfigs, filters, tasks} = lookups;
      const resultFilters = filters.filter(filterResultsFilter);
      const secinfoFilters = filters.filter(filterSecinfoFilter);
      const smbCredentials = credentials.filter(smb_credential_filter);

      const resultFilterId = selectSaveId(resultFilters);
      const reportFormatId = selectSaveId(reportFormats);
      const reportConfigId = UNSET_VALUE;

      const filterId = isDefined(reportComposerDefaults.reportResultFilterId)
        ? reportComposerDefaults.reportResultFilterId
        : undefined;

      setActive(undefined);
      setAlert(undefined);
      setAlertDialogVisible(true);
      setName(undefined);
      setComment(undefined);
      setCondition(undefined);
      setConditionDataAtLeast([resultFilterId, undefined]);
      setConditionDataCount(undefined);
      setConditionDataDirection(undefined);
      setConditionDataFilters(resultFilters);
      setConditionDataFilterId(resultFilterId);
      setConditionDataSeverity(undefined);
      setCredentials(credentials);
      setEvent(undefined);
      setEventDataStatus(DEFAULT_EVENT_STATUS);
      setEventDataFeedEvent(undefined);
      setEventDataSecinfoType(undefined);
      setFilterId(filterId);
      setFilters(filters);
      setComposerFilterId(reportComposerDefaults.reportResultFilterId);
      setComposerIgnorePagination(reportComposerDefaults.ignorePagination);
      setComposerIncludeOverrides(reportComposerDefaults.includeOverrides);
      setComposerStoreAsDefault(NO_VALUE);
      setId(undefined);
      setMethod(undefined);
      setMethodDataComposerIgnorePagination(undefined);
      setMethodDataComposerIncludeOverrides(undefined);
      setMethodDataDetailsUrl(undefined);
      setMethodDataToAddress(undefined);
      setMethodDataFromAddress(undefined);
      setMethodDataSubject(undefined);
      setMethodDataMessage(undefined);
      setMethodDataMessageAttach(undefined);
      setMethodDataNotice(undefined);
      setMethodDataNoticeReportFormat(
        selectSaveId(reportFormats, DEFAULT_NOTICE_REPORT_FORMAT),
      );
      setMethodDataNoticeReportConfig(undefined);
      setMethodDataNoticeAttachFormat(
        selectSaveId(reportFormats, DEFAULT_NOTICE_ATTACH_FORMAT),
      );
      setMethodDataNoticeAttachConfig(undefined);
      setMethodDataScpCredential(undefined);
      setMethodDataScpPath(DEFAULT_SCP_PATH);
      setMethodDataScpReportConfig(reportConfigId);
      setMethodDataScpReportFormat(reportFormatId);
      setMethodDataScpHost(undefined);
      setMethodDataScpPort(22);
      setMethodDataScpKnownHosts(undefined);
      setMethodDataSnmpAgent(undefined);
      setMethodDataSnmpCommunity(undefined);
      setMethodDataSnmpMessage(undefined);
      setMethodDataRecipientCredential(UNSET_VALUE);
      setMethodDataStartTaskTask(selectSaveId(tasks));
      setMethodDataSmbCredential(selectSaveId(smbCredentials));
      setMethodDataSmbSharePath(undefined);
      setMethodDataSmbFilePath(undefined);
      setMethodDataSmbFilePathType(undefined);
      setMethodDataSmbReportConfig(reportConfigId);
      setMethodDataSmbReportFormat(reportFormatId);
      setResultFilters(resultFilters);
      setSecinfoFilters(secinfoFilters);
      setReportFormats(reportFormats);
      setReportConfigs(reportConfigs);
      setTasks(tasks);
      setTitle(_('New Alert'));
    }
  };

  const closeAlertDialog = () => {
    setAlertDialogVisible(false);
  };

  const handleCloseAlertDialog = () => {
    setComposerIgnorePagination(undefined);
    setComposerIncludeOverrides(undefined);
    setComposerFilterId(undefined);
    setComposerStoreAsDefault(NO_VALUE);
    closeAlertDialog();
  };

  const handleTestAlert = alertObj => {
    return gmp.alert
      .test(alertObj)
      .then(() => {
        if (isDefined(onTestSuccess)) {
          onTestSuccess(
            _('Testing the alert {{name}} was successful.', alertObj),
          );
        }
      })
      .catch(
        response => {
          const {details, message} = response;
          if (isDefined(onTestError)) {
            if (isDefined(details)) {
              onTestError(
                <>
                  <p>
                    {_('Testing the alert {{name}} failed. {{message}}.', {
                      name: alertObj.name,
                      message,
                    })}
                  </p>
                  <FootNote>{details}</FootNote>
                </>,
              );
            } else {
              onTestError(
                _('Testing the alert {{name}} failed. {{message}}.', {
                  name: alertObj.name,
                  message,
                }),
              );
            }
          }
        },
        () => {
          if (isDefined(onTestError)) {
            onTestError(
              _(
                'An error occurred during Testing the alert {{name}}',
                alertObj,
              ),
            );
          }
        },
      );
  };

  const handleScpCredentialChange = credential => {
    setMethodDataScpCredential(credential);
  };

  const handleSmbCredentialChange = credential => {
    setMethodDataSmbCredential(credential);
  };

  const handleEmailCredentialChange = credential => {
    setMethodDataRecipientCredential(credential);
  };

  const handleValueChange = (value, name) => {
    name = capitalizeFirstLetter(name);

    if (name === 'IgnorePagination') {
      setComposerIgnorePagination(value);
    } else if (name === 'IncludeOverrides') {
      setComposerIncludeOverrides(value);
    } else if (name === 'StoreAsDefault') {
      setComposerStoreAsDefault(value);
    }
  };

  const handleFilterIdChange = value => {
    setComposerFilterId(value === UNSET_VALUE ? undefined : value);
  };

  return (
    <EntityComponent
      name="alert"
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
        <Layout>
          {children({
            ...other,
            create: openAlertDialog,
            edit: openAlertDialog,
            test: handleTestAlert,
          })}
          {alertDialogVisible && (
            <AlertDialog
              active={active}
              alert={alert}
              comment={comment}
              condition={condition}
              condition_data_at_least_count={conditionDataAtLeastCount}
              condition_data_at_least_filter_id={conditionDataAtLeastFilterId}
              condition_data_count={conditionDataCount}
              condition_data_direction={conditionDataDirection}
              condition_data_filter_id={conditionDataFilterId}
              condition_data_filters={conditionDataFilters}
              condition_data_severity={conditionDataSeverity}
              credentials={credentials}
              event={event}
              event_data_feed_event={eventDataFeedEvent}
              event_data_secinfo_type={eventDataSecinfoType}
              event_data_status={eventDataStatus}
              filter_id={filterId}
              filters={filters}
              id={id}
              method={method}
              method_data_composer_ignore_pagination={
                methodDataComposerIgnorePagination
              }
              method_data_composer_include_overrides={
                methodDataComposerIncludeOverrides
              }
              method_data_details_url={methodDataDetailsUrl}
              method_data_from_address={methodDataFromAddress}
              method_data_message={methodDataMessage}
              method_data_message_attach={methodDataMessageAttach}
              method_data_notice={methodDataNotice}
              method_data_notice_attach_config={methodDataNoticeAttachConfig}
              method_data_notice_attach_format={methodDataNoticeAttachFormat}
              method_data_notice_report_config={methodDataNoticeReportConfig}
              method_data_notice_report_format={methodDataNoticeReportFormat}
              method_data_recipient_credential={methodDataRecipientCredential}
              method_data_scp_credential={methodDataScpCredential}
              method_data_scp_host={methodDataScpHost}
              method_data_scp_known_hosts={methodDataScpKnownHosts}
              method_data_scp_path={methodDataScpPath}
              method_data_scp_port={methodDataScpPort}
              method_data_scp_report_config={methodDataScpReportConfig}
              method_data_scp_report_format={methodDataScpReportFormat}
              method_data_smb_credential={methodDataSmbCredential}
              method_data_smb_file_path={methodDataSmbFilePath}
              method_data_smb_file_path_type={methodDataSmbFilePathType}
              method_data_smb_max_protocol={methodDataSmbMaxProtocol}
              method_data_smb_report_config={methodDataSmbReportConfig}
              method_data_smb_report_format={methodDataSmbReportFormat}
              method_data_smb_share_path={methodDataSmbSharePath}
              method_data_snmp_agent={methodDataSnmpAgent}
              method_data_snmp_community={methodDataSnmpCommunity}
              method_data_snmp_message={methodDataSnmpMessage}
              method_data_start_task_task={methodDataStartTaskTask}
              method_data_subject={methodDataSubject}
              method_data_to_address={methodDataToAddress}
              name={name}
              report_configs={reportConfigs}
              report_formats={reportFormats}
              result_filters={resultFilters}
              secinfo_filters={secinfoFilters}
              tasks={tasks}
              title={title}
              onClose={handleCloseAlertDialog}
              onEmailCredentialChange={handleEmailCredentialChange}
              onNewEmailCredentialClick={openEmailCredentialDialog}
              onNewScpCredentialClick={openScpCredentialDialog}
              onNewSmbCredentialClick={openSmbCredentialDialog}
              onOpenContentComposerDialogClick={handleOpenContentComposerDialog}
              onSave={d => {
                const promise = isDefined(d.id) ? save(d) : create(d);
                return promise.then(() => closeAlertDialog());
              }}
              onScpCredentialChange={handleScpCredentialChange}
              onSmbCredentialChange={handleSmbCredentialChange}
            />
          )}
          {credentialDialogVisible && (
            <CredentialDialog
              title={credentialDialogTitle}
              types={credentialTypes}
              onClose={handleCloseCredentialDialog}
              onSave={handleCreateCredential}
            />
          )}
          {contentComposerDialogVisible && (
            <ContentComposerDialog
              filterId={composerFilterId}
              filters={resultFilters}
              ignorePagination={parseYesNo(composerIgnorePagination)}
              includeOverrides={parseYesNo(composerIncludeOverrides)}
              storeAsDefault={parseYesNo(composerStoreAsDefault)}
              title={_('Compose Content for Scan Report')}
              onChange={handleValueChange}
              onClose={closeContentComposerDialog}
              onFilterIdChange={handleFilterIdChange}
              onSave={handleSaveComposerContent}
            />
          )}
        </Layout>
      )}
    </EntityComponent>
  );
};

AlertComponent.propTypes = {
  children: PropTypes.func.isRequired,
  onCloneError: PropTypes.func,
  onCloned: PropTypes.func,
  onCreateError: PropTypes.func,
  onCreated: PropTypes.func,
  onDeleteError: PropTypes.func,
  onDeleted: PropTypes.func,
  onDownloadError: PropTypes.func,
  onDownloaded: PropTypes.func,
  onError: PropTypes.func,
  onSaveError: PropTypes.func,
  onSaved: PropTypes.func,
  onTestError: PropTypes.func,
  onTestSuccess: PropTypes.func,
};

export default AlertComponent;
