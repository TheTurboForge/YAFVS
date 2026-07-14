/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import React, {useState, useEffect, useCallback} from 'react';
import {useDispatch} from 'react-redux';
import {type EntityCommandParams} from 'gmp/commands/entity';
import type Rejection from 'gmp/http/rejection';
import {
  exportNativeTaskMetadata,
  isNativeTaskMutationOutcomeUncertain,
} from 'gmp/native-api/tasks';
import {ALL_FILTER} from 'gmp/models/filter';
import {FULL_AND_FAST_SCAN_CONFIG_ID} from 'gmp/models/scan-config';
import {OPENVAS_DEFAULT_SCANNER_ID} from 'gmp/models/scanner';
import type Task from 'gmp/models/task';
import {NO_VALUE, YES_VALUE, type YesNo} from 'gmp/parser';
import {map} from 'gmp/utils/array';
import {isDefined} from 'gmp/utils/identity';
import actionFunction from 'web/entity/hooks/action-function';
import useEntityClone, {
  type EntityCloneResponse,
} from 'web/entity/hooks/useEntityClone';
import {type EntityCreateResponse} from 'web/entity/hooks/useEntityCreate';
import useEntityDelete from 'web/entity/hooks/useEntityDelete';
import useEntityDownload, {
  type OnDownloadedFunc,
} from 'web/entity/hooks/useEntityDownload';
import useGmp from 'web/hooks/useGmp';
import useShallowEqualSelector from 'web/hooks/useShallowEqualSelector';
import useTranslation from 'web/hooks/useTranslation';
import AlertComponent from 'web/pages/alerts/AlertComponent';
import ScheduleComponent from 'web/pages/schedules/ScheduleComponent';
import TargetComponent from 'web/pages/targets/TargetComponent';
import TaskDialog, {type TaskDialogData} from 'web/pages/tasks/TaskDialog';
import {
  loadEntities as loadAlerts,
  selector as alertSelector,
} from 'web/store/entities/alerts';
import {
  loadEntities as loadScanConfigs,
  selector as scanConfigsSelector,
} from 'web/store/entities/scanconfigs';
import {
  loadEntities as loadScanners,
  selector as scannerSelector,
} from 'web/store/entities/scanners';
import {
  loadEntities as loadSchedules,
  selector as scheduleSelector,
} from 'web/store/entities/schedules';
import {
  loadEntities as loadTags,
  selector as tagsSelector,
} from 'web/store/entities/tags';
import {
  loadEntities as loadTargets,
  selector as targetSelector,
} from 'web/store/entities/targets';
import {loadUserSettingDefaults} from 'web/store/usersettings/defaults/actions';
import {getUserSettingsDefaults} from 'web/store/usersettings/defaults/selectors';
import {UNSET_VALUE} from 'web/utils/Render';

interface TaskComponentRenderProps {
  create: () => void;
  clone: (task: Task) => void;
  delete: (task: Task) => void;
  download: (task: Task) => void;
  edit: (task: Task) => void;
  start: (task: Task) => void;
  stop: (task: Task) => void;
}

interface TaskComponentProps {
  children?: (props: TaskComponentRenderProps) => React.ReactNode;
  onCloned?: (response: EntityCloneResponse) => void;
  onCloneError?: (error: Error) => void;
  onCreated?: (response: EntityCreateResponse) => void;
  onCreateError?: (error: Error) => void;
  onDeleted?: () => void;
  onDeleteError?: (error: Error) => void;
  onDownloaded?: OnDownloadedFunc;
  onDownloadError?: (error: Error) => void;
  onSaved?: () => void;
  onSaveError?: (error: Error) => void;
  onStarted?: () => void;
  onStartError?: (error: Error) => void;
  onStopError?: (error: Error) => void;
  onStopped?: () => void;
}

const TAGS_FILTER = ALL_FILTER.copy().set('resource_type', 'task');

const canUseNativeApi = (gmp: {buildUrl?: unknown}) =>
  typeof gmp?.buildUrl === 'function';

const valueToString = (value: unknown): string | undefined =>
  isDefined(value) ? String(value) : undefined;

const scalarEquals = (left: unknown, right: unknown): boolean =>
  valueToString(left) === valueToString(right);

const idEquals = (left: unknown, right: unknown): boolean =>
  scalarEquals(left, right);

const scheduleIdEquals = (left: unknown, right: unknown): boolean =>
  scalarEquals(left ?? UNSET_VALUE, right ?? UNSET_VALUE);

const numericEquals = (left: unknown, right: unknown): boolean => {
  if (!isDefined(left) && !isDefined(right)) {
    return true;
  }
  if (!isDefined(left) || !isDefined(right)) {
    return false;
  }
  const leftNumber = Number(left);
  const rightNumber = Number(right);
  return (
    Number.isFinite(leftNumber) &&
    Number.isFinite(rightNumber) &&
    leftNumber === rightNumber
  );
};

const alertIdsFromTask = (task: Task): string[] =>
  map(task.alerts, alert => alert.id as string);

const alertIdsEqual = (left: string[] = [], right: string[] = []): boolean =>
  left.length === right.length &&
  left.every((id, index) => id === right[index]);

export const isTaskMetadataOnlyDialogSave = ({
  alert_ids: alertIds = [],
  apply_overrides: applyOverrides,
  config_id: configId,
  max_checks: maxChecks,
  max_hosts: maxHosts,
  min_qod: minQod,
  scanner_id: scannerId,
  scanner_type: scannerType,
  schedule_id: scheduleId,
  schedule_periods: schedulePeriods,
  target_id: targetId,
  task,
}: TaskDialogData): boolean => {
  if (!isDefined(task?.id)) {
    return false;
  }

  return (
    alertIdsEqual(alertIds, alertIdsFromTask(task)) &&
    idEquals(configId, task.config?.id) &&
    idEquals(scannerId, task.scanner?.id) &&
    scalarEquals(scannerType, task.scanner?.scannerType) &&
    scheduleIdEquals(scheduleId, task.schedule?.id) &&
    numericEquals(
      schedulePeriods ?? NO_VALUE,
      task.schedule_periods ?? NO_VALUE,
    ) &&
    idEquals(targetId, task.target?.id) &&
    scalarEquals(applyOverrides, task.apply_overrides) &&
    numericEquals(maxChecks, task.max_checks) &&
    numericEquals(maxHosts, task.max_hosts) &&
    numericEquals(minQod, task.min_qod)
  );
};

const exportTask = (gmp: any, task: EntityCommandParams) => {
  return exportNativeTaskMetadata(gmp, task.id as string);
};

const TaskComponent = ({
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
  onStarted,
  onStartError,
  onStopError,
  onStopped,
}: TaskComponentProps) => {
  const gmp = useGmp();
  const [_] = useTranslation();
  const dispatch = useDispatch();

  const [taskDialogVisible, setTaskDialogVisible] = useState(false);

  const [alertIds, setAlertIds] = useState<string[]>([]);
  const [applyOverrides, setApplyOverrides] = useState<YesNo | undefined>();
  const [comment, setComment] = useState<string | undefined>();
  const [scanConfigId, setScanConfigId] = useState<string | undefined>();
  const [maxChecks, setMaxChecks] = useState<number | undefined>();
  const [maxHosts, setMaxHosts] = useState<number | undefined>();
  const [minQod, setMinQod] = useState<number | undefined>();
  const [name, setName] = useState<string | undefined>();
  const [scannerId, setScannerId] = useState<string | undefined>();
  const [scheduleId, setScheduleId] = useState<string | undefined>();
  const [schedulePeriods, setSchedulePeriods] = useState<number | undefined>();
  const [targetId, setTargetId] = useState<string | undefined>();
  const [task, setTask] = useState<Task | undefined>();
  const [title, setTitle] = useState<string>('');

  const userDefaultsSelector = useShallowEqualSelector(getUserSettingsDefaults);

  const alerts = useShallowEqualSelector(state =>
    alertSelector(state).getEntities(ALL_FILTER),
  );

  const targets = useShallowEqualSelector(state =>
    targetSelector(state).getEntities(ALL_FILTER),
  );

  const schedules = useShallowEqualSelector(state =>
    scheduleSelector(state).getEntities(ALL_FILTER),
  );

  const scanConfigs = useShallowEqualSelector(state =>
    scanConfigsSelector(state).getEntities(ALL_FILTER),
  );

  const scanners = useShallowEqualSelector(state =>
    scannerSelector(state).getEntities(ALL_FILTER),
  );

  const tags = useShallowEqualSelector(state =>
    tagsSelector(state).getEntities(TAGS_FILTER),
  );

  const defaultAlertId = userDefaultsSelector.getValueByName('defaultalert');

  const defaultScheduleId =
    userDefaultsSelector.getValueByName('defaultschedule');

  const defaultTargetId = userDefaultsSelector.getValueByName('defaulttarget');

  const defaultScanConfigId = userDefaultsSelector.getValueByName(
    'defaultopenvasscanconfig',
  );

  const defaultScannerId = userDefaultsSelector.getValueByName(
    'defaultopenvasscanner',
  );

  const isLoadingAlerts = useShallowEqualSelector(state =>
    alertSelector(state).isLoadingAllEntities(ALL_FILTER),
  );

  const isLoadingTargets = useShallowEqualSelector(state =>
    targetSelector(state).isLoadingAllEntities(ALL_FILTER),
  );

  const isLoadingSchedules = useShallowEqualSelector(state =>
    scheduleSelector(state).isLoadingAllEntities(ALL_FILTER),
  );

  const isLoadingScanners = useShallowEqualSelector(state =>
    scannerSelector(state).isLoadingAllEntities(ALL_FILTER),
  );

  const isLoadingTags = useShallowEqualSelector(state =>
    tagsSelector(state).isLoadingAllEntities(TAGS_FILTER),
  );

  const isLoadingConfigs = useShallowEqualSelector(state =>
    scanConfigsSelector(state).isLoadingAllEntities(ALL_FILTER),
  );

  const fetchAlerts = useCallback(
    // @ts-expect-error
    () => dispatch(loadAlerts(gmp)(ALL_FILTER)),
    [dispatch, gmp],
  );

  const fetchScanners = useCallback(() => {
    // @ts-expect-error
    dispatch(loadScanners(gmp)(ALL_FILTER));
  }, [dispatch, gmp]);

  const fetchSchedules = useCallback(() => {
    // @ts-expect-error
    dispatch(loadSchedules(gmp)(ALL_FILTER));
  }, [dispatch, gmp]);

  const fetchTargets = useCallback(() => {
    // @ts-expect-error
    dispatch(loadTargets(gmp)(ALL_FILTER));
  }, [dispatch, gmp]);

  const fetchTags = useCallback(() => {
    // @ts-expect-error
    dispatch(loadTags(gmp)(TAGS_FILTER));
  }, [dispatch, gmp]);

  const fetchScanConfigs = useCallback(() => {
    // @ts-expect-error
    dispatch(loadScanConfigs(gmp)(ALL_FILTER));
  }, [dispatch, gmp]);

  const fetchUserSettingsDefaults = useCallback(() => {
    // @ts-expect-error
    dispatch(loadUserSettingDefaults(gmp)());
  }, [dispatch, gmp]);

  useEffect(() => {
    fetchUserSettingsDefaults();
  }, [fetchUserSettingsDefaults]);

  const handleTargetChange = (targetId?: string) => {
    setTargetId(targetId);
  };

  const handleAlertsChange = (alertIds: string[]) => {
    setAlertIds(alertIds);
  };

  const handleScheduleChange = (scheduleId?: string) => {
    setScheduleId(scheduleId);
  };

  const handleTaskStart = (task: Task) => {
    const handleStartError = (error: Rejection) => {
      if (isNativeTaskMutationOutcomeUncertain(error)) {
        onStarted?.();
      }
      onStartError?.(error);
    };

    return actionFunction<void, Rejection>(
      // @ts-expect-error
      gmp.task.start(task),
      {
        onSuccess: onStarted,
        onError: handleStartError,
        successMessage: _('Task {{- name}} started successfully.', {
          name: task.name as string,
        }),
      },
    );
  };

  const handleTaskStop = (task: Task) => {
    return actionFunction<void, Rejection>(
      // @ts-expect-error
      gmp.task.stop(task),
      {
        onSuccess: onStopped,
        onError: onStopError,
        successMessage: _('Task {{- name}} stopped successfully.', {
          name: task.name as string,
        }),
      },
    );
  };

  const handleAlertCreated = (resp: {data: {id: string}}) => {
    const {data} = resp;

    fetchAlerts();
    setAlertIds(prevAlertIds => [data.id, ...prevAlertIds]);
  };

  const handleScheduleCreated = (resp: {data: {id?: string}}) => {
    const {data} = resp;

    fetchSchedules();

    setScheduleId(data.id);
  };

  const handleTargetCreated = (resp: {data: {id?: string}}) => {
    const {data} = resp;

    fetchTargets();

    setTargetId(data.id);
  };

  const handleSaveTask = (data: TaskDialogData) => {
    const {
      add_tag: addTag,
      alert_ids: alertIds,
      apply_overrides: applyOverrides,
      comment,
      config_id: configId,
      min_qod: minQod,
      max_checks: maxChecks,
      max_hosts: maxHosts,
      name,
      scanner_id: scannerId,
      scanner_type: scannerType,
      schedule_id: scheduleId,
      schedule_periods: schedulePeriods,
      tag_id: tagId,
      target_id: targetId,
      task,
    } = data;
    if (isDefined(task)) {
      if (canUseNativeApi(gmp) && isTaskMetadataOnlyDialogSave(data)) {
        return gmp.task
          .save({
            comment,
            id: task.id as string,
            name,
          })
          .then(onSaved, onSaveError)
          .then(() => closeTaskDialog());
      }
      return gmp.task
        .save({
          alert_ids: alertIds,
          apply_overrides: applyOverrides,
          comment,
          config_id: configId,
          id: task.id as string,
          hosts_ordering: task.hosts_ordering,
          max_checks: maxChecks,
          max_hosts: maxHosts,
          min_qod: minQod,
          name,
          scanner_id: scannerId,
          scanner_type: scannerType,
          schedule_id: scheduleId,
          schedule_periods: schedulePeriods,
          target_id: targetId,
        })
        .then(onSaved, onSaveError)
        .then(() => closeTaskDialog());
    }
    return gmp.task
      .create({
        add_tag: addTag,
        alert_ids: alertIds,
        apply_overrides: applyOverrides,
        comment,
        config_id: configId,
        max_checks: maxChecks,
        max_hosts: maxHosts,
        min_qod: minQod,
        name,
        scanner_type: scannerType,
        scanner_id: scannerId,
        schedule_id: scheduleId,
        schedule_periods: schedulePeriods,
        tag_id: tagId,
        target_id: targetId,
      })
      .then(onCreated, onCreateError)
      .then(() => closeTaskDialog());
  };

  const openTaskDialog = (task?: Task) => {
    openStandardTaskDialog(task);
  };

  const closeTaskDialog = () => {
    setTaskDialogVisible(false);
  };

  const openStandardTaskDialog = (task?: Task) => {
    fetchAlerts();
    fetchScanConfigs();
    fetchScanners();
    fetchSchedules();
    fetchTargets();
    fetchTags();

    if (isDefined(task)) {
      setName(task.name as string);
      setComment(task.comment);
      setApplyOverrides(task.apply_overrides);
      setMinQod(task.min_qod);
      setMaxChecks(task.max_checks);
      setMaxHosts(task.max_hosts);
      setScanConfigId(task.config?.id);
      setScannerId(task.scanner?.id);
      setScheduleId(task.schedule?.id ?? UNSET_VALUE);
      setSchedulePeriods(task.schedule_periods ?? NO_VALUE);
      setTargetId(task.target?.id);

      setAlertIds(map(task.alerts, alert => alert.id as string));

      setTask(task);
      setTitle(_('Edit Task {{- name}}', {name: task.name as string}));
    } else {
      setName(undefined);
      setComment(undefined);
      setApplyOverrides(undefined);
      setMinQod(undefined);
      setMaxChecks(undefined);
      setMaxHosts(undefined);
      setScanConfigId(defaultScanConfigId || FULL_AND_FAST_SCAN_CONFIG_ID);
      setScannerId(defaultScannerId || OPENVAS_DEFAULT_SCANNER_ID);
      setScheduleId(defaultScheduleId);
      setSchedulePeriods(undefined);
      setTargetId(defaultTargetId);
      setAlertIds(isDefined(defaultAlertId) ? [defaultAlertId] : []);
      setTask(undefined);
      setTitle(_('New Task'));
    }

    setTaskDialogVisible(true);
  };

  const handleScanConfigChange = (configId?: string) => {
    setScanConfigId(configId);
  };

  const handleScannerChange = (scannerId?: string) => {
    setScannerId(scannerId);
  };

  const handleCloseTaskDialog = () => {
    closeTaskDialog();
  };

  const handleEditTask = async (task: Task) => {
    await openTaskDialog(task);
  };

  const handleEntityDownload = useEntityDownload<Task>(
    entity => exportTask(gmp, entity),
    {
      onDownloadError,
      onDownloaded,
    },
  );

  const handleEntityDelete = useEntityDelete<Task>(
    entity => gmp.task.delete(entity),
    {
      onDeleteError,
      onDeleted,
    },
  );

  const handleEntityClone = useEntityClone<Task>(
    entity => gmp.task.clone(entity),
    {
      onCloneError,
      onCloned,
    },
  );

  return (
    <>
      {children &&
        children({
          clone: handleEntityClone,
          delete: handleEntityDelete,
          download: task => handleEntityDownload(task, {extension: 'json'}),
          create: openTaskDialog,
          edit: handleEditTask,
          start: handleTaskStart,
          stop: handleTaskStop,
        })}

      {taskDialogVisible && (
        <TargetComponent onCreated={handleTargetCreated}>
          {({create: createTarget}) => (
            // @ts-expect-error
            <AlertComponent onCreated={handleAlertCreated}>
              {({create: createAlert}) => (
                <ScheduleComponent onCreated={handleScheduleCreated}>
                  {({create: createSchedule}) => (
                    <TaskDialog
                      alert_ids={alertIds}
                      alerts={alerts}
                      apply_overrides={applyOverrides}
                      comment={comment}
                      config_id={scanConfigId}
                      isLoadingAlerts={isLoadingAlerts}
                      isLoadingConfigs={isLoadingConfigs}
                      isLoadingScanners={isLoadingScanners}
                      isLoadingSchedules={isLoadingSchedules}
                      isLoadingTags={isLoadingTags}
                      isLoadingTargets={isLoadingTargets}
                      max_checks={maxChecks}
                      max_hosts={maxHosts}
                      min_qod={minQod}
                      name={name}
                      scan_configs={scanConfigs}
                      scanner_id={scannerId}
                      scanners={scanners}
                      schedule_id={scheduleId}
                      schedule_periods={schedulePeriods}
                      schedules={schedules}
                      tags={tags}
                      target_id={targetId}
                      targets={targets}
                      task={task}
                      title={title}
                      onAlertsChange={handleAlertsChange}
                      onClose={handleCloseTaskDialog}
                      onNewAlertClick={createAlert}
                      onNewScheduleClick={createSchedule}
                      onNewTargetClick={createTarget}
                      onSave={handleSaveTask}
                      onScanConfigChange={handleScanConfigChange}
                      onScannerChange={handleScannerChange}
                      onScheduleChange={handleScheduleChange}
                      onTargetChange={handleTargetChange}
                    />
                  )}
                </ScheduleComponent>
              )}
            </AlertComponent>
          )}
        </TargetComponent>
      )}
    </>
  );
};

export default TaskComponent;
