/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/* eslint-disable @typescript-eslint/naming-convention */

import FeedStatusCommand from 'gmp/native-api/feeds';
import type Http from 'gmp/http/http';
import Response from 'gmp/http/response';
import logger from 'gmp/log';
import {type ScannerType} from 'gmp/models/scanner';
import Task, {
  HOSTS_ORDERING_RANDOM,
  DEFAULT_MAX_CHECKS,
  DEFAULT_MAX_HOSTS,
  DEFAULT_MIN_QOD,
  type TaskHostsOrdering,
} from 'gmp/models/task';
import {
  cloneNativeTask,
  createNativeTask,
  deleteNativeTask,
  exportNativeTaskMetadata,
  fetchNativeTask,
  patchNativeTask,
  replaceNativeTaskConfiguration,
  startNativeTask,
  stopNativeTask,
} from 'gmp/native-api/tasks';
import {NO_VALUE, YES_VALUE, type YesNo} from 'gmp/parser';

interface TaskCommandParams {
  id: string;
}

interface TaskCommandCreateParams {
  add_tag?: YesNo;
  alert_ids?: string[];
  apply_overrides?: YesNo;
  comment?: string;
  config_id?: string;
  max_checks?: number;
  max_hosts?: number;
  min_qod?: number;
  name: string;
  scanner_type?: ScannerType;
  scanner_id?: string;
  schedule_id?: string;
  schedule_periods?: number;
  tag_id?: string;
  target_id?: string;
}

interface TaskCommandSaveParams {
  alert_ids?: string[];
  apply_overrides?: YesNo;
  comment?: string;
  config_id?: string;
  id: string;
  hosts_ordering?: TaskHostsOrdering;
  max_checks?: number;
  max_hosts?: number;
  min_qod?: number;
  name: string;
  scanner_id?: string;
  scanner_type?: ScannerType;
  schedule_id?: string;
  schedule_periods?: number;
  target_id?: string;
}

const log = logger.getLogger('gmp.native-api.task-command');

const NO_VALUE_ID = String(NO_VALUE);
const TASK_METADATA_SAVE_KEYS = new Set(['id', 'name', 'comment']);

const requiredTaskReference = (value: string | undefined, field: string) => {
  if (value === undefined || value === NO_VALUE_ID || value === '0') {
    throw new Error(`${field} is required`);
  }
  return value;
};

const optionalTaskReference = (value: string | undefined) =>
  value === undefined || value === NO_VALUE_ID || value === '0'
    ? undefined
    : value;

const isTaskMetadataOnlySave = (args: TaskCommandSaveParams) => {
  const keys = Object.keys(args);
  return (
    keys.every(key => TASK_METADATA_SAVE_KEYS.has(key)) &&
    typeof args.id === 'string' &&
    typeof args.name === 'string' &&
    (args.comment === undefined || typeof args.comment === 'string')
  );
};

class TaskCommand {
  private readonly http: Http;

  constructor(http: Http) {
    this.http = http;
  }

  async get({id}: TaskCommandParams) {
    const {task} = await fetchNativeTask(this.http, id);
    return new Response<Task>(task);
  }

  async export({id}: TaskCommandParams) {
    return await exportNativeTaskMetadata(this.http, id);
  }

  async clone({id}: TaskCommandParams) {
    return await cloneNativeTask(this.http, id);
  }

  async delete({id}: TaskCommandParams) {
    await deleteNativeTask(this.http, id);
  }

  async start({id}: TaskCommandParams) {
    log.debug('Starting task...');

    try {
      const feeds = new FeedStatusCommand(this.http);

      const status = await feeds.checkFeedSync();

      if (status.isSyncing) {
        throw new Error('Feed is currently syncing. Please try again later.');
      }

      await startNativeTask(this.http, id);

      log.debug('Started task');
    } catch (error) {
      log.error('An error occurred while starting the task', id, error);
      throw error;
    }
  }

  async stop({id}: TaskCommandParams) {
    log.debug('Stopping task');

    try {
      await stopNativeTask(this.http, id);
      log.debug('Stopped task');
      return await this.get({id});
    } catch (err) {
      log.error('An error occurred while stopping the task', id, err);
      throw err;
    }
  }

  async create({
    add_tag,
    alert_ids = [],
    apply_overrides,
    comment = '',
    config_id,
    max_checks,
    max_hosts,
    min_qod,
    name,
    scanner_id,
    schedule_id,
    schedule_periods,
    tag_id,
    target_id,
  }: TaskCommandCreateParams) {
    return createNativeTask(this.http, {
      name,
      comment,
      targetId: requiredTaskReference(target_id, 'target_id'),
      configId: requiredTaskReference(config_id, 'config_id'),
      scannerId: requiredTaskReference(scanner_id, 'scanner_id'),
      scheduleId: optionalTaskReference(schedule_id),
      schedulePeriods: schedule_periods ?? 0,
      alertIds: alert_ids,
      applyOverrides: apply_overrides !== NO_VALUE,
      maxChecks: max_checks ?? DEFAULT_MAX_CHECKS,
      maxHosts: max_hosts ?? DEFAULT_MAX_HOSTS,
      minQod: min_qod ?? DEFAULT_MIN_QOD,
      hostsOrdering: HOSTS_ORDERING_RANDOM,
      tagId: add_tag === YES_VALUE ? optionalTaskReference(tag_id) : undefined,
    });
  }

  async save(args: TaskCommandSaveParams) {
    if (isTaskMetadataOnlySave(args)) {
      return patchNativeTask(this.http, {
        id: args.id,
        name: args.name,
        comment: args.comment,
      });
    }
    return replaceNativeTaskConfiguration(this.http, args.id, {
      name: args.name,
      comment: args.comment,
      targetId: requiredTaskReference(args.target_id, 'target_id'),
      configId: requiredTaskReference(args.config_id, 'config_id'),
      scannerId: requiredTaskReference(args.scanner_id, 'scanner_id'),
      scheduleId: optionalTaskReference(args.schedule_id),
      schedulePeriods: args.schedule_periods ?? 0,
      alertIds: args.alert_ids ?? [],
      applyOverrides: args.apply_overrides !== NO_VALUE,
      maxChecks: args.max_checks ?? DEFAULT_MAX_CHECKS,
      maxHosts: args.max_hosts ?? DEFAULT_MAX_HOSTS,
      minQod: args.min_qod ?? DEFAULT_MIN_QOD,
      hostsOrdering: args.hosts_ordering ?? HOSTS_ORDERING_RANDOM,
    });
  }
}

export default TaskCommand;
