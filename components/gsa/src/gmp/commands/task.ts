/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * Modified by TurboVAS contributors, 2026.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/* eslint-disable @typescript-eslint/naming-convention */

import EntityCommand, {type EntityCommandParams} from 'gmp/commands/entity';
import FeedStatusCommand, {feedStatusRejection} from 'gmp/commands/feed-status';
import type Http from 'gmp/http/http';
import {type ResponseRejection} from 'gmp/http/rejection';
import _ from 'gmp/locale';
import logger from 'gmp/log';
import {type Element} from 'gmp/models/model';
import {type ScannerType} from 'gmp/models/scanner';
import Task, {
  HOSTS_ORDERING_RANDOM,
  AUTO_DELETE_KEEP_DEFAULT_VALUE,
  type TaskElement,
  type TaskAutoDelete,
} from 'gmp/models/task';
import {NO_VALUE, YES_VALUE, parseYesNo, type YesNo} from 'gmp/parser';
import {isDefined} from 'gmp/utils/identity';

interface TaskCommandCreateParams {
  add_tag?: YesNo;
  alert_ids?: string[];
  alterable?: YesNo;
  apply_overrides?: YesNo;
  auto_delete?: TaskAutoDelete;
  auto_delete_data?: number;
  comment?: string;
  config_id?: string;
  csAllowFailedRetrieval?: boolean;
  in_assets?: YesNo;
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

export interface TaskCommandCreateImportTaskParams {
  name: string;
  comment?: string;
}

interface TaskCommandSaveParams {
  alert_ids?: string[];
  alterable?: YesNo;
  auto_delete?: TaskAutoDelete;
  auto_delete_data?: number;
  apply_overrides?: YesNo;
  comment?: string;
  config_id?: string;
  csAllowFailedRetrieval?: boolean;
  id: string;
  in_assets?: YesNo;
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

interface TaskCommandSaveImportTaskParams {
  name: string;
  comment?: string;
  in_assets?: YesNo;
  id: string;
}

const log = logger.getLogger('gmp.commands.tasks');

const NO_VALUE_ID = String(NO_VALUE);
const MANAGER_DAEMON_RESPONSE_FAILURE =
  'Failure to receive response from manager daemon';
const TASK_START_RESPONSE_FOLLOWUP = _(
  'The task start request may have changed scan state before the manager response failed. Refresh the task status and check the latest report before retrying.',
);

export const isTaskStartManagerResponseFailure = (error: unknown) =>
  error instanceof Error &&
  error.message.includes(MANAGER_DAEMON_RESPONSE_FAILURE);

const enrichTaskStartManagerResponseFailure = (error: unknown) => {
  if (
    !isTaskStartManagerResponseFailure(error) ||
    (error as Error).message.includes(TASK_START_RESPONSE_FOLLOWUP)
  ) {
    return;
  }
  const message = `${(error as Error).message}\n${TASK_START_RESPONSE_FOLLOWUP}`;
  if (
    typeof (error as {setMessage?: (message: string) => unknown}).setMessage ===
    'function'
  ) {
    (error as {setMessage: (message: string) => unknown}).setMessage(message);
  } else {
    (error as Error).message = message;
  }
};

class TaskCommand extends EntityCommand<Task, TaskElement> {
  constructor(http: Http) {
    super(http, 'task', Task);
  }

  async start({id}: EntityCommandParams) {
    log.debug('Starting task...');

    try {
      const feeds = new FeedStatusCommand(this.http);

      const status = await feeds.checkFeedSync();

      if (status.isSyncing) {
        throw new Error('Feed is currently syncing. Please try again later.');
      }

      await this.httpPostWithTransform({
        cmd: 'start_task',
        id,
      });

      log.debug('Started task');
    } catch (error) {
      enrichTaskStartManagerResponseFailure(error);
      log.error('An error occurred while starting the task', id, error);
      throw error;
    }
  }

  async stop({id}: EntityCommandParams) {
    log.debug('Stopping task');

    try {
      await this.httpPostWithTransform({
        cmd: 'stop_task',
        id,
      });
      log.debug('Stopped task');
      return await this.get({id});
    } catch (err) {
      log.error('An error occurred while stopping the task', id, err);
      throw err;
    }
  }

  async resume({id}: EntityCommandParams) {
    try {
      await this.httpPostWithTransform({
        cmd: 'resume_task',
        id,
      });
      log.debug('Resumed task');
      return await this.get({id});
    } catch (err) {
      log.error('An error occurred while resuming the task', id, err);
      throw err;
    }
  }

  async create({
    add_tag,
    alert_ids = [],
    alterable,
    apply_overrides,
    auto_delete,
    auto_delete_data,
    comment = '',
    config_id,
    csAllowFailedRetrieval,
    in_assets,
    max_checks,
    max_hosts,
    min_qod,
    name,
    scanner_type,
    scanner_id,
    schedule_id,
    schedule_periods,
    tag_id,
    target_id,
  }: TaskCommandCreateParams) {
    const data = {
      cmd: 'create_task',
      add_tag,
      'alert_ids:': alert_ids,
      alterable,
      apply_overrides,
      auto_delete,
      auto_delete_data,
      comment,
      config_id,
      cs_allow_failed_retrieval: isDefined(csAllowFailedRetrieval)
        ? parseYesNo(csAllowFailedRetrieval)
        : undefined,
      hosts_ordering: HOSTS_ORDERING_RANDOM,
      in_assets,
      max_checks,
      max_hosts,
      min_qod,
      name,
      scanner_id,
      scanner_type,
      schedule_id,
      schedule_periods,
      tag_id,
      target_id,
      usage_type: 'scan',
    };
    log.debug('Creating task', data);

    try {
      return await this.entityAction(data);
    } catch (error_) {
      await feedStatusRejection(this.http, error_ as ResponseRejection);
      throw error_;
    }
  }


  async createImportTask({
    name,
    comment = '',
  }: TaskCommandCreateImportTaskParams) {
    log.debug('Creating import task', name, comment);
    return await this.entityAction({
      cmd: 'create_import_task',
      auto_delete_data: AUTO_DELETE_KEEP_DEFAULT_VALUE,
      name,
      comment,
      usage_type: 'scan',
    });
  }

  async save({
    alert_ids = [],
    alterable,
    auto_delete,
    auto_delete_data,
    apply_overrides,
    comment = '',
    config_id = NO_VALUE_ID,
    csAllowFailedRetrieval,
    id,
    in_assets,
    max_checks,
    max_hosts,
    min_qod,
    name,
    scanner_id = NO_VALUE_ID,
    scanner_type,
    schedule_id = NO_VALUE_ID,
    schedule_periods,
    target_id = NO_VALUE_ID,
  }: TaskCommandSaveParams) {
    const data = {
      alterable,
      'alert_ids:': alert_ids,
      apply_overrides,
      auto_delete,
      auto_delete_data,
      comment,
      config_id,
      cmd: 'save_task',
      cs_allow_failed_retrieval: isDefined(csAllowFailedRetrieval)
        ? parseYesNo(csAllowFailedRetrieval)
        : undefined,
      hosts_ordering: HOSTS_ORDERING_RANDOM,
      in_assets,
      max_checks,
      max_hosts,
      min_qod,
      name,
      scanner_id,
      scanner_type,
      schedule_id,
      schedule_periods,
      target_id,
      task_id: id,
      usage_type: 'scan',
    };
    log.debug('Saving task', data);
    try {
      await this.httpPostWithTransform(data);
    } catch (rejection) {
      await feedStatusRejection(this.http, rejection as ResponseRejection);
    }
  }


  async saveImportTask({
    name,
    comment = '',
    in_assets = YES_VALUE,
    id,
  }: TaskCommandSaveImportTaskParams) {
    log.debug('Saving import task', {name, comment, in_assets, id});
    await this.httpPostWithTransform({
      cmd: 'save_import_task',
      name,
      comment,
      in_assets,
      auto_delete: 'no',
      auto_delete_data: AUTO_DELETE_KEEP_DEFAULT_VALUE,
      task_id: id,
      usage_type: 'scan',
    });
  }

  getElementFromRoot(root: Element): TaskElement {
    // @ts-expect-error
    return root.get_task.get_tasks_response.task;
  }
}

export default TaskCommand;
