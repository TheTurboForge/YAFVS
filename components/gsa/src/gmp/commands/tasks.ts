/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type CollectionCounts from 'gmp/collection/collection-counts';
import EntitiesCommand from 'gmp/commands/entities';
import {
  type HttpCommandInputParams,
  type HttpCommandOptions,
} from 'gmp/commands/http';
import {
  canUseNativeApi,
  filterFromCommandParams,
  nativeCollectionMeta,
  NATIVE_COMMAND_PAGE_SIZE,
} from 'gmp/commands/native';
import type Http from 'gmp/http/http';
import Response from 'gmp/http/response';
import type Filter from 'gmp/models/filter';
import {type Element} from 'gmp/models/model';
import Task, {type TaskElement} from 'gmp/models/task';
import {
  exportNativeTasksMetadata,
  fetchNativeTasks,
  nativeTaskQueryFromFilter,
} from 'gmp/native-api/tasks';
import {parseYesNo, type YesNo} from 'gmp/parser';
import {isDefined} from 'gmp/utils/identity';

interface GetTasksResponse extends Element {
  apply_overrides: YesNo;
  task: TaskElement | TaskElement[];
  filters: Filter;
  sort: {
    field: {
      __text: string;
      order: 'ascending' | 'descending';
    };
  };
  task_count: {
    __text: number;
    _filtered: number;
    _page: number;
  };
  tasks: {
    _start: number;
    _max: number;
  };
}

interface TasksCommandWithFilterParam {
  filter?: Filter;
}

interface TasksCommandGetParams {
  filter?: Filter | string;
  schedulesOnly?: boolean;
}

const shouldExportAllByFilter = filter => {
  const rows = Number.parseInt(String(filter.get('rows') ?? ''), 10);
  return Number.isFinite(rows) && rows < 0;
};

class TasksCommand extends EntitiesCommand<Task, GetTasksResponse> {
  constructor(http: Http) {
    super(http, 'task', Task);
  }

  getEntitiesResponse(root: Element): GetTasksResponse {
    // @ts-expect-error
    return root.get_tasks.get_tasks_response;
  }

  async get(
    {filter, schedulesOnly}: TasksCommandGetParams = {},
    options?: HttpCommandOptions,
  ) {
    if (canUseNativeApi(this.http) && !schedulesOnly) {
      const nativeFilter = filterFromCommandParams({filter});
      const nativeResponse = await fetchNativeTasks(
        this.http,
        nativeTaskQueryFromFilter(nativeFilter),
      );
      return new Response(nativeResponse.tasks, {
        filter: nativeFilter,
        counts: nativeResponse.counts,
      });
    }

    const params = {
      filter,
      usage_type: 'scan',
      schedules_only: isDefined(schedulesOnly)
        ? parseYesNo(schedulesOnly)
        : undefined,
    };
    const response = await this.httpGetWithTransform(params, options);
    const {
      entities,
      filter: responseFilter,
      counts,
    } = this.getCollectionListFromRoot(response.data);
    return response.set<Task[], {filter: Filter; counts: CollectionCounts}>(
      entities,
      {filter: responseFilter, counts},
    );
  }

  async getAll(
    params: HttpCommandInputParams & {schedulesOnly?: boolean} = {},
    options?: HttpCommandOptions,
  ) {
    if (!canUseNativeApi(this.http) || params.schedulesOnly) {
      return super.getAll(params, options);
    }

    const filter = filterFromCommandParams(params).all();
    const tasks: Task[] = [];
    let total = Number.POSITIVE_INFINITY;

    for (let page = 1; tasks.length < total; page += 1) {
      const nativeResponse = await fetchNativeTasks(this.http, {
        ...nativeTaskQueryFromFilter(filter),
        page,
        pageSize: NATIVE_COMMAND_PAGE_SIZE,
      });
      tasks.push(...nativeResponse.tasks);
      total = nativeResponse.page.total;
      if (nativeResponse.tasks.length === 0) {
        break;
      }
    }

    return new Response(
      tasks,
      nativeCollectionMeta(filter, tasks, Number.isFinite(total) ? total : 0),
    );
  }

  exportByIds(ids: string[]) {
    return exportNativeTasksMetadata(this.http, ids);
  }

  export(entities: Task[]) {
    return this.exportByIds(
      entities.flatMap(entity =>
        entity.id === undefined ? [] : [entity.id],
      ),
    );
  }

  async exportByFilter(filter) {
    const tasks: Task[] = [];
    if (shouldExportAllByFilter(filter)) {
      let total = Number.POSITIVE_INFINITY;
      for (let page = 1; tasks.length < total; page += 1) {
        const nativeResponse = await fetchNativeTasks(this.http, {
          ...nativeTaskQueryFromFilter(filter),
          page,
          pageSize: NATIVE_COMMAND_PAGE_SIZE,
        });
        tasks.push(...nativeResponse.tasks);
        total = nativeResponse.page.total;
        if (nativeResponse.tasks.length === 0) {
          break;
        }
      }
    } else {
      const nativeResponse = await fetchNativeTasks(
        this.http,
        nativeTaskQueryFromFilter(filter),
      );
      tasks.push(...nativeResponse.tasks);
    }

    return exportNativeTasksMetadata(
      this.http,
      tasks.flatMap(task => (task.id === undefined ? [] : [task.id])),
    );
  }

  getSeverityAggregates({filter}: TasksCommandWithFilterParam = {}) {
    return this.getAggregates({
      aggregate_type: 'task',
      group_column: 'severity',
      usage_type: 'scan',
      filter,
    });
  }

  getStatusAggregates({filter}: TasksCommandWithFilterParam = {}) {
    return this.getAggregates({
      aggregate_type: 'task',
      group_column: 'status',
      usage_type: 'scan',
      filter,
    });
  }

  getHighResultsAggregates({
    filter,
    max,
  }: {filter?: Filter; max?: number} = {}) {
    return this.getAggregates({
      filter,
      aggregate_type: 'task',
      group_column: 'uuid',
      usage_type: 'scan',
      textColumns: ['name', 'high_per_host', 'severity', 'modified'],
      sort: [
        {
          field: 'high_per_host',
          direction: 'descending',
          stat: 'max',
        },
        {
          field: 'modified',
          direction: 'descending',
        },
      ],
      maxGroups: max,
    });
  }
}

export default TasksCommand;
