/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import HttpCommand from 'gmp/commands/http';
import {canUseNativeApi} from 'gmp/commands/native';
import Response from 'gmp/http/response';
import {type XmlMeta, type XmlResponseData} from 'gmp/http/transform/fast-xml';
import Alert from 'gmp/models/alert';
import Credential from 'gmp/models/credential';
import Filter from 'gmp/models/filter';
import {type ModelElement} from 'gmp/models/model';
import Override from 'gmp/models/override';
import PortList from 'gmp/models/port-list';
import ReportConfig from 'gmp/models/report-config';
import ReportFormat from 'gmp/models/report-format';
import ScanConfig from 'gmp/models/scan-config';
import Scanner from 'gmp/models/scanner';
import Schedule from 'gmp/models/schedule';
import Tag from 'gmp/models/tag';
import Target from 'gmp/models/target';
import Task from 'gmp/models/task';
import {YES_VALUE} from 'gmp/parser';
import {
  deleteNativeTrashcanEntity,
  fetchNativeTrashcanItems,
  type NativeTrashcanItem,
  supportsNativeTrashcanDelete,
  restoreNativeTrashcanEntity,
  supportsNativeTrashcanRestore,
} from 'gmp/native-api/trashcan';
import {map} from 'gmp/utils/array';
import {apiType, type EntityType} from 'gmp/utils/entity-type';
import {isDefined} from 'gmp/utils/identity';

export interface TrashCanGetData {
  alerts: Alert[];
  scanConfigs: ScanConfig[];
  credentials: Credential[];
  filters: Filter[];
  overrides: Override[];
  portLists: PortList[];
  reportConfigs: ReportConfig[];
  reportFormats: ReportFormat[];
  scanners: Scanner[];
  schedules: Schedule[];
  tags: Tag[];
  targets: Target[];
  tasks: Task[];
  failedRequests?: string[];
}

interface UsageTypeElement extends ModelElement {
  usage_type?: string;
}

interface AlertResponseData {
  get_alerts_response?: {alert: ModelElement[] | ModelElement};
}

interface ConfigsResponseData {
  get_configs_response?: {config: UsageTypeElement[] | UsageTypeElement};
}

interface CredentialsResponseData {
  get_credentials_response?: {credential: ModelElement[] | ModelElement};
}

interface FiltersResponseData {
  get_filters_response?: {filter: ModelElement[] | ModelElement};
}

interface OverridesResponseData {
  get_overrides_response?: {override: ModelElement[] | ModelElement};
}

interface PortListsResponseData {
  get_port_lists_response?: {port_list: ModelElement[] | ModelElement};
}

interface ReportConfigsResponseData {
  get_report_configs_response?: {report_config: ModelElement[] | ModelElement};
}

interface ReportFormatsResponseData {
  get_report_formats_response?: {report_format: ModelElement[] | ModelElement};
}

interface ScannersResponseData {
  get_scanners_response?: {scanner: ModelElement[] | ModelElement};
}

interface SchedulesResponseData {
  get_schedules_response?: {schedule: ModelElement[] | ModelElement};
}

interface TagsResponseData {
  get_tags_response?: {tag: ModelElement[] | ModelElement};
}

interface TargetsResponseData {
  get_targets_response?: {target: ModelElement[] | ModelElement};
}

interface TasksResponseData {
  get_tasks_response?: {task: UsageTypeElement[] | UsageTypeElement};
}

interface TrashCanGetResponseData<TData> extends XmlResponseData {
  get_trash: TData;
}

type TrashCanGetResponse<TData> = Response<
  TrashCanGetResponseData<TData>,
  XmlMeta
>;

type TrashCanGetPromise<TData> = Promise<TrashCanGetResponse<TData>>;

const nativeItemElement = (item: NativeTrashcanItem): ModelElement => ({
  _id: item.id,
  name: item.name,
  comment: item.comment ?? undefined,
  creation_time: isDefined(item.creation_time)
    ? String(item.creation_time)
    : undefined,
  modification_time: isDefined(item.modification_time)
    ? String(item.modification_time)
    : undefined,
  trash: YES_VALUE,
  writable: YES_VALUE,
});

const pushNativeTrashcanItem = (
  data: TrashCanGetData,
  item: NativeTrashcanItem,
) => {
  const element = nativeItemElement(item);
  switch (item.entity_type) {
    case 'alert':
      data.alerts.push(Alert.fromElement(element));
      break;
    case 'scanconfig':
      data.scanConfigs.push(ScanConfig.fromElement(element as UsageTypeElement));
      break;
    case 'credential':
      data.credentials.push(Credential.fromElement(element));
      break;
    case 'filter':
      data.filters.push(Filter.fromElement(element));
      break;
    case 'override':
      data.overrides.push(Override.fromElement(element));
      break;
    case 'portlist':
      data.portLists.push(PortList.fromElement(element));
      break;
    case 'reportconfig':
      data.reportConfigs.push(ReportConfig.fromElement(element));
      break;
    case 'reportformat':
      data.reportFormats.push(ReportFormat.fromElement(element));
      break;
    case 'scanner':
      data.scanners.push(Scanner.fromElement(element));
      break;
    case 'schedule':
      data.schedules.push(Schedule.fromElement(element));
      break;
    case 'tag':
      data.tags.push(Tag.fromElement(element));
      break;
    case 'target':
      data.targets.push(Target.fromElement(element));
      break;
    case 'task':
      data.tasks.push(Task.fromElement(element as UsageTypeElement));
      break;
  }
};

const nativeTrashcanItemsToData = (
  items: NativeTrashcanItem[],
): TrashCanGetData => {
  const data: TrashCanGetData = {
    alerts: [],
    scanConfigs: [],
    credentials: [],
    filters: [],
    overrides: [],
    portLists: [],
    reportConfigs: [],
    reportFormats: [],
    scanners: [],
    schedules: [],
    tags: [],
    targets: [],
    tasks: [],
  };
  items.forEach(item => pushNativeTrashcanItem(data, item));
  return data;
};

class TrashCanCommand extends HttpCommand {
  async restore({id, entityType}: {id: string; entityType?: EntityType}) {
    if (
      supportsNativeTrashcanRestore(entityType) &&
      canUseNativeApi(this.http)
    ) {
      await restoreNativeTrashcanEntity(this.http, {id, entityType});
      return;
    }
    const data = {cmd: 'restore', target_id: id};
    await this.httpPostWithTransform(data);
  }

  async delete({id, entityType}: {id: string; entityType: EntityType}) {
    if (
      supportsNativeTrashcanDelete(entityType) &&
      canUseNativeApi(this.http)
    ) {
      await deleteNativeTrashcanEntity(this.http, {id, entityType});
      return;
    }
    const cmdApiType = apiType(entityType);
    const cmd = 'delete_from_trash';
    const typeId = cmdApiType + '_id';
    await this.httpPostWithTransform({
      cmd,
      [typeId]: id,
      resource_type: cmdApiType,
    });
  }

  async empty() {
    await this.httpPostWithTransform({cmd: 'empty_trashcan'});
  }

  async get(): Promise<Response<TrashCanGetData, XmlMeta>> {
    if (canUseNativeApi(this.http)) {
      return new Response(
        nativeTrashcanItemsToData(await fetchNativeTrashcanItems(this.http)),
      );
    }

    const requests = [
      this.httpGetWithTransform({
        cmd: 'get_trash_alerts',
      }) as TrashCanGetPromise<AlertResponseData>,
      this.httpGetWithTransform({
        cmd: 'get_trash_configs',
      }) as TrashCanGetPromise<ConfigsResponseData>,
      this.httpGetWithTransform({
        cmd: 'get_trash_credentials',
      }) as TrashCanGetPromise<CredentialsResponseData>,
      this.httpGetWithTransform({
        cmd: 'get_trash_filters',
      }) as TrashCanGetPromise<FiltersResponseData>,
      this.httpGetWithTransform({
        cmd: 'get_trash_overrides',
      }) as TrashCanGetPromise<OverridesResponseData>,
      this.httpGetWithTransform({
        cmd: 'get_trash_port_lists',
      }) as TrashCanGetPromise<PortListsResponseData>,
      this.httpGetWithTransform({
        cmd: 'get_trash_report_configs',
      }) as TrashCanGetPromise<ReportConfigsResponseData>,
      this.httpGetWithTransform({
        cmd: 'get_trash_report_formats',
      }) as TrashCanGetPromise<ReportFormatsResponseData>,
      this.httpGetWithTransform({
        cmd: 'get_trash_scanners',
      }) as TrashCanGetPromise<ScannersResponseData>,
      this.httpGetWithTransform({
        cmd: 'get_trash_schedules',
      }) as TrashCanGetPromise<SchedulesResponseData>,
      this.httpGetWithTransform({
        cmd: 'get_trash_tags',
      }) as TrashCanGetPromise<TagsResponseData>,
      this.httpGetWithTransform({
        cmd: 'get_trash_targets',
      }) as TrashCanGetPromise<TargetsResponseData>,
      this.httpGetWithTransform({
        cmd: 'get_trash_tasks',
      }) as TrashCanGetPromise<TasksResponseData>,
    ];

    const requestNames = [
      'alerts',
      'configs',
      'credentials',
      'filters',
      'overrides',
      'portLists',
      'reportConfigs',
      'reportFormats',
      'scanners',
      'schedules',
      'tags',
      'targets',
      'tasks',
    ];

    const results = await Promise.allSettled(requests);
    const failedRequests = results
      .map((result, index) =>
        result.status === 'rejected' ? requestNames[index] : undefined,
      )
      .filter((name): name is string => name !== undefined);

    const getResponse = <T>(index: number): T | null =>
      results[index].status === 'fulfilled'
        ? (results[index].value as T)
        : null;

    const alertsResponse =
      getResponse<TrashCanGetResponse<AlertResponseData>>(0);
    const configsResponse =
      getResponse<TrashCanGetResponse<ConfigsResponseData>>(1);
    const credentialsResponse =
      getResponse<TrashCanGetResponse<CredentialsResponseData>>(2);
    const filtersResponse =
      getResponse<TrashCanGetResponse<FiltersResponseData>>(3);
    const overridesResponse =
      getResponse<TrashCanGetResponse<OverridesResponseData>>(4);
    const portListsResponse =
      getResponse<TrashCanGetResponse<PortListsResponseData>>(5);
    const reportConfigsResponse =
      getResponse<TrashCanGetResponse<ReportConfigsResponseData>>(6);
    const reportFormatsResponse =
      getResponse<TrashCanGetResponse<ReportFormatsResponseData>>(7);
    const scannersResponse =
      getResponse<TrashCanGetResponse<ScannersResponseData>>(8);
    const schedulesResponse =
      getResponse<TrashCanGetResponse<SchedulesResponseData>>(9);
    const tagsResponse = getResponse<TrashCanGetResponse<TagsResponseData>>(10);
    const targetsResponse =
      getResponse<TrashCanGetResponse<TargetsResponseData>>(11);
    const tasksResponse =
      getResponse<TrashCanGetResponse<TasksResponseData>>(12);

    const alertsData = alertsResponse?.data.get_trash;
    const configsData = configsResponse?.data.get_trash;
    const credentialsData = credentialsResponse?.data.get_trash;
    const filtersData = filtersResponse?.data.get_trash;
    const overridesData = overridesResponse?.data.get_trash;
    const portListsData = portListsResponse?.data.get_trash;
    const reportConfigsData = reportConfigsResponse?.data.get_trash;
    const reportFormatsData = reportFormatsResponse?.data.get_trash;
    const scannersData = scannersResponse?.data.get_trash;
    const schedulesData = schedulesResponse?.data.get_trash;
    const tagsData = tagsResponse?.data.get_trash;
    const targetsData = targetsResponse?.data.get_trash;
    const tasksData = tasksResponse?.data.get_trash;

    const baseResponse =
      targetsResponse ||
      alertsResponse ||
      configsResponse ||
      credentialsResponse ||
      filtersResponse ||
      overridesResponse ||
      portListsResponse ||
      reportConfigsResponse ||
      reportFormatsResponse ||
      scannersResponse ||
      schedulesResponse ||
      tagsResponse ||
      tasksResponse;

    if (!baseResponse) {
      throw new Error('All trash can requests failed');
    }

    return baseResponse.setData({
      alerts: map(alertsData?.get_alerts_response?.alert, element =>
        Alert.fromElement(element),
      ),
      scanConfigs: map(configsData?.get_configs_response?.config, element =>
        ScanConfig.fromElement(element),
      ),
      credentials: map(
        credentialsData?.get_credentials_response?.credential,
        element => Credential.fromElement(element),
      ),
      filters: map(filtersData?.get_filters_response?.filter, element =>
        Filter.fromElement(element),
      ),
      overrides: map(overridesData?.get_overrides_response?.override, element =>
        Override.fromElement(element),
      ),
      portLists: map(
        portListsData?.get_port_lists_response?.port_list,
        element => PortList.fromElement(element),
      ),
      reportConfigs: map(
        reportConfigsData?.get_report_configs_response?.report_config,
        element => ReportConfig.fromElement(element),
      ),
      reportFormats: map(
        reportFormatsData?.get_report_formats_response?.report_format,
        element => ReportFormat.fromElement(element),
      ),
      scanners: map(scannersData?.get_scanners_response?.scanner, element =>
        Scanner.fromElement(element),
      ),
      schedules: map(schedulesData?.get_schedules_response?.schedule, element =>
        Schedule.fromElement(element),
      ),
      tags: map(tagsData?.get_tags_response?.tag, element =>
        Tag.fromElement(element),
      ),
      targets: map(targetsData?.get_targets_response?.target, element =>
        Target.fromElement(element),
      ),
      tasks: map(tasksData?.get_tasks_response?.task, element =>
        Task.fromElement(element),
      ),
      failedRequests: failedRequests.length > 0 ? failedRequests : undefined,
    });
  }
}

export default TrashCanCommand;
