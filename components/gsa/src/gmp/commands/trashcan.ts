/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import HttpCommand from 'gmp/commands/http';
import {canUseNativeApi} from 'gmp/commands/native';
import Response from 'gmp/http/response';
import Alert from 'gmp/models/alert';
import Credential from 'gmp/models/credential';
import Filter from 'gmp/models/filter';
import {type ModelElement} from 'gmp/models/model';
import Override from 'gmp/models/override';
import PortList from 'gmp/models/port-list';
import ReportFormat from 'gmp/models/report-format';
import ScanConfig from 'gmp/models/scan-config';
import Scanner from 'gmp/models/scanner';
import Schedule from 'gmp/models/schedule';
import Tag from 'gmp/models/tag';
import Target from 'gmp/models/target';
import Task from 'gmp/models/task';
import {
  deleteNativeTrashcanEntity,
  emptyNativeTrashcan,
  fetchNativeTrashcanEmptyPreview,
  fetchNativeTrashcanItems,
  type NativeTrashcanEmptyPreview,
  type NativeTrashcanItem,
  supportsNativeTrashcanDelete,
  restoreNativeTrashcanEntity,
  supportsNativeTrashcanRestore,
} from 'gmp/native-api/trashcan';
import {YES_VALUE} from 'gmp/parser';
import {type EntityType} from 'gmp/utils/entity-type';
import {isDefined} from 'gmp/utils/identity';

export interface TrashCanGetData {
  alerts: Alert[];
  scanConfigs: ScanConfig[];
  credentials: Credential[];
  filters: Filter[];
  overrides: Override[];
  portLists: PortList[];
  reportFormats: ReportFormat[];
  scanners: Scanner[];
  schedules: Schedule[];
  tags: Tag[];
  targets: Target[];
  tasks: Task[];
}

export interface TrashCanEmptyParams {
  expectedTotal: number;
  expectedSnapshotDigest: string;
}

interface UsageTypeElement extends ModelElement {
  usage_type?: string;
}

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
      data.scanConfigs.push(
        ScanConfig.fromElement(element as UsageTypeElement),
      );
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
  async restore({id, entityType}: {id: string; entityType: EntityType}) {
    if (supportsNativeTrashcanRestore(entityType)) {
      if (!canUseNativeApi(this.http)) {
        throw new Error(
          `Native Trashcan restore is unavailable for ${entityType}`,
        );
      }
      await restoreNativeTrashcanEntity(this.http, {id, entityType});
      return;
    }

    throw new Error(`Trashcan restore is unavailable for ${entityType}`);
  }

  async delete({id, entityType}: {id: string; entityType: EntityType}) {
    if (supportsNativeTrashcanDelete(entityType)) {
      if (!canUseNativeApi(this.http)) {
        throw new Error(
          `Native Trashcan permanent delete is unavailable for ${entityType}`,
        );
      }
      await deleteNativeTrashcanEntity(this.http, {id, entityType});
      return;
    }

    throw new Error(
      `Trashcan permanent delete is unavailable for ${entityType}`,
    );
  }

  async emptyPreview(): Promise<NativeTrashcanEmptyPreview> {
    if (!canUseNativeApi(this.http)) {
      throw new Error('Native Trashcan empty preview is unavailable');
    }
    return fetchNativeTrashcanEmptyPreview(this.http);
  }

  async empty({expectedTotal, expectedSnapshotDigest}: TrashCanEmptyParams) {
    if (!canUseNativeApi(this.http)) {
      throw new Error('Native Trashcan empty is unavailable');
    }
    return emptyNativeTrashcan(
      this.http,
      expectedTotal,
      expectedSnapshotDigest,
    );
  }

  async get(): Promise<Response<TrashCanGetData>> {
    if (!canUseNativeApi(this.http)) {
      throw new Error('Native Trashcan inventory is unavailable');
    }

    return new Response(
      nativeTrashcanItemsToData(await fetchNativeTrashcanItems(this.http)),
    );
  }
}

export default TrashCanCommand;
