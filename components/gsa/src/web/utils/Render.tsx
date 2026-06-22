/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import React from 'react';
import {format} from 'd3-format';
import {getFormattedDate} from 'gmp/locale/date';
import {_} from 'gmp/locale/lang';
import date, {type Date} from 'gmp/models/date';
import {parseBoolean, type YesNo} from 'gmp/parser';
import {isDefined, isFunction, isObject} from 'gmp/utils/identity';
import {isEmpty, shorten} from 'gmp/utils/string';
import {type SelectItem} from 'web/components/form/Select';

export interface RenderSelectItemProps {
  name: string;
  id: string;
  deprecated?: boolean | YesNo;
}

export interface GenerateFilenameParams {
  creationTime?: Date;
  extension?: string;
  fileNameFormat?: string;
  reportFormat?: string;
  id?: string;
  modificationTime?: Date;
  resourceName?: string;
  resourceType?: string;
  username?: string;
}

export const UNSET_VALUE = '0';
export const UNSET_LABEL = '--';

/**
 * Render a entities list as items array
 *
 * @param list             The entities list
 * @param defaultItemValue (optional) Value for the default item
 * @param defaultItemLabel (optional. Default is '--') Label to display for the default item
 *
 * @returns An array to be used as items for a Select component or undefined
 */
export const renderSelectItems = (
  list: RenderSelectItemProps[] | undefined,
  defaultItemValue?: string,
  defaultItemLabel: string = UNSET_LABEL,
): SelectItem[] => {
  const items = isDefined(list)
    ? list.map(item => ({
        label: String(item.name),
        value: item.id,
        deprecated: isDefined(item.deprecated)
          ? parseBoolean(item.deprecated)
          : undefined,
      }))
    : [];

  if (!isDefined(defaultItemValue)) {
    return items;
  }

  const defaultItem = {
    value: defaultItemValue,
    label: defaultItemLabel,
  };
  return isDefined(items) ? [defaultItem, ...items] : [defaultItem];
};

export const severityFormat = format('0.1f');

export const renderNvtName = (
  oid: string,
  name?: string,
  length: number = 70,
) => {
  if (!isDefined(name)) {
    return oid;
  }

  if (name.length < length) {
    return name;
  }

  return <abbr title={name + ' (' + oid + ')'}>{shorten(name, length)}</abbr>;
};

export const renderComponent = <TProps extends {}>(
  Component:
    | React.FunctionComponent<TProps>
    | React.ComponentClass<TProps>
    | string,
  props: TProps = {} as TProps,
) => (Component ? <Component {...props} /> : null);

export const renderChildren = (children: React.ReactNode) =>
  React.Children.count(children) > 1 ? (
    <React.Fragment>{children}</React.Fragment>
  ) : (
    children
  );

export const na = (value: string) => {
  return isEmpty(value) ? _('N/A') : value;
};

export const renderYesNo = (
  value?: YesNo | string | number | boolean | null,
) => {
  switch (value) {
    case true:
    case 1:
    case '1':
    case 'yes':
    case 'Yes':
      return _('Yes');
    case false:
    case 0:
    case '0':
    case 'no':
    case 'No':
      return _('No');
    default:
      return _('Unknown');
  }
};

export const getTranslatableSeverityOrigin = (origin: string) => {
  switch (origin) {
    case 'Third Party':
      return _('Third Party');
    case 'Vendor':
      return _('Vendor');
    case 'Greenbone':
      return _('Greenbone');
    case 'NVD':
      return _('NVD');
    default:
      return origin;
  }
};

export const setRef =
  <TRef,>(...refs: (React.Ref<TRef> | null | undefined)[]) =>
  (ref: TRef) => {
    for (const rf of refs) {
      if (isFunction(rf)) {
        (rf as React.RefCallback<TRef>)(ref);
      } else if (isObject(rf) && isDefined(rf.current)) {
        // @ts-expect-error
        (rf as React.RefObject<TRef>).current = ref;
      }
    }
  };

export const generateFilename = ({
  creationTime,
  extension = 'xml',
  fileNameFormat = '',
  reportFormat = 'XML',
  id = 'list',
  modificationTime,
  resourceName,
  resourceType,
  username,
}: GenerateFilenameParams) => {
  const currentTime = date();
  const cTime = isDefined(creationTime) ? creationTime : currentTime;

  let mTime = isDefined(modificationTime) ? modificationTime : creationTime;
  if (!isDefined(mTime)) {
    mTime = currentTime;
  }

  const percentC = getFormattedDate(cTime, 'YYYYMMDD');
  const percentc = getFormattedDate(cTime, 'HHMMss'); // Updated format
  const percentD = getFormattedDate(currentTime, 'YYYYMMDD');
  const percentt = getFormattedDate(currentTime, 'HHMMss'); // Updated format
  const percentM = getFormattedDate(mTime, 'YYYYMMDD');
  const percentm = getFormattedDate(mTime, 'HHMMss'); // Updated format
  const percentN = isDefined(resourceName) ? resourceName : resourceType;

  const fileNameMap = {
    '%C': percentC, // The creation date in the format YYYYMMDD. Changed to the current date if a creation date is not available.
    '%c': percentc, // The creation time in the format HHMMss. Changed to the current time if a creation time is not available.
    '%D': percentD, // The current date in the format YYYYMMDD.
    '%F': reportFormat, // The name of the format plug-in used (XML for lists and types other than reports).
    '%M': percentM, // The modification date in the format YYYYMMDD. Changed to the creation date or to the current date if a modification date is not available.
    '%m': percentm, // The modification time in the format HHMMss. Changed to the creation time or to the current time if a modification time is not available.
    '%N': percentN, // The name for the resource or the associated task for reports. Lists and types without a name will use the type (see %T).
    '%T': resourceType, // The resource type, e.g. “task”, “port_list”. Pluralized for list pages.
    '%t': percentt, // The current time in the format HHMMss.
    '%U': id, // The unique ID of the resource or “list” for lists of multiple resources.
    '%u': username, // The name for the currently logged in user.
    '%%': '%',
  };
  const regExp = new RegExp(Object.keys(fileNameMap).join('|'), 'gi');

  let fileName = fileNameFormat.replace(regExp, match => fileNameMap[match]);

  fileName += '.' + extension;

  if (fileName === '.' + extension) {
    // if something went wrong, make sure to always have a filename
    fileName = 'unnamed.unknown';
  }

  return fileName;
};
