/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * Modified by TurboVAS contributors, 2026.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {isDefined} from 'gmp/utils/identity';

export const simplifiedReportIdentifier = (reportId, filter) => {
  if (isDefined(filter)) {
    const filterString = filter.simple().toFilterString();
    if (filterString.trim().length > 0) {
      return `${reportId}-${filterString}`;
    }
  }
  return reportId;
};

export const reportIdentifier = (reportId, filter) => {
  if (isDefined(filter)) {
    const filterString = filter.toFilterString();
    if (filterString.trim().length > 0) {
      return `${reportId}-${filterString}`;
    }
  }
  return reportId;
};

class ReportSelector {
  constructor(state = {}) {
    this.state = state;
  }

  isLoadingEntity(id, filter) {
    return isDefined(this.state.isLoading)
      ? this.state.isLoading[reportIdentifier(id, filter)]
      : undefined;
  }

  getEntityError(id, filter) {
    return isDefined(this.state.errors)
      ? this.state.errors[reportIdentifier(id, filter)]
      : undefined;
  }

  getEntity(id, filter) {
    return isDefined(this.state.byId)
      ? this.state.byId[simplifiedReportIdentifier(id, filter)]
      : undefined;
  }
}

export const reportSelector = rootState =>
  new ReportSelector(rootState.entities.report);
