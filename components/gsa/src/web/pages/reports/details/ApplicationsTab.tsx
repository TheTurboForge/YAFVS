/* SPDX-FileCopyrightText: 2026 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type Filter from 'gmp/models/filter';
import type {TaskStatus} from 'gmp/models/task';
import NativeInventoryEvidenceTab from 'web/pages/reports/details/NativeInventoryEvidenceTab';

interface ApplicationsTabProps {
  filter?: Filter;
  reportId: string;
  status: TaskStatus;
}

const ApplicationsTabWrapper = ({filter, reportId}: ApplicationsTabProps) => (
  <NativeInventoryEvidenceTab
    kind="applications"
    reportFilter={filter}
    reportId={reportId}
  />
);

export default ApplicationsTabWrapper;
