/* SPDX-FileCopyrightText: 2026 Greenbone AG
 * Modified by TurboVAS contributors, 2026.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type Filter from 'gmp/models/filter';
import type {TaskStatus} from 'gmp/models/task';
import NativeInventoryEvidenceTab from 'web/pages/reports/details/NativeInventoryEvidenceTab';

interface OperatingSystemsTabWrapperProps {
  filter?: Filter;
  reportId: string;
  status: TaskStatus;
}

const OperatingSystemsTabWrapper = ({
  filter,
  reportId,
}: OperatingSystemsTabWrapperProps) => (
  <NativeInventoryEvidenceTab
    kind="operatingSystems"
    reportFilter={filter}
    reportId={reportId}
  />
);

export default OperatingSystemsTabWrapper;
