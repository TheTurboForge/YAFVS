/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import Filter from 'gmp/models/filter';
import type {TaskStatus} from 'gmp/models/task';
import NativeCvesTab from 'web/pages/reports/details/NativeCvesTab';

interface CvesTabProps {
  filter?: Filter;
  reportId: string;
  status: TaskStatus;
}

const CvesTabWrapper = ({filter, reportId}: CvesTabProps) => (
  <NativeCvesTab reportFilter={filter ?? new Filter()} reportId={reportId} />
);

export default CvesTabWrapper;
