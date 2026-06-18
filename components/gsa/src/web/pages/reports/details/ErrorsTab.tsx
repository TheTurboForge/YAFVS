/* SPDX-FileCopyrightText: 2026 Greenbone AG
 * Modified by TurboVAS contributors, 2026.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import Filter from 'gmp/models/filter';
import type {TaskStatus} from 'gmp/models/task';
import NativeErrorsTab from 'web/pages/reports/details/NativeErrorsTab';

interface ErrorsTabWrapperProps {
  filter?: Filter;
  reportId: string;
  status: TaskStatus;
}

const ErrorsTabWrapper = ({filter, reportId}: ErrorsTabWrapperProps) => (
  <NativeErrorsTab reportFilter={filter ?? new Filter()} reportId={reportId} />
);

export default ErrorsTabWrapper;
