/* SPDX-FileCopyrightText: 2026 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import Filter from 'gmp/models/filter';
import NativePortsTab from 'web/pages/reports/details/NativePortsTab';

interface PortsTabProps {
  reportId: string;
  reportFilter: Filter;
}

const PortsTab = ({reportId, reportFilter}: PortsTabProps) => (
  <NativePortsTab reportFilter={reportFilter} reportId={reportId} />
);

export default PortsTab;
