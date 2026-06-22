/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type Filter from 'gmp/models/filter';
import type ReportTLSCertificate from 'gmp/models/report/tls-certificate';
import type {TaskStatus} from 'gmp/models/task';
import NativeInventoryEvidenceTab from 'web/pages/reports/details/NativeInventoryEvidenceTab';

interface TlsCertificatesTabProps {
  reportId: string;
  reportFilter: Filter;
  status: TaskStatus;
  onTlsCertificateDownloadClick: (entity: ReportTLSCertificate) => void;
}

const TlsCertificatesTab = ({
  reportFilter,
  reportId,
}: TlsCertificatesTabProps) => (
  <NativeInventoryEvidenceTab
    kind="tlsCertificates"
    reportFilter={reportFilter}
    reportId={reportId}
  />
);

export default TlsCertificatesTab;
