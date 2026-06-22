/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {describe, test, expect, testing} from '@gsa/testing';
import {render, screen} from 'web/testing';
import Filter from 'gmp/models/filter';
import ReportFormat from 'gmp/models/report-format';
import DownloadReportDialog from 'web/pages/reports/DownloadReportDialog';

const filter = Filter.fromString('rows=100');

const reportFormats = [
  ReportFormat.fromElement({_id: 'rf-1', name: 'PDF', report_type: 'scan'}),
  ReportFormat.fromElement({_id: 'rf-2', name: 'CSV', report_type: 'scan'}),
];

const defaultProps = {
  defaultReportFormatId: 'rf-1',
  filter,
  reportFormats,
  onClose: testing.fn(),
  onSave: testing.fn(),
};

describe('DownloadReportDialog', () => {
  test('should render the dialog with scan report title', () => {
    render(<DownloadReportDialog {...defaultProps} />);

    expect(
      screen.getByText('Compose Content for Scan Report'),
    ).toBeInTheDocument();
  });

  test('should not show container scanning warning when not container scanning', () => {
    render(
      <DownloadReportDialog
        {...defaultProps}
        totalResultCount={20000}
      />,
    );

    expect(
      screen.queryByText(/Please be aware that the report has more results/),
    ).not.toBeInTheDocument();
  });

  test('should show threshold message when not container scanning', () => {
    render(
      <DownloadReportDialog
        {...defaultProps}
        showThresholdMessage={true}
        threshold={1000}
        totalResultCount={20000}
      />,
    );

    expect(screen.getByText(/threshold of 1000/)).toBeInTheDocument();
  });

});
