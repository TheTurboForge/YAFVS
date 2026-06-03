/* SPDX-FileCopyrightText: 2026 Greenbone AG
 * Modified by TurboVAS contributors, 2026.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type CollectionCounts from 'gmp/collection/collection-counts';
import type Filter from 'gmp/models/filter';
import type {TaskStatus} from 'gmp/models/task';
import EmptyReport from 'web/pages/reports/details/EmptyReport';
import EmptyResultsReport from 'web/pages/reports/details/EmptyResultsReport';
import ResultsTab from 'web/pages/reports/details/ResultsTab';

interface ResultsTabContentProps {
  hasTarget: boolean;
  progress: number;
  reportFilter: Filter;
  reportId: string;
  reportResultsCounts?: CollectionCounts;
  status: TaskStatus;
  onFilterAddLogLevelClick?: () => void;
  onFilterDecreaseMinQoDClick: () => void;
  onFilterEditClick: () => void;
  onFilterRemoveClick: () => void;
  onFilterRemoveSeverityClick?: () => void;
  onTargetEditClick: () => void;
}

const ResultsTabContent = ({
  hasTarget,
  progress,
  reportFilter,
  reportId,
  reportResultsCounts,
  status,
  onFilterAddLogLevelClick,
  onFilterDecreaseMinQoDClick,
  onFilterEditClick,
  onFilterRemoveClick,
  onFilterRemoveSeverityClick,
  onTargetEditClick,
}: ResultsTabContentProps) => {
  // Show empty report when no results are available.
  if (
    reportResultsCounts?.filtered === 0 &&
    reportResultsCounts.all === 0
  ) {
    return (
      <EmptyReport
        hasTarget={hasTarget}
        progress={progress}
        status={status}
        onTargetEditClick={onTargetEditClick}
      />
    );
  }

  // Show empty results report when all results are filtered out.
  if (
    reportResultsCounts?.filtered === 0 &&
    reportResultsCounts.all > 0
  ) {
    return (
      <EmptyResultsReport
        all={reportResultsCounts.all}
        filter={reportFilter}
        onFilterAddLogLevelClick={onFilterAddLogLevelClick}
        onFilterDecreaseMinQoDClick={onFilterDecreaseMinQoDClick}
        onFilterEditClick={onFilterEditClick}
        onFilterRemoveClick={onFilterRemoveClick}
        onFilterRemoveSeverityClick={onFilterRemoveSeverityClick}
      />
    );
  }


  return (
    <ResultsTab
      hasTarget={hasTarget}
      progress={progress}
      reportFilter={reportFilter}
      reportId={reportId}
      reportResultsCounts={reportResultsCounts}
      status={status}
      onFilterAddLogLevelClick={onFilterAddLogLevelClick}
      onFilterDecreaseMinQoDClick={onFilterDecreaseMinQoDClick}
      onFilterEditClick={onFilterEditClick}
      onFilterRemoveClick={onFilterRemoveClick}
      onFilterRemoveSeverityClick={onFilterRemoveSeverityClick}
      onTargetEditClick={onTargetEditClick}
    />
  );
};

export default ResultsTabContent;
