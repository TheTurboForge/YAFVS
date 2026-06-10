/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * Modified by TurboVAS contributors, 2026.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import type Filter from 'gmp/models/filter';
import Checkbox from 'web/components/form/Checkbox';
import BooleanFilterGroup from 'web/components/powerfilter/BooleanFilterGroup';
import CreateNamedFilterGroup from 'web/components/powerfilter/CreateNamedFilterGroup';
import FilterDialog from 'web/components/powerfilter/FilterDialog';
import FilterSearchGroup from 'web/components/powerfilter/FilterSearchGroup';
import FilterStringGroup from 'web/components/powerfilter/FilterStringGroup';
import FirstResultGroup from 'web/components/powerfilter/FirstResultGroup';
import MinQodGroup from 'web/components/powerfilter/MinQodGroup';
import ResultsPerPageGroup from 'web/components/powerfilter/ResultsPerPageGroup';
import SeverityLevelsGroup from 'web/components/powerfilter/SeverityLevelsGroup';
import SeverityValuesGroup from 'web/components/powerfilter/SeverityValuesGroup';
import SolutionTypeGroup from 'web/components/powerfilter/SolutionTypeGroup';
import useFilterDialog from 'web/components/powerfilter/useFilterDialog';
import useFilterDialogSave, {
  type UseFilterDialogSaveProps,
  type UseFilterDialogStateProps,
} from 'web/components/powerfilter/useFilterDialogSave';
import useCapabilities from 'web/hooks/useCapabilities';
import useTranslation from 'web/hooks/useTranslation';

interface ReportDetailsFilterDialogProps extends UseFilterDialogSaveProps {
  filter?: Filter;
}

const ReportDetailsFilterDialog = ({
  filter: initialFilter,
  onClose,
  onFilterChanged,
  onFilterCreated,
}: ReportDetailsFilterDialogProps) => {
  const [_] = useTranslation();
  const capabilities = useCapabilities();
  const filterDialogProps =
    useFilterDialog<UseFilterDialogStateProps>(initialFilter);
  const [handleSave] = useFilterDialogSave(
    'result',
    {
      onClose,
      onFilterChanged,
      onFilterCreated,
    },
    filterDialogProps,
  );
  const {
    filter,
    filterName,
    filterString,
    saveNamedFilter,
    onFilterChange,
    onFilterValueChange,
    onFilterStringChange,
    onSearchTermChange,
    onValueChange,
  } = filterDialogProps;
  const resultHostsOnly = filter.get('result_hosts_only');
  const handleRemoveLevels = () =>
    onFilterChange(filter.copy().delete('levels'));
  return (
    <FilterDialog onClose={onClose} onSave={handleSave}>
      <FilterStringGroup
        filter={filterString}
        name="filterString"
        onChange={onFilterStringChange}
      />

      <BooleanFilterGroup
        filter={filter}
        name="apply_overrides"
        title={_('Apply Overrides')}
        onChange={onFilterValueChange}
      />

      <Checkbox
        checked={resultHostsOnly === 1}
        checkedValue={1}
        name="result_hosts_only"
        title={_('Only show hosts that have results')}
        unCheckedValue={0}
        onChange={onFilterValueChange as (value: number, name?: string) => void}
      />

      <MinQodGroup
        filter={filter}
        name="min_qod"
        onChange={onFilterValueChange}
      />

      <SeverityLevelsGroup
        filter={filter}
        onChange={onFilterValueChange}
        onRemove={handleRemoveLevels}
      />

      <SeverityValuesGroup
        filter={filter}
        name="severity"
        title={_('Severity')}
        onChange={onFilterValueChange}
      />

      <SolutionTypeGroup
        filter={filter}
        onChange={value => onFilterChange(value)}
      />

      <FilterSearchGroup
        filter={filter}
        name="vulnerability"
        title={_('Vulnerability')}
        onChange={onSearchTermChange}
      />

      <FilterSearchGroup
        filter={filter}
        name="host"
        title={_('Host (IP)')}
        onChange={onSearchTermChange}
      />

      <FilterSearchGroup
        filter={filter}
        name="location"
        title={_('Location (eg. port/protocol)')}
        onChange={onSearchTermChange}
      />

      <FirstResultGroup filter={filter} onChange={onFilterValueChange} />

      <ResultsPerPageGroup filter={filter} onChange={onFilterValueChange} />

      {capabilities.mayCreate('filter') && (
        <CreateNamedFilterGroup
          filterName={filterName}
          saveNamedFilter={saveNamedFilter}
          onValueChange={onValueChange}
        />
      )}
    </FilterDialog>
  );
};

export default ReportDetailsFilterDialog;
