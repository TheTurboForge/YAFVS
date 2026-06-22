/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {describe, test, expect, testing} from '@gsa/testing';
import {
  changeInputValue,
  screen,
  rendererWith,
  fireEvent,
  getSelectItemElementsForSelect,
  waitFor,
} from 'web/testing';
import Features from 'gmp/capabilities/features';
import Filter from 'gmp/models/filter';
import FilterTerm from 'gmp/models/filter/filterterm';
import {OPENVASD_SCANNER_TYPE, scannerTypeName} from 'gmp/models/scanner';
import ScannerFilterDialog from 'web/pages/scanners/ScannerFilterDialog';

describe('ScannerFilterDialog tests', () => {

  test('should allow to create a new filter', async () => {
    const filter = new Filter({
      terms: [new FilterTerm({keyword: 'name', value: 'test'})],
    });
    const newFilter = new Filter({id: 'new-filter'});
    const newFilterWithDetails = newFilter.copy().set('rows', 10);
    const gmp = {
      settings: {enableGreenboneSensor: true},
      filter: {
        create: testing.fn().mockResolvedValue({data: newFilter}),
        get: testing.fn().mockResolvedValue({data: newFilterWithDetails}),
      },
    };
    const handleClose = testing.fn();
    const handleFilterChanged = testing.fn();
    const handleFilterCreated = testing.fn();
    const {render} = rendererWith({capabilities: true, gmp});

    render(
      <ScannerFilterDialog
        filter={filter}
        onClose={handleClose}
        onFilterChanged={handleFilterChanged}
        onFilterCreated={handleFilterCreated}
      />,
    );

    const checkbox = screen.getByTestId('createnamedfiltergroup-checkbox');
    fireEvent.click(checkbox);
    expect(checkbox).toBeChecked();

    const nameInput = screen.getByName('filterName');
    changeInputValue(nameInput, 'New Task Filter');

    const saveButton = screen.getDialogSaveButton();
    fireEvent.click(saveButton);

    await waitFor(() => expect(handleClose).toHaveBeenCalled());

    expect(gmp.filter.create).toHaveBeenCalledWith({
      term: filter.toFilterString(),
      type: 'scanner',
      name: 'New Task Filter',
    });
    expect(gmp.filter.get).toHaveBeenCalledWith({id: newFilter.id});
    expect(handleFilterChanged).not.toHaveBeenCalledWith();
    expect(handleFilterCreated).toHaveBeenCalledWith(newFilterWithDetails);
  });

  test('should not render create named filter group if not allowed', () => {
    const filter = new Filter();
    const gmp = {
      settings: {enableGreenboneSensor: true},
      filter: {
        create: testing.fn().mockResolvedValue(new Filter()),
      },
    };
    const handleClose = testing.fn();
    const handleFilterChanged = testing.fn();
    const handleFilterCreated = testing.fn();
    const {render} = rendererWith({capabilities: false, gmp});

    render(
      <ScannerFilterDialog
        filter={filter}
        onClose={handleClose}
        onFilterChanged={handleFilterChanged}
        onFilterCreated={handleFilterCreated}
      />,
    );

    expect(
      screen.queryByTestId('createnamedfiltergroup-checkbox'),
    ).not.toBeInTheDocument();
  });

});
