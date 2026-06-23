/* SPDX-FileCopyrightText: 2025 Greenbone AG
 * SPDX-FileCopyrightText: 2026 Robert Pelfrey <Robert@Pelfrey.de>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {describe, test, expect, testing} from '@gsa/testing';
import {render, screen, fireEvent, waitFor} from 'web/testing';
import SearchBar from 'web/components/searchbar/SearchBar';

describe('SearchBar', () => {
  const placeholder = 'Search...';

  test('calls onSearch with debounced input value', async () => {
    const onSearch = testing.fn();
    render(
      <SearchBar
        matchesCount={2}
        placeholder={placeholder}
        onSearch={onSearch}
      />,
    );
    const input = screen.getByPlaceholderText(placeholder);

    await waitFor(() => {
      expect(onSearch).toHaveBeenCalledWith('');
    });
    onSearch.mockClear();

    fireEvent.change(input, {target: {value: 'ap'}});

    await waitFor(() => {
      expect(onSearch).toHaveBeenCalledWith('ap');
    });
  });

  test('shows no results message when resultsCount is zero', async () => {
    const onSearch = testing.fn();
    render(
      <SearchBar
        matchesCount={0}
        placeholder={placeholder}
        onSearch={onSearch}
      />,
    );
    const input = screen.getByPlaceholderText(placeholder);

    fireEvent.change(input, {target: {value: 'xyz'}});

    await waitFor(() => {
      expect(screen.getByText('No matches found.')).toBeVisible();
    });
  });
});
