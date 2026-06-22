/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {describe, test, expect, testing} from '@gsa/testing';
import {changeInputValue, screen, render} from 'web/testing';
import {
  AUTO_DELETE_KEEP_DEFAULT_VALUE,
} from 'gmp/models/task';
import AutoDeleteReportsGroup from 'web/pages/tasks/AutoDeleteReportsGroup';

describe('AutoDeleteReportsGroup tests', () => {
  test('should render dialog group', () => {
    const handleChange = testing.fn();

    const {element} = render(
      <AutoDeleteReportsGroup
        autoDeleteData={AUTO_DELETE_KEEP_DEFAULT_VALUE}
        onChange={handleChange}
      />,
    );

    expect(element).toBeInTheDocument();
  });

  test('should allow to change auto delete keep value', () => {
    const handleChange = testing.fn();

    render(
      <AutoDeleteReportsGroup
        autoDeleteData={AUTO_DELETE_KEEP_DEFAULT_VALUE}
        onChange={handleChange}
      />,
    );

    const autoDeleteKeepData = screen.getByName('auto_delete_data');
    changeInputValue(autoDeleteKeepData, '12');
    expect(handleChange).toHaveBeenCalledWith(12, 'auto_delete_data');
  });

});
