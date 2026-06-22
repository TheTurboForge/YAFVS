/* SPDX-FileCopyrightText: 2024 Greenbone AG
 *
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {describe, test, expect} from '@gsa/testing';
import {render, screen} from 'web/testing';
import usePreviousValue from 'web/hooks/usePreviousValue';

interface TestComponentProps {
  value: number;
}

const TestComponent = ({value}: TestComponentProps) => {
  const previousValue = usePreviousValue(value);
  return (
    <>
      <span data-testid="value">{value}</span>
      <span data-testid="previousValue">{String(previousValue)}</span>
    </>
  );
};

describe('usePreviousValue', () => {
  test('should return the previous value', () => {
    const {rerender} = render(<TestComponent value={0} />);

    const value = screen.getByTestId('value');
    const previousValue = screen.getByTestId('previousValue');

    expect(value).toHaveTextContent('0');
    expect(previousValue).toHaveTextContent('undefined');

    rerender(<TestComponent value={1} />);

    expect(value).toHaveTextContent('1');
    expect(previousValue).toHaveTextContent('0');
  });
});
