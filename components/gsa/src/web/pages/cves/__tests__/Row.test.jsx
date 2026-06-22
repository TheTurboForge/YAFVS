/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {describe, test, expect, testing} from '@gsa/testing';
import {rendererWithTableBody, fireEvent, screen} from 'web/testing';
import Cve from 'gmp/models/cve';
import {parseDate} from 'gmp/parser';
import {createSession} from 'gmp/testing';
import {SEVERITY_RATING_CVSS_3} from 'gmp/utils/severity';
import CveRow from 'web/pages/cves/Row';

const entity = Cve.fromElement({
  _id: 'CVE-2020-9992',
  name: 'CVE-2020-9992',
  creationTime: parseDate('2020-10-22T19:15:00Z'),
  cve: {
    cvss_vector: 'AV:N/AC:M/Au:N/C:C/I:C/A:C',
    severity: '9.3',
    description: 'foo bar baz',
  },
});

const createGmp = () => ({
  settings: {
    severityRating: SEVERITY_RATING_CVSS_3,
  },
  session: createSession({timezone: 'CET'}),
});

describe('CVEv2 Row tests', () => {
  test('should render', () => {
    const handleToggleDetailsClick = testing.fn();

    const {render} = rendererWithTableBody({
      gmp: createGmp(),
      capabilities: true,
      store: true,
      router: true,
    });

    const {baseElement} = render(
      <CveRow
        entity={entity}
        onToggleDetailsClick={handleToggleDetailsClick}
      />,
    );

    // Name
    expect(baseElement).toHaveTextContent('CVE-2020-9992');

    // CVSS Base Vector
    expect(baseElement).toHaveTextContent('AV:N/AC:M/Au:N/C:C/I:C/A:C');

    // Published
    expect(baseElement).toHaveTextContent(
      'Thu, Oct 22, 2020 9:15 PM Central European Summer Time',
    );

    // Severity
    const bars = screen.getAllByTestId('progressbar-box');
    expect(bars[0]).toHaveAttribute('title', 'Critical');
    expect(bars[0]).toHaveTextContent('9.3 (Critical)');

    // Description
    expect(baseElement).toHaveTextContent('foo bar baz');
  });

  test('should call click handlers', () => {
    const handleToggleDetailsClick = testing.fn();

    const {render} = rendererWithTableBody({
      gmp: createGmp(),
      capabilities: true,
      router: true,
      store: true,
    });

    const {baseElement} = render(
      <CveRow
        entity={entity}
        onToggleDetailsClick={handleToggleDetailsClick}
      />,
    );

    const spans = baseElement.querySelectorAll('span');
    fireEvent.click(spans[1]);
    expect(handleToggleDetailsClick).toHaveBeenCalledWith(
      undefined,
      'CVE-2020-9992',
    );
  });
});

const entity_v3 = Cve.fromElement({
  _id: 'CVE-2020-9992',
  name: 'CVE-2020-9992',
  creationTime: '2020-10-22T19:15:00Z',
  cve: {
    cvss_vector: 'CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H',
    severity: '7.1',
    description: 'foo bar baz',
  },
});

describe('CVEv3 Row tests', () => {
  test('should render', () => {
    const handleToggleDetailsClick = testing.fn();

    const {render} = rendererWithTableBody({
      gmp: createGmp(),
      capabilities: true,
      store: true,
      router: true,
    });

    const {baseElement} = render(
      <CveRow
        entity={entity_v3}
        onToggleDetailsClick={handleToggleDetailsClick}
      />,
    );

    // Name
    expect(baseElement).toHaveTextContent('CVE-2020-9992');

    // CVSS Base Vector
    expect(baseElement).toHaveTextContent(
      'CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H',
    );

    // Published
    expect(baseElement).toHaveTextContent(
      'Thu, Oct 22, 2020 9:15 PM Central European Summer Time',
    );

    // Severity
    const bars = screen.getAllByTestId('progressbar-box');
    expect(bars[0]).toHaveAttribute('title', 'High');
    expect(bars[0]).toHaveTextContent('7.1 (High)');

    // Description
    expect(baseElement).toHaveTextContent('foo bar baz');
  });

  test('should call click handlers', () => {
    const handleToggleDetailsClick = testing.fn();

    const {render} = rendererWithTableBody({
      gmp: createGmp(),
      capabilities: true,
      router: true,
    });

    const {baseElement} = render(
      <CveRow
        entity={entity}
        onToggleDetailsClick={handleToggleDetailsClick}
      />,
    );

    const spans = baseElement.querySelectorAll('span');
    fireEvent.click(spans[1]);
    expect(handleToggleDetailsClick).toHaveBeenCalledWith(
      undefined,
      'CVE-2020-9992',
    );
  });
});
