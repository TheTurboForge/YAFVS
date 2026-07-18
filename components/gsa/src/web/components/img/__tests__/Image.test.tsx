/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {describe, test, expect} from '@gsa/testing';
import {render} from 'web/testing';
import Image from 'web/components/img/Image';

describe('Image tests', () => {
  test('should render image with attributes', () => {
    const {element} = render(<Image alt="YAFVS" src="favicon.svg" />);

    expect(element).toHaveAttribute('alt', 'YAFVS');
    expect(element).toHaveAttribute('src', '/img/favicon.svg');
  });
});
