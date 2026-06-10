/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * Modified by TurboVAS contributors, 2026.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {describe, test, expect} from '@gsa/testing';
import {rendererWith} from 'web/testing';
import Features from 'gmp/capabilities/features';
import useFeatures from 'web/hooks/useFeatures';

const TestUseFeatures = () => {
  const features = useFeatures();
  if (features.featureEnabled('ENABLE_OPENVASD')) {
    return <span>May use OpenVASD</span>;
  }
  return <span>OpenVASD is not available</span>;
};

describe('useFeatures tests', () => {
  test('should expose enabled features', () => {
    const features = new Features(['ENABLE_OPENVASD']);
    const {render} = rendererWith({features});

    const {element} = render(<TestUseFeatures />);

    expect(element).toHaveTextContent(/^May use OpenVASD$/);
  });

  test('should not expose disabled features', () => {
    const features = new Features();
    const {render} = rendererWith({features});

    const {element} = render(<TestUseFeatures />);

    expect(element).toHaveTextContent(/^OpenVASD is not available$/);
  });

  test('should throw an error if used outside FeaturesProvider', () => {
    // @ts-expect-error
    const {render} = rendererWith({features: null});

    expect(() => render(<TestUseFeatures />)).toThrow(
      'useFeatures must be used within a FeaturesProvider',
    );
  });
});
