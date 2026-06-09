/* SPDX-FileCopyrightText: 2025 Greenbone AG
 * Modified by TurboVAS contributors, 2026.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {describe, expect, test} from '@gsa/testing';
import {rendererWith, screen} from 'web/testing';
import Capabilities from 'gmp/capabilities/capabilities';
import EverythingCapabilities from 'gmp/capabilities/everything';
import Features, {type Feature} from 'gmp/capabilities/features';
import {isDefined} from 'gmp/utils/identity';
import Menu from 'web/components/menu/Menu';

const renderMenuWith = ({
  capabilities,
  gmpSettings,
  features,
}: {
  capabilities: true | false | Capabilities;
  gmpSettings: Record<string, unknown>;
  features?: Feature[];
}) => {
  const gmp = {
    settings: gmpSettings,
  };

  const {render} = rendererWith({
    capabilities,
    gmp,
    router: true,
    features: isDefined(features) ? new Features(features) : undefined,
  });
  return render(<Menu />);
};

describe('Menu rendering', () => {
  test.each([
    'Scans',
    'Assets',
    'Security Information',
    'Configuration',
    'Administration',
  ])('should render top-level menu: %s', async label => {
    renderMenuWith({
      capabilities: new EverythingCapabilities(),
      gmpSettings: {
        enableAssetManagement: false,
        reloadInterval: 5000,
        reloadIntervalActive: 5000,
        reloadIntervalInactive: 5000,
      },
    });

    expect(screen.getByText(label)).toBeInTheDocument();
  });

  test.each([
    'Alerts',
    'CERT-Bund Advisories',
    'CPEs',
    'Credentials',
    'CVEs',
    'DFN-CERT Advisories',
    'Feed Status',
    'Filters',
    'LDAP',
    'NVTs',
    'Overrides',
    'Performance',
    'Port Lists',
    'RADIUS',
    'Report Configs',
    'Report Formats',
    'Reports',
    'Results',
    'Scan Configs',
    'Scanners',
    'Scope Reports',
    'Schedules',
    'Scopes',
    'Tags',
    'Targets',
    'Tasks',
    'Trashcan',
    'Users',
    'Vulnerabilities',
  ])('should render sub-menu: %s', async label => {
    renderMenuWith({
      capabilities: new EverythingCapabilities(),
      gmpSettings: {
        enableAssetManagement: false,
        reloadInterval: 5000,
        reloadIntervalActive: 5000,
        reloadIntervalInactive: 5000,
      },
    });

    expect(screen.getByText(label)).toBeInTheDocument();
  });
  test.each(['Configuration'])(
    'should not render %s when mayAccess returns false',
    async text => {
      renderMenuWith({
        capabilities: new Capabilities(),
        gmpSettings: {
          enableAssetManagement: false,
          reloadInterval: 5000,
          reloadIntervalActive: 5000,
          reloadIntervalInactive: 5000,
        },
      });

      expect(screen.queryByText(text)).not.toBeInTheDocument();
    },
  );

  test('should not render Asset menu when enableAssetManagement is false', async () => {
    renderMenuWith({
      capabilities: new EverythingCapabilities(),
      gmpSettings: {
        enableAssetManagement: false,
        reloadInterval: 5000,
        reloadIntervalActive: 5000,
        reloadIntervalInactive: 5000,
      },
    });
    expect(screen.queryByText('Asset')).not.toBeInTheDocument();
  });
});
