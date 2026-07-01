/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import React from 'react';
import {exportNativeOperatingSystemMetadata} from 'gmp/native-api/operating-systems';
import EntityComponent from 'web/entity/EntityComponent';
import useGmp from 'web/hooks/useGmp';

const canUseNativeApi = gmp => typeof gmp?.buildUrl === 'function';

const exportOperatingSystem = (gmp, operatingSystem) => {
  if (canUseNativeApi(gmp)) {
    return exportNativeOperatingSystemMetadata(gmp, operatingSystem.id);
  }
  return gmp.operatingsystem.export(operatingSystem);
};

const OsComponent = props => {
  const gmp = useGmp();
  return (
    <EntityComponent
      {...props}
      download={entity => exportOperatingSystem(gmp, entity)}
      downloadOptions={canUseNativeApi(gmp) ? {extension: 'json'} : undefined}
      name="operatingsystem"
    />
  );
};

export default OsComponent;
