/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import React from 'react';
import {exportNativeNvtMetadata} from 'gmp/native-api/nvts';
import EntityComponent from 'web/entity/EntityComponent';
import useGmp from 'web/hooks/useGmp';
import OverrideComponent from 'web/pages/overrides/OverrideComponent';
import PropTypes from 'web/utils/PropTypes';

const canUseNativeApi = gmp => typeof gmp?.buildUrl === 'function';

const exportNvt = (gmp, nvt) => {
  if (canUseNativeApi(gmp)) {
    return exportNativeNvtMetadata(gmp, nvt.id);
  }
  return gmp.nvt.export(nvt);
};

const NvtComponent = ({children, onChanged, onDownloaded, onDownloadError}) => {
  const gmp = useGmp();
  return (
    <OverrideComponent onCreated={onChanged} onSaved={onChanged}>
      {({create: overridecreate}) => (
        <EntityComponent
          download={entity => exportNvt(gmp, entity)}
          downloadOptions={canUseNativeApi(gmp) ? {extension: 'json'} : undefined}
          name="nvt"
          onDownloadError={onDownloadError}
          onDownloaded={onDownloaded}
        >
          {({download}) =>
            children({
              overridecreate,
              download,
            })
          }
        </EntityComponent>
      )}
    </OverrideComponent>
  );
};

NvtComponent.propTypes = {
  children: PropTypes.func.isRequired,
  onChanged: PropTypes.func,
  onDownloadError: PropTypes.func,
  onDownloaded: PropTypes.func,
};

export default NvtComponent;
