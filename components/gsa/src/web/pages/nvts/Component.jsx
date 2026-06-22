/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import React from 'react';
import EntityComponent from 'web/entity/EntityComponent';
import OverrideComponent from 'web/pages/overrides/OverrideComponent';
import PropTypes from 'web/utils/PropTypes';

const NvtComponent = ({children, onChanged, onDownloaded, onDownloadError}) => (
  <OverrideComponent onCreated={onChanged} onSaved={onChanged}>
    {({create: overridecreate}) => (
      <EntityComponent
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

NvtComponent.propTypes = {
  children: PropTypes.func.isRequired,
  onChanged: PropTypes.func,
  onDownloadError: PropTypes.func,
  onDownloaded: PropTypes.func,
};

export default NvtComponent;
