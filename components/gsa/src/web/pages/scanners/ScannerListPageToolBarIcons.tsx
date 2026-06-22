/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {NewIcon} from 'web/components/icon';
import ManualIcon from 'web/components/icon/ManualIcon';
import IconDivider from 'web/components/layout/IconDivider';
import useCapabilities from 'web/hooks/useCapabilities';
import useGmp from 'web/hooks/useGmp';
import useTranslation from 'web/hooks/useTranslation';

interface ScannerListPageToolBarIconsProps {
  onScannerCreateClick: () => void;
}

const ScannerListPageToolBarIcons = ({
  onScannerCreateClick,
}: ScannerListPageToolBarIconsProps) => {
  const gmp = useGmp();
  const capabilities = useCapabilities();
  const [_] = useTranslation();
  const showNewScannerIcon =
    capabilities.mayCreate('scanner') && gmp.settings.enableGreenboneSensor;
  return (
    <IconDivider>
      <ManualIcon
        anchor="managing-scanners"
        page="scanning"
        title={_('Help: Scanners')}
      />
      {showNewScannerIcon && (
        <NewIcon
          title={_('New Scanner')}
          onClick={() => onScannerCreateClick && onScannerCreateClick()}
        />
      )}
    </IconDivider>
  );
};

export default ScannerListPageToolBarIcons;
