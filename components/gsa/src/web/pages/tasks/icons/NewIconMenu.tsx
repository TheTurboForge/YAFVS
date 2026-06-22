/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {NewIcon} from 'web/components/icon';
import useCapabilities from 'web/hooks/useCapabilities';
import useTranslation from 'web/hooks/useTranslation';

interface NewIconMenuProps {
  onNewClick?: () => void;
}

const NewIconMenu = ({onNewClick}: NewIconMenuProps) => {
  const [_] = useTranslation();
  const capabilities = useCapabilities();
  if (capabilities.mayCreate('task')) {
    return (
      <NewIcon data-testid="new-task" title={_('New Task')} onClick={onNewClick} />
    );
  }
  return null;
};

export default NewIconMenu;
