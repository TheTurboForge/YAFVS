/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * Modified by TurboVAS contributors, 2026.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import React from 'react';
import date from 'gmp/models/date';
import {isDefined} from 'gmp/utils/identity';
import Layout from 'web/components/layout/Layout';
import Link from 'web/components/link/Link';
import InfoPanel from 'web/components/panel/InfoPanel';
import useLicense from 'web/hooks/useLicense';
import useTranslation from 'web/hooks/useTranslation';
import PropTypes from 'web/utils/PropTypes';

const LICENSE_EXPIRATION_THRESHOLD = 30;

const LicenseLinkComponent = () => {
  const [_] = useTranslation();
  return <Link to="license">{_('License Management page')}</Link>;
};

const LicenseNotification = ({capabilities, onCloseClick}) => {
  const [_] = useTranslation();
  const {license} = useLicense();
  const days = license?.expires
    ? date(license?.expires).diff(date(), 'days')
    : undefined;
  const corruptMessageAdmin = (
    <span>
      {_(
        'The legacy appliance license for this system is invalid. ' +
          'You can still use the system without restrictions, but you will not ' +
          'receive updates anymore. Review the local deployment documentation ' +
          'before relying on this system beyond development use.',
      )}
    </span>
  );
  const corruptMessageUser = (
    <span>
      {_(
        'The legacy appliance license for this system is invalid. ' +
          'You can still use the system without restrictions, but you will not ' +
          'receive updates anymore. Please contact your administrator.',
      )}
    </span>
  );
  const corruptTitleMessage = _(
    'Your legacy appliance license is invalid!',
  );
  const expiringMessageAdmin = (
    <span>
      {_(
        'The legacy appliance license for this system will expire in ' +
          '{{days}} days. After that your appliance remains valid and you can ' +
          'still use the system without restrictions, but you will not receive ' +
          'updates anymore. You can find information about extending your ' +
          'license on the',
        {days},
      )}
      &nbsp;
      <LicenseLinkComponent />
    </span>
  );
  const expiringMessageUser = (
    <span>
      {_(
        'The legacy appliance license for this system will expire in ' +
          '{{days}} days. After that your appliance remains valid and you can ' +
          'still use the system without restrictions, but you will not receive ' +
          'updates anymore. Please contact your administrator for extending the ' +
          'license.',
        {days},
      )}
    </span>
  );
  const expiringTitleMessage = _(
    'Your legacy appliance license will expire in {{days}} days!',
    {
      days,
    },
  );
  const expiringTrialMessageAdmin = (
    <span>
      {_(
        'The trial period for this system will end in {{days}} days. ' +
          'You can find further information about purchasing a ' +
          'license on the',
        {days},
      )}
      &nbsp;
      <LicenseLinkComponent />
    </span>
  );
  const expiringTrialMessageUser = (
    <span>
      {_(
        'The trial period for this system will end in {{days}} days. Please contact ' +
          'your administrator for purchasing a new license.',
        {days},
      )}
    </span>
  );
  const expiredMessageAdmin = (
    <Layout flex="column">
      {_(
        'The legacy appliance license for this system expired {{days}} days ' +
          'ago. You can still use the system without restrictions, but you will ' +
          'not receive updates anymore. Especially, you will miss new ' +
          'vulnerability tests and thus your scans will not detect important new ' +
          'vulnerabilities in your network.',
        {days: Math.abs(days)},
      )}
      <br />
      <br />
      <span>
        {_('You can find information about renewing your license on the')}&nbsp;
        <LicenseLinkComponent />
      </span>
    </Layout>
  );
  const expiredMessageUser = (
    <span>
      {_(
        'The legacy appliance license for ' +
          'this system expired {{days}} days ago. You can still use the system without ' +
          'restrictions, but you will not receive updates anymore. Especially you ' +
          'will miss new vulnerability tests and thus your scans will not detect ' +
          'important new vulnerabilities in your network. Please contact your ' +
          'administrator for renewing the license.',
        {days: Math.abs(days)},
      )}
    </span>
  );
  const expiredTitleMessage = _(
    'Your legacy appliance license has expired {{days}} days ago!',
    {days: Math.abs(days)},
  );

  const {status, type} = license;

  let titleMessage;
  let message;
  let isWarning = false;

  if (status === 'no_license') {
    return null;
  } else if (status === 'expired') {
    isWarning = true;
    message = capabilities.mayEdit('license')
      ? expiredMessageAdmin
      : expiredMessageUser;
    titleMessage = expiredTitleMessage;
  } else if (status === 'corrupt') {
    isWarning = true;
    message = capabilities.mayEdit('license')
      ? corruptMessageAdmin
      : corruptMessageUser;
    titleMessage = corruptTitleMessage;
  } else if (status === 'active') {
    if (!isDefined(days) || days > LICENSE_EXPIRATION_THRESHOLD) {
      return null;
    }
    if (type === 'trial') {
      message = capabilities.mayEdit('license')
        ? expiringTrialMessageAdmin
        : expiringTrialMessageUser;
    } else {
      message = capabilities.mayEdit('license')
        ? expiringMessageAdmin
        : expiringMessageUser;
    }
    titleMessage = expiringTitleMessage;
  }

  return (
    <InfoPanel
      heading={titleMessage}
      isWarning={isWarning}
      noMargin={true}
      onCloseClick={onCloseClick}
    >
      {message}
    </InfoPanel>
  );
};

LicenseNotification.propTypes = {
  capabilities: PropTypes.capabilities.isRequired,
  onCloseClick: PropTypes.func.isRequired,
};

export default LicenseNotification;
