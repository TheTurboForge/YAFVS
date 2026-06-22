/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import HttpCommand from 'gmp/commands/http';
import type Http from 'gmp/http/http';
import {ResponseRejection} from 'gmp/http/rejection';
import {type XmlResponseData} from 'gmp/http/transform/fast-xml';
import {buildServerUrl} from 'gmp/http/utils';
import _ from 'gmp/locale';
import logger from 'gmp/log';
import date from 'gmp/models/date';
import {parseBoolean, parseDate, type YesNo} from 'gmp/parser';
import {map} from 'gmp/utils/array';
import {isDefined} from 'gmp/utils/identity';

export interface Feed {
  feedType: string;
  name: string;
  description: string;
  status?: string;
  currentlySyncing?: boolean;
  syncNotAvailableError?: string;
  version: string;
  age: number;
}

interface FeedElement {
  description?: string;
  name: string;
  type: string;
  version: number | string;
  status?: string;
  currently_syncing?: {
    timestamp?: string;
  };
  sync_not_available?: {
    error?: string;
  };
}

interface NativeFeedInventory {
  items?: FeedElement[];
}

export interface FeedStatusElement extends XmlResponseData {
  get_feeds: {
    get_feeds_response: {
      feed: FeedElement | FeedElement[];
      feed_owner_set?: YesNo;
      feed_resources_access?: YesNo;
    };
  };
}

const log = logger.getLogger('gmp.commands.feedstatus');

export const NVT_FEED = 'NVT';
export const CERT_FEED = 'CERT';
export const SCAP_FEED = 'SCAP';
export const GVMD_DATA_FEED = 'GVMD_DATA';

export const FEED_COMMUNITY = 'Greenbone Community Feed';
export const FEED_ENTERPRISE = 'Enterprise Feed';

const convertVersion = (version: number | string) =>
  `${version}`.slice(0, 8) + 'T' + `${version}`.slice(8, 12);

export function createFeed(feed: FeedElement): Feed {
  const versionDate = convertVersion(feed.version);
  const lastUpdate = parseDate(versionDate);

  return {
    feedType: feed.type,
    name: feed.name,
    description: feed.description ?? '',
    status: feed.status,
    currentlySyncing: isDefined(feed.currently_syncing),
    syncNotAvailableError: feed.sync_not_available?.error,
    version: versionDate,
    age: date().diff(lastUpdate, 'days'),
  };
}

export const feedStatusRejection = async (
  http: Http,
  rejection: Error,
): Promise<never> => {
  if (rejection instanceof ResponseRejection && rejection.status === 404) {
    const feedStatus = new FeedStatusCommand(http);
    const {isFeedOwnerSet, isFeedResourcesAccess} =
      await feedStatus.checkFeedOwnerAndPermissions();
    const syncMessage = _(
      'This issue may be due to the feed not having completed its synchronization.\nPlease try again shortly.',
    );
    if (!isFeedOwnerSet) {
      rejection.setMessage(
        `${_('The feed owner is currently not set.')} ${syncMessage}`,
      );
    } else if (!isFeedResourcesAccess) {
      rejection.setMessage(
        `${_('Access to the feed resources is currently restricted.')} ${syncMessage}`,
      );
    } else if (rejection.message.includes('Failed to find port_list')) {
      rejection.setMessage(
        `${_('Failed to create a new Target because the default Port List is not available.')} ${syncMessage}`,
      );
    } else if (rejection.message.includes('Failed to find config')) {
      rejection.setMessage(
        `${_('Failed to create a new Task because the default Scan Config is not available.')} ${syncMessage}`,
      );
    }
  }
  throw rejection;
};

class FeedStatusCommand extends HttpCommand {
  constructor(http: Http) {
    super(http, {cmd: 'get_feeds'});
  }

  async readFeedInformation() {
    return this.readNativeFeedInformation();
  }

  private async readNativeFeedInformation() {
    const url = buildServerUrl(
      this.http.apiServer,
      'api/v1/feeds',
      this.http.apiProtocol,
    );
    const response = await this.http.request<string>('get', {
      url,
      args: this.http.getParams(),
    });
    const payload = JSON.parse(response.data) as NativeFeedInventory;
    const feeds = map(payload.items ?? [], feed => createFeed(feed));
    return response.setData(feeds);
  }

  private readInheritedFeedOwnerAndPermissions() {
    // Feed owner/resource-access flags are still inherited GMP compatibility
    // data used only to improve target/task creation rejection messages.
    return this.httpGetWithTransform();
  }

  /**
   * Checks if any feed is currently syncing or if required feeds are not present.
   *
   * @returns A promise that resolves to an object indicating if any feed is syncing or if required feeds are not present or if there was an error.
   * @throws Throws an error if there is an issue fetching feed information.
   */

  async checkFeedSync() {
    try {
      const response = await this.readFeedInformation();

      const isFeedSyncing = response.data.some(
        feed => feed.currentlySyncing || isDefined(feed.syncNotAvailableError),
      );

      return {
        isSyncing: isFeedSyncing,
      };
    } catch (error) {
      log.error('Error checking if feed is syncing:', error);
      throw error;
    }
  }

  /**
   * Checks if the current user is the owner of the feed and if they have access to feed resources.
   *
   * @async
   * @returns An object containing two boolean properties:
   * - `isFeedOwner`: Indicates if the user is the owner of the feed.
   * - `isFeedResourcesAccess`: Indicates if the user has access to feed resources.
   * @throws Will throw an error if the HTTP request fails.
   */
  async checkFeedOwnerAndPermissions() {
    try {
      const response = await this.readInheritedFeedOwnerAndPermissions();
      const data = response.data as FeedStatusElement;
      const isFeedOwnerSet = parseBoolean(
        data.get_feeds.get_feeds_response.feed_owner_set,
      );
      const isFeedResourcesAccess = parseBoolean(
        data.get_feeds.get_feeds_response.feed_resources_access,
      );

      log.debug('Checking feed owner and permissions...', {
        isFeedOwnerSet,
        isFeedResourcesAccess,
      });
      return {
        isFeedOwnerSet,
        isFeedResourcesAccess,
      };
    } catch (error) {
      log.error('Error checking feed owner and permissions:', error);
      throw error;
    }
  }

  async isEnterpriseFeed() {
    try {
      const {data} = await this.readFeedInformation();

      const nvtFeed = data.find(feed => feed.feedType === NVT_FEED);

      return nvtFeed?.name === FEED_ENTERPRISE;
    } catch (error) {
      log.error('Error checking if feed is enterprise:', error);
      throw error;
    }
  }
}

export default FeedStatusCommand;
