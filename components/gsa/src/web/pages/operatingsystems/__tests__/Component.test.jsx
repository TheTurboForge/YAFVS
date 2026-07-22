/* SPDX-FileCopyrightText: 2026 Robert Pelfrey <robert@pelfrey.de>
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import OperatingSystem from 'gmp/models/os';
import {createSession} from 'gmp/testing';
import {currentSettingsDefaultResponse} from 'web/pages/__fixtures__/current-settings';
import OsComponent from 'web/pages/operatingsystems/Component';
import {rendererWith, wait} from 'web/testing';

const nativePayload = {
  id: 'os-123',
  name: 'Linux',
  title: 'Linux Kernel',
  hosts: 1,
  all_hosts: 1,
};

const createGmp = ({
  currentSettings = testing
    .fn()
    .mockResolvedValue(currentSettingsDefaultResponse),
  exportOperatingSystem = testing.fn().mockResolvedValue({
    data: '<operating_system id="os-123"/>',
  }),
} = {}) => ({
  buildUrl: testing.fn((path, _params) => `https://yafvs.example/${path}`),
  session: {...createSession(), token: 'test-token', jwt: 'jwt-token'},
  user: {currentSettings},
  operatingsystem: {export: exportOperatingSystem},
});

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('OperatingSystem Component tests', () => {
  test('should use native metadata export for downloads', async () => {
    const fetchMock = testing.fn().mockResolvedValue({
      json: testing.fn().mockResolvedValue(nativePayload),
      ok: true,
      status: 200,
    });
    testing.stubGlobal('fetch', fetchMock);
    const gmp = createGmp({
      currentSettings: testing.fn().mockResolvedValue({
        data: {
          detailsexportfilename: {
            id: 'details-export-filename',
            name: 'Details Export File Name',
            value: '%T-%U',
          },
        },
      }),
    });
    const operatingSystem = OperatingSystem.fromElement({
      _id: 'os-123',
      name: 'Linux',
    });
    let downloadClick;
    const onDownloaded = testing.fn();
    const onDownloadError = testing.fn();
    const {render} = rendererWith({gmp, capabilities: true});

    render(
      <OsComponent
        onDownloadError={onDownloadError}
        onDownloaded={onDownloaded}
      >
        {({download}) => {
          downloadClick = download;
          return <div>Some Content</div>;
        }}
      </OsComponent>,
    );

    await wait();
    downloadClick(operatingSystem);
    await wait();

    expect(gmp.operatingsystem.export).not.toHaveBeenCalled();
    expect(gmp.buildUrl).toHaveBeenCalledWith(
      'api/v1/operating-systems/os-123/export',
      {token: 'test-token'},
    );
    expect(fetchMock).toHaveBeenCalledExactlyOnceWith(
      'https://yafvs.example/api/v1/operating-systems/os-123/export',
      expect.objectContaining({credentials: 'include'}),
    );
    expect(onDownloaded).toHaveBeenCalledWith({
      filename: 'operatingsystem-os-123.json',
      data: `${JSON.stringify(nativePayload, null, 2)}\n`,
    });
    expect(onDownloadError).not.toHaveBeenCalled();
  });
});
