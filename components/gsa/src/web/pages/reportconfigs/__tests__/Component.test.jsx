/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * Modified by TurboVAS contributors, 2026.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {afterEach, describe, test, expect, testing} from '@gsa/testing';
import {
  getSelectItemElementsForSelect,
  screen,
  within,
  fireEvent,
  rendererWith,
  wait,
} from 'web/testing';
import ReportConfig from 'gmp/models/report-config';
import {createSession} from 'gmp/testing';
import {currentSettingsDefaultResponse} from 'web/pages/__fixtures__/current-settings';
import ReportFormatComponent from 'web/pages/reportconfigs/ReportConfigsComponent';

const mockReportConfig = ReportConfig.fromElement({
  _id: 'rc123',
  name: 'test report config',
  report_format: {
    _id: 'rf456',
    name: 'test report format',
  },
  param: [
    {
      name: 'test param',
      value: 'ABC',
      type: {
        __text: 'string',
        min: '0',
        max: '1',
      },
    },
  ],
});

const mockReportFormat = {
  id: 'rf456',
  name: 'test report format',
  configurable: true,
  params: [
    {
      name: 'test param',
      value: 'ABC',
      type: 'string',
    },
  ],
};

const nativeReportFormatParam = {
  name: 'test param',
  type: 'string',
  value: 'ABC',
  default: 'ABC',
  min: 0,
  max: 1,
  options: [],
};

const nativeReportFormatItem = {
  id: 'rf456',
  name: 'test report format',
  configurable: true,
  params: [nativeReportFormatParam],
};

const nativeReportConfigPayload = {
  id: 'rc123',
  name: 'test report config',
  comment: '',
  owner: {name: 'admin'},
  report_format: {
    id: 'rf456',
    name: 'test report format',
  },
  writable: true,
  in_use: false,
  orphan: false,
  alerts: [],
  params: [
    {
      ...nativeReportFormatParam,
      using_default: false,
    },
  ],
};

const nativeReportFormatsPayload = {
  page: {page: 1, page_size: 200, total: 1, sort: 'name', filter: ''},
  items: [nativeReportFormatItem],
};

const nativeReportFormatDetailPayload = {
  ...nativeReportFormatItem,
  alerts: [],
  report_configs: [],
};

const stubNativeFetch = (...payloads) => {
  const fetchMock = testing.fn();
  payloads.forEach(payload => {
    fetchMock.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: testing.fn().mockResolvedValue(payload),
    });
  });
  testing.stubGlobal('fetch', fetchMock);
  return fetchMock;
};

const createGmp = ({
  currentSettings = testing
    .fn()
    .mockResolvedValue(currentSettingsDefaultResponse),
  getReportConfig = testing.fn().mockResolvedValue({
    data: mockReportConfig,
  }),
  getReportFormat = testing.fn().mockResolvedValue({
    data: mockReportFormat,
  }),
  getAllReportFormats = testing.fn().mockResolvedValue({
    data: [mockReportFormat],
  }),
  saveReportConfig = testing.fn().mockResolvedValue({
    data: {},
  }),
  createReportConfig = testing.fn().mockResolvedValue({
    data: {},
  }),
} = {}) => ({
  buildUrl: testing.fn((path, _params) => `https://turbovas.example/${path}`),
  session: {...createSession(), token: 'test-token', jwt: 'jwt-token'},
  user: {
    currentSettings: currentSettings,
  },
  reportconfig: {
    get: getReportConfig,
    save: saveReportConfig,
    create: createReportConfig,
  },
  reportformats: {
    getAll: getAllReportFormats,
  },
  reportformat: {
    get: getReportFormat,
  },
});

afterEach(() => {
  testing.unstubAllGlobals();
});

describe('Report Config Component tests', () => {
  test('should open edit dialog and call GMP save', async () => {
    const fetchMock = stubNativeFetch(
      nativeReportConfigPayload,
      nativeReportFormatsPayload,
    );
    let editClick;
    const children = testing.fn(({edit}) => {
      editClick = edit;
    });

    const gmp = createGmp();

    const {render} = rendererWith({
      gmp,
      router: true,
      store: true,
    });

    render(<ReportFormatComponent>{children}</ReportFormatComponent>);
    editClick({id: 'rc123'});

    await wait();

    expect(gmp.reportconfig.get).not.toHaveBeenCalled();
    expect(gmp.reportformats.getAll).not.toHaveBeenCalled();
    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/report-configs/rc123', {
      token: 'test-token',
    });
    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/report-formats', {
      token: 'test-token',
      page: 1,
      page_size: 200,
      sort: 'name',
      filter: '',
    });
    expect(fetchMock).toHaveBeenCalledTimes(2);

    expect(screen.queryDialogTitle()).toHaveTextContent(
      'Edit Report Config test report config',
    );
    const content = within(screen.queryDialogContent());
    const inputs = content.queryTextInputs();
    expect(inputs[0]).toHaveValue('test report config');

    const select = content.queryAllSelectElements();
    expect(select[0]).toHaveValue('test report format');

    const saveButton = screen.getDialogSaveButton();
    fireEvent.click(saveButton);

    expect(gmp.reportconfig.save).toHaveBeenCalledWith({
      comment: '',
      id: 'rc123',
      name: 'test report config',
      paramTypes: {
        'test param': 'string',
      },
      params: {
        'test param': 'ABC',
      },
      paramsUsingDefault: {
        'test param': false,
      },
      reportFormatId: 'rf456',
    });
  });

  test('should open create dialog and call GMP create', async () => {
    const fetchMock = stubNativeFetch(
      nativeReportFormatsPayload,
      nativeReportFormatDetailPayload,
    );
    let createClick;
    const children = testing.fn(({create}) => {
      createClick = create;
    });

    const gmp = createGmp();
    const {render} = rendererWith({
      gmp,
      router: true,
      store: true,
    });

    render(<ReportFormatComponent>{children}</ReportFormatComponent>);
    createClick();

    await wait();

    expect(gmp.reportformats.getAll).not.toHaveBeenCalled();
    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/report-formats', {
      token: 'test-token',
      page: 1,
      page_size: 200,
      sort: 'name',
      filter: '',
    });

    expect(screen.queryDialogTitle()).toHaveTextContent('New Report Config');
    const content = within(screen.queryDialogContent());
    const selects = content.queryAllSelectElements();

    // No report format selected at start
    expect(selects[0]).not.toHaveTextContent('test report format');
    // No params before report format has been selected
    expect(screen.queryDialogContent()).not.toHaveTextContent('test param');

    // Choose report format
    const items = await getSelectItemElementsForSelect(selects[0]);
    fireEvent.click(items[0]);
    await wait();

    expect(gmp.reportformat.get).not.toHaveBeenCalled();
    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/report-formats/rf456', {
      token: 'test-token',
    });
    expect(fetchMock).toHaveBeenCalledTimes(2);

    const saveButton = screen.getDialogSaveButton();
    fireEvent.click(saveButton);

    expect(gmp.reportconfig.create).toHaveBeenCalledWith({
      name: 'Unnamed',
      comment: '',
      paramTypes: {
        'test param': 'string',
      },
      params: {
        'test param': 'ABC',
      },
      paramsUsingDefault: {
        'test param': true,
      },
      reportFormatId: 'rf456',
    });
  });

  test('should open and close create dialog', async () => {
    stubNativeFetch(nativeReportFormatsPayload);
    let createClick;
    const children = testing.fn(({create}) => {
      createClick = create;
    });
    const gmp = createGmp();

    const {render} = rendererWith({
      gmp,
      router: true,
      store: true,
    });

    const {baseElement} = render(
      <ReportFormatComponent>{children}</ReportFormatComponent>,
    );
    createClick();
    await wait();

    expect(baseElement).toHaveTextContent('New Report Config');

    const closeButton = screen.getDialogCloseButton();
    fireEvent.click(closeButton);
    await wait();

    expect(baseElement).not.toHaveTextContent('New Report Config');
  });
});
