/* SPDX-FileCopyrightText: 2025 Greenbone AG
 * TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {describe, test, expect, testing} from '@gsa/testing';
import {fireEvent, rendererWith, screen, wait} from 'web/testing';
import {createActionResultResponse} from 'gmp/commands/testing';
import Response from 'gmp/http/response';
import type Model from 'gmp/models/model';
import Setting from 'gmp/models/setting';
import Target, {SCAN_CONFIG_DEFAULT} from 'gmp/models/target';
import {createSession} from 'gmp/testing';
import Button from 'web/components/form/Button';
import TargetComponent from 'web/pages/targets/TargetComponent';
import {
  DEFAULT_PORT_LIST_ID,
  DEFAULT_PORT_LIST_NAME,
} from 'web/pages/targets/TargetDialog';

const createGmp = ({
  credentials = [],
  portlists = [],
}: {credentials?: Model[]; portlists?: Model[]} = {}) => {
  return {
    settings: {
      enableGreenboneSensor: true,
      enableKrb5: false,
    },
    session: createSession(),
    user: {
      currentSettings: testing.fn().mockResolvedValue(
        new Response({
          detailsexportfilename: new Setting({
            _id: 'a6ac88c5-729c-41ba-ac0a-deea4a3441f2',
            name: 'Details Export File Name',
            value: '%T-%U',
          }),
        }),
      ),
    },
    credentials: {
      getAll: testing.fn().mockResolvedValue(new Response(credentials)),
    },
    portlists: {
      getAll: testing.fn().mockResolvedValue(new Response(portlists)),
    },
    target: {
      create: testing
        .fn()
        .mockResolvedValue(createActionResultResponse({id: 'new-id'})),
      save: testing
        .fn()
        .mockResolvedValue(createActionResultResponse({id: 'saved-id'})),
      clone: testing
        .fn()
        .mockResolvedValue(createActionResultResponse({id: 'cloned-id'})),
      export: testing.fn().mockResolvedValue(new Response('some-data')),
    },
  };
};

describe('TargetComponent tests', () => {
  test('should render', async () => {
    const gmp = createGmp();
    const {render} = rendererWith({gmp});

    render(
      <TargetComponent>
        {() => <Button data-testid="button" />}
      </TargetComponent>,
    );

    expect(screen.getByTestId('button')).toBeInTheDocument();
  });

  test('should report target dialog preparation failures without an unhandled rejection', async () => {
    const gmp = createGmp();
    const failure = new Error('credential inventory unavailable');
    gmp.credentials.getAll.mockRejectedValue(failure);
    const onCreateError = testing.fn();
    const {render} = rendererWith({gmp, capabilities: true});

    render(
      <TargetComponent onCreateError={onCreateError}>
        {({create}) => <Button data-testid="button" onClick={() => create()} />}
      </TargetComponent>,
    );

    fireEvent.click(screen.getByTestId('button'));

    await expect.poll(() => onCreateError).toHaveBeenCalledWith(failure);
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });

  test('should serialize target dialog preparation and release its lock', async () => {
    let resolveCredentials: (value: Response<Model[]>) => void = () => {};
    const credentials = new Promise<Response<Model[]>>(resolve => {
      resolveCredentials = resolve;
    });
    const gmp = createGmp();
    gmp.credentials.getAll.mockReturnValueOnce(credentials);
    let createTarget: (() => Promise<void>) | undefined;
    const {render} = rendererWith({gmp, capabilities: true});

    render(
      <TargetComponent>
        {({create}) => {
          createTarget = create;
          return <Button data-testid="button" />;
        }}
      </TargetComponent>,
    );

    const first = createTarget?.();
    const competing = createTarget?.();
    expect(gmp.credentials.getAll).toHaveBeenCalledTimes(1);
    expect(gmp.portlists.getAll).toHaveBeenCalledTimes(1);

    resolveCredentials(new Response([]));
    await first;
    await competing;
    await expect.poll(() => screen.getDialog()).toBeInTheDocument();

    await createTarget?.();
    expect(gmp.credentials.getAll).toHaveBeenCalledTimes(2);
    expect(gmp.portlists.getAll).toHaveBeenCalledTimes(2);
  });

  test('should load dialog credentials and port lists through the native API when available', async () => {
    const gmp = {
      ...createGmp(),
      buildUrl: testing.fn((path: string) => `https://yafvs.example/${path}`),
      session: createSession({token: 'test-token'}),
    };
    const fetchMock = testing.fn((url: string) => {
      const payload = url.endsWith('/credentials')
        ? {
            page: {
              page: 1,
              page_size: 1000,
              total: 0,
              sort: 'name',
              filter: '',
            },
            items: [],
          }
        : {
            page: {
              page: 1,
              page_size: 1000,
              total: 1,
              sort: 'name',
              filter: '',
            },
            items: [
              {
                id: DEFAULT_PORT_LIST_ID,
                name: DEFAULT_PORT_LIST_NAME,
                predefined: true,
                port_count: {all: 7594, tcp: 7594, udp: 0},
              },
            ],
          };
      return Promise.resolve({
        json: testing.fn().mockResolvedValue(payload),
        ok: true,
        status: 200,
      });
    });
    testing.stubGlobal('fetch', fetchMock);
    const {render} = rendererWith({gmp, capabilities: true});

    render(
      <TargetComponent>
        {({create}) => <Button data-testid="button" onClick={() => create()} />}
      </TargetComponent>,
    );

    fireEvent.click(screen.getByTestId('button'));

    await screen.findByText('New Target');

    expect(gmp.credentials.getAll).not.toHaveBeenCalled();
    expect(gmp.portlists.getAll).not.toHaveBeenCalled();
    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/credentials', {
      token: 'test-token',
      page: 1,
      page_size: 1000,
      sort: 'name',
      filter: '',
    });
    expect(gmp.buildUrl).toHaveBeenCalledWith('api/v1/port-lists', {
      token: 'test-token',
      page: 1,
      page_size: 1000,
      sort: 'name',
      filter: '',
    });
    expect(fetchMock).toHaveBeenCalledWith(
      'https://yafvs.example/api/v1/port-lists',
      expect.objectContaining({
        credentials: 'include',
      }),
    );
    expect(screen.getByName('portListId')).toHaveValue(DEFAULT_PORT_LIST_ID);
  });

  test('should allow to create a new target', async () => {
    const gmp = createGmp();
    const {render} = rendererWith({gmp, capabilities: true});
    const onCreated = testing.fn();

    render(
      <TargetComponent onCreated={onCreated}>
        {({create}) => <Button data-testid="button" onClick={() => create()} />}
      </TargetComponent>,
    );

    const button = screen.getByTestId('button');
    fireEvent.click(button);

    await wait();

    expect(screen.getDialog()).toBeInTheDocument();
    fireEvent.click(screen.getDialogSaveButton());

    expect(gmp.target.create).toHaveBeenCalledWith({
      aliveTests: [SCAN_CONFIG_DEFAULT],
      allowSimultaneousIPs: true,
      comment: '',
      esxiCredentialId: undefined,
      excludeHosts: '',
      hosts: '',
      hostsCount: undefined,
      id: undefined,
      inUse: false,
      krb5CredentialId: undefined,
      name: 'Unnamed',
      port: 22,
      portListId: DEFAULT_PORT_LIST_ID,
      reverseLookupOnly: false,
      reverseLookupUnify: false,
      smbCredentialId: undefined,
      snmpCredentialId: undefined,
      sshCredentialId: undefined,
      sshElevateCredentialId: undefined,
      sshHostKeyPins: '',
      targetExcludeSource: 'manual',
      targetSource: 'manual',
    });

    await wait();

    expect(onCreated).toHaveBeenCalledWith(
      expect.objectContaining({
        _data: {
          envelope: {
            action_result: expect.objectContaining({
              id: 'new-id',
            }),
          },
        },
      }),
    );
  });

  test('should clear hidden asset IDs when switching to a manual target', async () => {
    const gmp = createGmp();
    let createTarget: (data?: {
      hostAssetIds?: string[];
      hostsCount?: number;
      targetSource?: 'manual' | 'file' | 'asset_hosts';
    }) => Promise<void> = async () => {};
    const {render} = rendererWith({gmp, capabilities: true});

    render(
      <TargetComponent>
        {({create}) => {
          createTarget = create;
          return <Button data-testid="button" />;
        }}
      </TargetComponent>,
    );

    await createTarget({
      hostAssetIds: ['11111111-1111-4111-8111-111111111111'],
      hostsCount: 1,
      targetSource: 'asset_hosts',
    });
    await expect.poll(() => screen.getDialog()).toBeInTheDocument();

    fireEvent.click(screen.getAllByName('targetSource')[0]);
    fireEvent.change(screen.getByName('hosts'), {
      target: {value: '192.0.2.10'},
    });
    fireEvent.click(screen.getDialogSaveButton());

    await expect
      .poll(() => gmp.target.create)
      .toHaveBeenCalledWith(
        expect.objectContaining({
          hostAssetIds: undefined,
          hosts: '192.0.2.10',
          targetSource: 'manual',
        }),
      );
  });

  test('should allow to edit an existing target', async () => {
    const gmp = createGmp();
    const target = new Target({name: 'My Target', id: '1234'});
    const onSaved = testing.fn();

    const {render} = rendererWith({gmp, capabilities: true});

    render(
      <TargetComponent onSaved={onSaved}>
        {({edit}) => (
          <Button data-testid="button" onClick={() => edit(target)} />
        )}
      </TargetComponent>,
    );

    const button = screen.getByTestId('button');
    fireEvent.click(button);

    await wait();

    expect(screen.getDialog()).toBeInTheDocument();
    fireEvent.click(screen.getDialogSaveButton());

    expect(gmp.target.save).toHaveBeenCalledWith({
      aliveTests: [],
      allowSimultaneousIPs: false,
      comment: '',
      esxiCredentialId: undefined,
      excludeHosts: '',
      hosts: '',
      hostsCount: undefined,
      id: '1234',
      inUse: false,
      krb5CredentialId: undefined,
      name: 'My Target',
      port: 22,
      portListId: DEFAULT_PORT_LIST_ID,
      reverseLookupOnly: false,
      reverseLookupUnify: false,
      smbCredentialId: undefined,
      snmpCredentialId: undefined,
      sshCredentialId: undefined,
      sshElevateCredentialId: undefined,
      sshHostKeyPins: '',
      targetExcludeSource: 'manual',
      targetSource: 'manual',
    });

    await wait();

    expect(onSaved).toHaveBeenCalledWith(
      expect.objectContaining({
        _data: {
          envelope: {
            action_result: expect.objectContaining({
              id: 'saved-id',
            }),
          },
        },
      }),
    );
  });

  test('should allow to clone an existing target', async () => {
    const gmp = createGmp();
    const target = new Target({name: 'My Target', id: '1234'});
    const onCloned = testing.fn();

    const {render} = rendererWith({gmp, capabilities: true});

    render(
      <TargetComponent onCloned={onCloned}>
        {({clone}) => (
          <Button data-testid="button" onClick={() => clone(target)} />
        )}
      </TargetComponent>,
    );

    const button = screen.getByTestId('button');
    fireEvent.click(button);
    expect(gmp.target.clone).toHaveBeenCalledWith(target);

    await wait();

    expect(onCloned).toHaveBeenCalledWith(
      expect.objectContaining({
        _data: {
          envelope: {
            action_result: expect.objectContaining({
              id: 'cloned-id',
            }),
          },
        },
      }),
    );
  });

  test('should allow to download a target', async () => {
    const gmp = createGmp();
    const target = new Target({name: 'My Target', id: '1234'});

    const {render} = rendererWith({gmp, capabilities: true});
    const onDownloaded = testing.fn();

    render(
      <TargetComponent
        onDownloadError={onDownloaded}
        onDownloaded={onDownloaded}
      >
        {({download}) => (
          <Button data-testid="button" onClick={() => download(target)} />
        )}
      </TargetComponent>,
    );

    // allow user settings to load
    await wait();

    const button = screen.getByTestId('button');
    fireEvent.click(button);
    expect(gmp.target.export).toHaveBeenCalledWith(target);

    await wait();

    expect(onDownloaded).toHaveBeenCalledWith({
      data: 'some-data',
      filename: 'target-1234.xml',
    });
  });
});
