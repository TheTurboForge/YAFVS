/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * Modified by TurboVAS contributors, 2026.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {describe, test, expect, testing} from '@gsa/testing';
import {
  changeInputValue,
  screen,
  rendererWith,
  fireEvent,
  getSelectItemElementsForSelect,
  wait,
} from 'web/testing';
import Features from 'gmp/capabilities/features';
import {
  GREENBONE_SENSOR_SCANNER_TYPE,
  OPENVAS_SCANNER_TYPE,
  OPENVASD_SCANNER_TYPE,
} from 'gmp/models/scanner';
import ScannerDialog from 'web/pages/scanners/ScannerDialog';

const createGmp = ({enableGreenboneSensor = true} = {}) => {
  return {settings: {enableGreenboneSensor}};
};

describe('ScannerDialog tests', () => {
  test('should display defaults without scanner type provided', async () => {
    const gmp = createGmp({enableGreenboneSensor: false});
    const handleSave = testing.fn();

    const {render} = rendererWith({gmp, capabilities: true});

    render(<ScannerDialog onSave={handleSave} />);

    expect(screen.getByName('name')).toHaveValue('Unnamed');
    expect(screen.getByName('comment')).toHaveValue(''); // comment field

    const scannerType = screen.getByRole('textbox', {name: 'Scanner Type'});
    expect(scannerType).toHaveValue('');

    expect(screen.queryByName('host')).not.toBeInTheDocument();
    expect(screen.queryByName('port')).not.toBeInTheDocument();
    expect(screen.queryByName('caCertificate')).not.toBeInTheDocument();
    expect(
      screen.queryByRole('textbox', {name: 'Credential'}),
    ).not.toBeInTheDocument();

    fireEvent.click(screen.getDialogSaveButton());
    expect(handleSave).toHaveBeenCalledWith({
      caCertificate: undefined,
      host: 'localhost',
      name: 'Unnamed',
      comment: '',
      credentialId: undefined,
      type: undefined,
      id: undefined,
      port: '',
    });
  });

  test('should display defaults for greenbone sensor', async () => {
    const gmp = createGmp();
    const handleSave = testing.fn();

    const {render} = rendererWith({gmp, capabilities: true});

    render(
      <ScannerDialog
        type={GREENBONE_SENSOR_SCANNER_TYPE}
        onSave={handleSave}
      />,
    );

    expect(screen.getByName('name')).toHaveValue('Unnamed');
    expect(screen.getByName('comment')).toHaveValue(''); // comment field

    expect(screen.getDialog()).toBeInTheDocument();
    const scannerType = screen.getByRole('textbox', {name: 'Scanner Type'});
    expect(scannerType).toHaveValue('Greenbone Sensor');
    expect(screen.getByName('host')).toHaveValue('localhost');
    expect(screen.queryByName('port')).not.toBeInTheDocument();
    expect(screen.queryByName('caCertificate')).not.toBeInTheDocument();
    expect(
      screen.queryByRole('textbox', {name: 'Credential'}),
    ).not.toBeInTheDocument();

    fireEvent.click(screen.getDialogSaveButton());
    expect(handleSave).toHaveBeenCalledWith({
      caCertificate: undefined,
      host: 'localhost',
      name: 'Unnamed',
      comment: '',
      credentialId: undefined,
      type: GREENBONE_SENSOR_SCANNER_TYPE,
      id: undefined,
      port: 22,
    });
  });


  test('should display defaults for openvas scanner', async () => {
    const gmp = createGmp();
    const handleSave = testing.fn();

    const {render} = rendererWith({
      gmp,
      capabilities: true,
      features: new Features(['ENABLE_OPENVASD']),
    });

    render(<ScannerDialog type={OPENVAS_SCANNER_TYPE} onSave={handleSave} />);

    expect(screen.getByName('name')).toHaveValue('Unnamed');
    expect(screen.getByName('comment')).toHaveValue('');

    const scannerType = screen.getByRole('textbox', {name: 'Scanner Type'});
    expect(scannerType).toHaveValue('OpenVAS Scanner');

    expect(screen.getByName('host')).toHaveValue('localhost');
    expect(screen.getByName('port')).toHaveValue('');
    expect(screen.getByName('caCertificate')).toHaveValue('');
    expect(screen.getByRole('textbox', {name: 'Credential'})).toHaveValue('');

    fireEvent.click(screen.getDialogSaveButton());
    expect(handleSave).toHaveBeenCalledWith({
      caCertificate: undefined,
      host: 'localhost',
      name: 'Unnamed',
      comment: '',
      credentialId: undefined,
      type: OPENVAS_SCANNER_TYPE,
      id: undefined,
      port: '',
    });
  });

  test('should display defaults for openvasd scanner', async () => {
    const gmp = createGmp();
    const handleSave = testing.fn();

    const {render} = rendererWith({
      gmp,
      capabilities: true,
      features: new Features(['ENABLE_OPENVASD']),
    });

    render(<ScannerDialog type={OPENVASD_SCANNER_TYPE} onSave={handleSave} />);

    expect(screen.getByName('name')).toHaveValue('Unnamed');
    expect(screen.getByName('comment')).toHaveValue('');
    expect(screen.getByName('host')).toHaveValue('localhost');
    expect(screen.getByName('port')).toHaveValue('443');

    const scannerType = screen.getByRole('textbox', {name: 'Scanner Type'});
    expect(scannerType).toHaveValue('OpenVASD Scanner');
    expect(screen.getByRole('textbox', {name: 'Credential'})).toHaveValue('');
    expect(screen.getByName('caCertificate')).toHaveValue('');

    fireEvent.click(screen.getDialogSaveButton());
    expect(handleSave).toHaveBeenCalledWith({
      caCertificate: undefined,
      host: 'localhost',
      name: 'Unnamed',
      comment: '',
      credentialId: undefined,
      type: OPENVASD_SCANNER_TYPE,
      id: undefined,
      port: 443,
    });
  });



  test('should display value from props', async () => {
    const gmp = createGmp();
    const handleClose = testing.fn();
    const handleSave = testing.fn();

    const {render} = rendererWith({gmp, capabilities: true});

    render(
      <ScannerDialog
        comment="lorem ipsum"
        host="mypc"
        name="john"
        type={GREENBONE_SENSOR_SCANNER_TYPE}
        onClose={handleClose}
        onSave={handleSave}
      />,
    );

    const inputs = screen.queryTextInputs();

    expect(inputs[0]).toHaveAttribute('name', 'name');
    expect(inputs[0]).toHaveAttribute('value', 'john');

    expect(inputs[1]).toHaveAttribute('name', 'comment');
    expect(inputs[1]).toHaveAttribute('value', 'lorem ipsum');

    expect(inputs[2]).toHaveAttribute('name', 'host');
    expect(inputs[2]).toHaveAttribute('value', 'mypc');

    const scannerType = screen.getByRole('textbox', {name: 'Scanner Type'});
    expect(scannerType).toHaveValue('Greenbone Sensor');
  });

  test('should allow to save dialog', async () => {
    const gmp = createGmp();
    const handleClose = testing.fn();
    const handleCredentialChange = testing.fn();
    const handleSave = testing.fn();

    const {render} = rendererWith({gmp, capabilities: true});

    render(
      <ScannerDialog
        comment="lorem ipsum"
        host="mypc"
        id="1234"
        name="john"
        type={GREENBONE_SENSOR_SCANNER_TYPE}
        onClose={handleClose}
        onCredentialChange={handleCredentialChange}
        onSave={handleSave}
      />,
    );

    const saveButton = screen.getDialogSaveButton();

    fireEvent.click(saveButton);

    expect(handleSave).toHaveBeenCalledWith({
      caCertificate: undefined,
      host: 'mypc',
      name: 'john',
      comment: 'lorem ipsum',
      credentialId: undefined,
      type: GREENBONE_SENSOR_SCANNER_TYPE,
      id: '1234',
      port: 22,
    });
  });




  test('should allow to close the dialog', async () => {
    const gmp = createGmp();
    const handleClose = testing.fn();
    const handleSave = testing.fn();

    const {render} = rendererWith({gmp, capabilities: true});

    render(<ScannerDialog onClose={handleClose} onSave={handleSave} />);

    const closeButton = screen.getDialogCloseButton();
    fireEvent.click(closeButton);
    expect(handleClose).toHaveBeenCalled();
    expect(handleSave).not.toHaveBeenCalled();
  });




  test('should allow to set a CA certificate of a scanner', async () => {
    const gmp = createGmp();
    const handleClose = testing.fn();
    const handleSave = testing.fn();

    const {render} = rendererWith({gmp, capabilities: true});

    render(
      <ScannerDialog
        type={OPENVAS_SCANNER_TYPE}
        onClose={handleClose}
        onSave={handleSave}
      />,
    );
    const caCertificateInput = screen.getByName('caCertificate');
    const content =
      '-----BEGIN CERTIFICATE-----\nfoo\n-----END CERTIFICATE-----';
    const file = new File([content], 'ca.crt', {
      type: 'text/plain',
    });
    // jsdom does not implement file.text() so we need to mock it
    file.text = testing.fn().mockResolvedValue(content);
    fireEvent.change(caCertificateInput, {
      target: {files: [file]},
    });

    // wait for the file to be read
    await wait();

    fireEvent.click(screen.getDialogSaveButton());
    expect(handleSave).toHaveBeenCalledWith({
      caCertificate: file,
      host: 'localhost',
      name: 'Unnamed',
      comment: '',
      credentialId: undefined,
      type: OPENVAS_SCANNER_TYPE,
      id: undefined,
      port: '',
    });
  });

  test('should render openvasd in scanner selection if feature is enabled', async () => {
    const gmp = createGmp({enableGreenboneSensor: false}); // no sensor
    const {render} = rendererWith({
      gmp, // no sensor
      capabilities: true,
      features: new Features(['ENABLE_OPENVASD']),
    });

    render(<ScannerDialog type={OPENVASD_SCANNER_TYPE} />);

    expect(screen.getDialog()).toBeInTheDocument();
    const scannerType = screen.getByRole<HTMLSelectElement>('textbox', {
      name: 'Scanner Type',
    });
    expect(scannerType).toHaveValue('OpenVASD Scanner');
    const scannerTypeItems = await getSelectItemElementsForSelect(scannerType);
    expect(scannerTypeItems.length).toEqual(3); // OpenVAS Scanner, OpenVASD Scanner and OpenVASD Sensor
    expect(scannerTypeItems[0]).toHaveTextContent('OpenVAS Scanner');
    expect(scannerTypeItems[1]).toHaveTextContent('OpenVASD Scanner');
    expect(scannerTypeItems[2]).toHaveTextContent('OpenVASD Sensor');
  });

  test('should not render openvasd in scanner selection if feature is disabled', async () => {
    const gmp = createGmp();
    const {render} = rendererWith({
      gmp,
      capabilities: true,
      features: new Features([]), // no OPENVASD feature
    });

    render(<ScannerDialog type={OPENVASD_SCANNER_TYPE} />);

    expect(screen.getDialog()).toBeInTheDocument();
    const scannerType = screen.getByRole<HTMLSelectElement>('textbox', {
      name: 'Scanner Type',
    });
    expect(scannerType).toHaveValue('');
    const scannerTypeItems = await getSelectItemElementsForSelect(scannerType);
    expect(scannerTypeItems.length).toEqual(2); // OpenVAS Scanner and Greenbone Sensor
    expect(scannerTypeItems[0]).toHaveTextContent('OpenVAS Scanner');
    expect(scannerTypeItems[1]).toHaveTextContent('Greenbone Sensor');
  });



  test('should use greenbone sensor scanner as default if enabled and no initial scanner type', async () => {
    const gmp = createGmp();
    const handleClose = testing.fn();
    const handleCredentialChange = testing.fn();
    const handleSave = testing.fn();

    const {render} = rendererWith({gmp, capabilities: true});

    render(
      <ScannerDialog
        onClose={handleClose}
        onCredentialChange={handleCredentialChange}
        onSave={handleSave}
      />,
    );

    expect(screen.getDialog()).toBeInTheDocument();
    const scannerType = screen.getByRole('textbox', {name: 'Scanner Type'});
    expect(scannerType).toHaveValue('Greenbone Sensor');
  });
});
