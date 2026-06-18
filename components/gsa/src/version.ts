/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * Modified by TurboVAS contributors, 2026.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

const getMajorMinorVersion = () => {
  const [major, minor] = VERSION.split('.');
  const minorVersion = parseInt(minor);
  return `${major}.${minorVersion}`;
};

export const VERSION = '0.1.0-alpha.0';

export const RELEASE_VERSION = getMajorMinorVersion();

export default VERSION;
