/* SPDX-FileCopyrightText: 2024 Greenbone AG
 * Modified by TurboVAS contributors, 2026.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

import {type ComplianceType} from 'gmp/models/compliance';
import Model, {type ModelElement, type ModelProperties} from 'gmp/models/model';
import Nvt, {type NvtEpssElement} from 'gmp/models/nvt';
import Override, {type OverrideElement} from 'gmp/models/override';
import {
  parseSeverity,
  parseQod,
  type QoD,
  parseToString,
  type QoDParams,
  parseFloat,
} from 'gmp/parser';
import {forEach, map} from 'gmp/utils/array';
import {isDefined} from 'gmp/utils/identity';

interface CveResult {
  name: string;
  id: string;
  epss?: Epss;
}

interface ResultInformationElement {
  epss?: NvtEpssElement;
  name?: string;
  type?: string;
}

type ResultCveElement = ResultInformationElement;

interface EpssValue {
  percentile?: number;
  score?: number;
  cve?: {
    id?: string;
    severity?: number;
  };
}

interface Epss {
  maxEpss?: EpssValue;
  maxSeverity?: EpssValue;
}

interface ResultDetectionDetailElement {
  name: string;
  value: string;
}

interface SeverityElement {
  _type?: string;
  date?: string;
  origin?: string;
  score?: number;
  value?: string;
}

interface ResultNvtElement extends ResultInformationElement {
  _oid?: string;
  cvss_base?: number;
  family?: string;
  severities?: {
    _score?: number | string;
    severity?: SeverityElement;
  };
  solution?: {
    __text?: string;
    _type?: string;
  };
  tags?: string;
}

interface ResultElement extends ModelElement {
  compliance?: string;
  description?: string;
  detection?: {
    result?: {
      _id?: string;
      details?: {
        detail?: ResultDetectionDetailElement | ResultDetectionDetailElement[];
      };
    };
  };
  host?: {
    __text?: string;
    asset?: {
      _asset_id?: string;
    };
    hostname?: string;
  };
  nvt?: ResultNvtElement | ResultCveElement;
  original_severity?: number;
  overrides?: {
    override?: OverrideElement | OverrideElement[];
  };
  port?: string;
  report?: {
    _id?: string;
  };
  scan_nvt_version?: string;
  severity?: number;
  task?: {
    _id?: string;
    name?: string;
  };
  threat?: string;
  qod?: QoDParams;
}

interface ResultHost {
  name?: string;
  id?: string;
  hostname?: string;
}

interface ResultDetectionResult {
  id?: string;
  details?: Record<string, string>;
}

interface ResultDetection {
  result: ResultDetectionResult;
}

interface ResultProperties extends ModelProperties {
  compliance?: ComplianceType;
  detection?: ResultDetection;
  description?: string;
  host?: ResultHost;
  information?: Nvt | CveResult;
  original_severity?: number;
  overrides?: Override[];
  port?: string;
  qod?: QoD;
  report?: Model;
  scan_nvt_version?: string;
  severity?: number;
  task?: Model;
  vulnerability?: string;
}

const createCveResult = ({name, epss}: ResultCveElement): CveResult => {
  const retEpss: Epss = {};

  if (isDefined(epss?.max_epss)) {
    retEpss.maxEpss = {
      percentile: parseFloat(epss?.max_epss?.percentile),
      score: parseFloat(epss?.max_epss?.score),
    };
    if (isDefined(epss?.max_epss?.cve)) {
      retEpss.maxEpss.cve = {
        id: epss?.max_epss?.cve?._id,
        severity: parseFloat(epss?.max_epss?.cve?.severity),
      };
    }
  }
  if (isDefined(epss?.max_severity)) {
    retEpss.maxSeverity = {
      percentile: parseFloat(epss?.max_severity?.percentile),
      score: parseFloat(epss?.max_severity?.score),
    };
    if (isDefined(epss?.max_severity?.cve)) {
      retEpss.maxSeverity.cve = {
        id: epss?.max_severity?.cve?._id,
        severity: parseFloat(epss?.max_severity?.cve?.severity),
      };
    }
  }

  return {
    name: name as string,
    id: name as string,
    epss: retEpss,
  };
};

class Result extends Model {
  static readonly entityType = 'result';

  readonly compliance?: ComplianceType;
  readonly detection?: ResultDetection;
  readonly description?: string;
  readonly host?: ResultHost;
  readonly information?: Nvt | CveResult;
  readonly original_severity?: number;
  readonly overrides: Override[];
  readonly port?: string;
  readonly qod?: QoD;
  readonly report?: Model;
  readonly scan_nvt_version?: string;
  readonly severity?: number;
  readonly task?: Model;
  readonly vulnerability?: string;

  constructor({
    compliance,
    detection,
    description,
    host,
    information,
    // eslint-disable-next-line @typescript-eslint/naming-convention
    original_severity,
    overrides = [],
    port,
    qod,
    report,
    // eslint-disable-next-line @typescript-eslint/naming-convention
    scan_nvt_version,
    severity,
    task,
    vulnerability,
    ...properties
  }: ResultProperties = {}) {
    super(properties);

    this.compliance = compliance;
    this.detection = detection;
    this.description = description;
    this.host = host;
    this.information = information;
    this.original_severity = original_severity;
    this.overrides = overrides;
    this.port = port;
    this.qod = qod;
    this.report = report;
    this.scan_nvt_version = scan_nvt_version;
    this.severity = severity;
    this.task = task;
    this.vulnerability = vulnerability;
  }

  static fromElement(element: ResultElement = {}): Result {
    return new Result(this.parseElement(element));
  }

  static parseElement(element: ResultElement = {}): ResultProperties {
    const copy = super.parseElement(element) as ResultProperties;

    const {
      compliance,
      description,
      detection,
      host,
      name,
      nvt: information,
      original_severity,
      overrides,
      report,
      severity,
      task,
      qod,
    } = element;

    if (isDefined(host)) {
      copy.host = {
        name: parseToString(host.__text),
        id: parseToString(host.asset?._asset_id),
        hostname: parseToString(host.hostname),
      };
    }

    if (isDefined(information)) {
      if (information.type === 'nvt') {
        copy.information = Nvt.fromElement({
          nvt: information,
        } as ResultNvtElement);
      } else {
        copy.information = createCveResult(information as ResultCveElement);
        copy.name = name ?? information.name;
      }
    }

    copy.description = parseToString(description);
    copy.compliance = parseToString(compliance) as ComplianceType;
    copy.port = parseToString(element.port);
    copy.scan_nvt_version = parseToString(element.scan_nvt_version);
    copy.severity = parseSeverity(severity);
    copy.vulnerability = isDefined(name)
      ? name
      : (information as ResultNvtElement)?._oid;

    copy.report = isDefined(report)
      ? Model.fromElement(report, 'report')
      : undefined;
    copy.task = isDefined(task) ? Model.fromElement(task, 'task') : undefined;

    if (isDefined(detection) && isDefined(detection.result)) {
      const details = {};

      if (isDefined(detection.result.details)) {
        forEach(detection.result.details.detail, detail => {
          details[detail.name] = detail.value;
        });
      }

      copy.detection = {
        result: {
          id: detection.result._id,
          details: details,
        },
      };
    }

    copy.original_severity = isDefined(original_severity)
      ? parseSeverity(original_severity)
      : undefined;
    copy.qod = isDefined(qod) ? parseQod(qod) : undefined;
    copy.overrides = map(overrides?.override, override =>
      Override.fromElement(override),
    );

    return copy;
  }
}

export default Result;
