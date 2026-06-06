# SPDX-FileCopyrightText: 2026 TurboVAS contributors
#
# SPDX-License-Identifier: GPL-3.0-or-later

from argparse import Namespace

from gvm.protocols.gmp import Gmp
from gvmtools.helper import Table


def main(gmp: Gmp, args: Namespace) -> None:
    # pylint: disable=unused-argument

    response_xml = gmp.get_scope_reports(details=True)
    reports_xml = response_xml.xpath("scope_report")

    heading = [
        "#",
        "Name",
        "Id",
        "Scope",
        "Created",
        "Latest Evidence",
        "Source Reports",
        "Hosts With Evidence",
        "Vulnerabilities",
    ]
    rows = []

    print("Listing scope reports.\n")

    for number, report in enumerate(reports_xml, start=1):
        counts = report.find("counts")
        rows.append(
            [
                str(number),
                "".join(report.xpath("name/text()")),
                report.get("id"),
                "".join(report.xpath("scope/name/text()")),
                "".join(report.xpath("created/text()")),
                "".join(report.xpath("latest_evidence_time/text()")),
                "" if counts is None else "".join(counts.xpath("source_reports/text()")),
                "" if counts is None else "".join(counts.xpath("hosts_with_evidence/text()")),
                "" if counts is None else "".join(counts.xpath("vulnerabilities_total/text()")),
            ]
        )

    print(Table(heading=heading, rows=rows))


if __name__ == "__gmp__":
    main(gmp, args)
