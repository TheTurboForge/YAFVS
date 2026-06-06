# SPDX-FileCopyrightText: 2026 TurboVAS contributors
#
# SPDX-License-Identifier: GPL-3.0-or-later

from argparse import Namespace

from gvm.protocols.gmp import Gmp
from gvmtools.helper import Table


def main(gmp: Gmp, args: Namespace) -> None:
    # pylint: disable=unused-argument

    response_xml = gmp.get_scopes(details=True)
    scopes_xml = response_xml.xpath("scope")

    heading = [
        "#",
        "Name",
        "Id",
        "Protection Requirement",
        "Targets",
        "Hosts",
        "Scope Reports",
    ]
    rows = []

    print("Listing scopes.\n")

    for number, scope in enumerate(scopes_xml, start=1):
        counts = scope.find("counts")
        rows.append(
            [
                str(number),
                "".join(scope.xpath("name/text()")),
                scope.get("id"),
                "".join(scope.xpath("protection_requirement/label/text()")),
                "" if counts is None else "".join(counts.xpath("targets/text()")),
                "" if counts is None else "".join(counts.xpath("hosts/text()")),
                "" if counts is None else "".join(counts.xpath("scope_reports/text()")),
            ]
        )

    print(Table(heading=heading, rows=rows))


if __name__ == "__gmp__":
    main(gmp, args)
