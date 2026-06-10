# SPDX-FileCopyrightText: 2026 TurboVAS contributors
#
# SPDX-License-Identifier: GPL-3.0-or-later

from argparse import ArgumentParser, Namespace, RawTextHelpFormatter

from gvm.protocols.gmp import Gmp
from gvmtools.helper import Table


DEFAULT_FILTER = "levels=chml rows=50 first=1 sort-reverse=severity min_qod=70"


def parse_args(args: Namespace) -> Namespace:
    parser = ArgumentParser(
        prefix_chars="+",
        add_help=False,
        formatter_class=RawTextHelpFormatter,
        description="List deduplicated result rows for a TurboVAS scope report.",
    )
    parser.add_argument(
        "+h",
        "++help",
        action="help",
        help="Show this help message and exit.",
    )
    parser.add_argument("scope_report_id", help="Scope report UUID")
    parser.add_argument(
        "++filter",
        default=DEFAULT_FILTER,
        help=f"Result filter string. Default: {DEFAULT_FILTER}",
    )
    script_args = args.script[1:] if args.script else []
    parsed_args, _ = parser.parse_known_args(script_args)
    return parsed_args


def main(gmp: Gmp, args: Namespace) -> None:
    parsed_args = parse_args(args)
    response_xml = gmp.get_scope_report_results(
        parsed_args.scope_report_id,
        filter_string=parsed_args.filter,
        details=False,
    )
    results_xml = response_xml.xpath("result")

    heading = ["#", "Result", "Vulnerability", "Severity", "QoD", "Host", "Port", "Raw Report"]
    rows = []

    print("Listing scope report results.\n")

    for number, result in enumerate(results_xml, start=1):
        rows.append(
            [
                str(number),
                result.get("id"),
                "".join(result.xpath("name/text()")),
                "".join(result.xpath("severity/text()")),
                "".join(result.xpath("qod/value/text()")),
                "".join(result.xpath("host/text()")),
                "".join(result.xpath("port/text()")),
                "".join(result.xpath("report/@id")),
            ]
        )

    print(Table(heading=heading, rows=rows))


if __name__ == "__gmp__":
    main(gmp, args)
