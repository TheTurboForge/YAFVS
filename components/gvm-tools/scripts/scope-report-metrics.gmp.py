# SPDX-FileCopyrightText: 2026 TurboVAS contributors
#
# SPDX-License-Identifier: GPL-3.0-or-later

from argparse import ArgumentParser, Namespace, RawTextHelpFormatter

from gvm.protocols.gmp import Gmp
from gvmtools.helper import Table


def parse_args(args: Namespace) -> Namespace:
    parser = ArgumentParser(
        prefix_chars="+",
        add_help=False,
        formatter_class=RawTextHelpFormatter,
        description="Show TurboVAS CVSS Load and authenticated coverage metrics for a scope report.",
    )
    parser.add_argument("+h", "++help", action="help", help="Show this help message and exit.")
    parser.add_argument("scope_report_id", help="Scope report UUID")
    script_args = args.script[1:] if args.script else []
    parsed_args, _ = parser.parse_known_args(script_args)
    return parsed_args


def main(gmp: Gmp, args: Namespace) -> None:
    parsed_args = parse_args(args)
    response_xml = gmp.get_scope_report_metrics(parsed_args.scope_report_id)
    metrics = response_xml.find("scope_report_metrics")
    summary = None if metrics is None else metrics.find("summary")
    heading = ["Metric", "Value"]
    rows = []
    for metric in (
        "alive_system_count",
        "total_system_cvss_load",
        "average_system_cvss_load",
        "vulnerability_count",
        "authenticated_scan_coverage_percent",
    ):
        rows.append([metric, "" if summary is None else "".join(summary.xpath(f"{metric}/text()"))])

    print("Scope report metrics.\n")
    print(Table(heading=heading, rows=rows))


if __name__ == "__gmp__":
    main(gmp, args)
