# SPDX-FileCopyrightText: 2026 TurboVAS contributors
#
# SPDX-License-Identifier: GPL-3.0-or-later

from argparse import ArgumentParser, Namespace, RawTextHelpFormatter

from gvm.protocols.gmp import Gmp


def parse_args(args: Namespace) -> Namespace:
    parser = ArgumentParser(
        prefix_chars="+",
        add_help=False,
        formatter_class=RawTextHelpFormatter,
        description="Generate a TurboVAS scope report.",
    )
    parser.add_argument(
        "+h",
        "++help",
        action="help",
        help="Show this help message and exit.",
    )
    parser.add_argument("scope_id", help="Scope UUID")
    script_args = args.script[1:] if args.script else []
    parsed_args, _ = parser.parse_known_args(script_args)
    return parsed_args


def main(gmp: Gmp, args: Namespace) -> None:
    parsed_args = parse_args(args)
    response_xml = gmp.generate_scope_report(parsed_args.scope_id)
    report_id = response_xml.get("id")
    print(f"Generated scope report: {report_id}")


if __name__ == "__gmp__":
    main(gmp, args)
