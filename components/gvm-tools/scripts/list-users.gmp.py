# SPDX-FileCopyrightText: 2024 Martin Boller
# TurboVAS modifications Copyright (C) 2026 Robert Pelfrey <Robert@Pelfrey.de>.
#
# SPDX-License-Identifier: GPL-3.0-or-later

from argparse import Namespace

from gvm.protocols.gmp import Gmp
from gvmtools.helper import Table


def main(gmp: Gmp, args: Namespace) -> None:
    # pylint: disable=unused-argument

    response_xml = gmp.get_users(filter_string="rows=-1")
    users_xml = response_xml.xpath("user")

    heading = ["#", "Name", "Id"]

    rows = []
    numberRows = 0

    print("Listing users.\n")

    for user in users_xml:
        # Count number of reports
        numberRows = numberRows + 1
        # Cast/convert to text to show in list
        rowNumber = str(numberRows)

        name = "".join(user.xpath("name/text()"))
        user_id = user.get("id")

        rows.append([rowNumber, name, user_id])

    print(Table(heading=heading, rows=rows))


if __name__ == "__gmp__":
    main(gmp, args)
