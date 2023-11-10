#!/usr/bin/env python3

# SPDX-FileCopyrightText: Red Hat, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later

from pathlib import Path
from datetime import datetime
from mako.template import Template
import hidl_parser

SCRIPT_PATH = Path(__file__).parent.resolve()
TEMPLATE_PATH = 'vhal_consts_2_0.rs.mako'
DATA_TYPES_PATH = 'data/types.hal'
OUTPUT_PATH = '../vhal_consts_2_0.rs'


def main():
    """
    Parse types.hal file using Google's hidl_parser, and render to output file.
    """
    vhal_20_file = Path(SCRIPT_PATH, DATA_TYPES_PATH)
    template_file = Path(SCRIPT_PATH, TEMPLATE_PATH)
    vhal_20_data = hidl_parser.parse(vhal_20_file)

    template = Template(filename=str(template_file), output_encoding='utf-8')
    with Path(SCRIPT_PATH, OUTPUT_PATH).open('wb') as out:
        out.write(
            template.render(
                data=vhal_20_data,
                time=datetime.now().strftime("%Y-%m-%d")))


if __name__ == "__main__":
    main()
