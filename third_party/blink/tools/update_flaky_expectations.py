#!/usr/bin/env vpython
#
# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import sys

from blinkpy.common import add_webkitpy  # pylint: disable=unused-import
from webkitpy.common import host
from webkitpy.layout_tests import update_flaky_expectations
from webkitpy.layout_tests.layout_package.bot_test_expectations import BotTestExpectationsFactory


if __name__ == "__main__":
    host = host.Host()
    return_code = update_flaky_expectations.main(
        host, BotTestExpectationsFactory(host.builders), sys.argv[1:])
    sys.exit(return_code)
