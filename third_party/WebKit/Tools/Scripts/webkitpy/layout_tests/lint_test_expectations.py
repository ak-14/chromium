# Copyright (C) 2012 Google Inc. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#     * Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above
# copyright notice, this list of conditions and the following disclaimer
# in the documentation and/or other materials provided with the
# distribution.
#     * Neither the name of Google Inc. nor the names of its
# contributors may be used to endorse or promote products derived from
# this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import json
import logging
import optparse
import traceback

from webkitpy.common import add_blinkpy  # pylint: disable=unused-import
from webkitpy.common import exit_codes
from webkitpy.common.host import Host
from webkitpy.common.system.log_utils import configure_logging
from webkitpy.layout_tests.models import test_expectations
from webkitpy.layout_tests.port.factory import platform_options
from blinkpy.w3c.wpt_manifest import WPTManifest

_log = logging.getLogger(__name__)


def lint(host, options):
    ports_to_lint = [host.port_factory.get(name) for name in host.port_factory.all_port_names(options.platform)]
    files_linted = set()

    # In general, the set of TestExpectation files should be the same for
    # all ports. However, the method used to list expectations files is
    # in Port, and the TestExpectations constructor takes a Port.
    # Perhaps this function could be changed to just use one Port
    # (the default Port for this host) and it would work the same.

    failures = []
    for port_to_lint in ports_to_lint:
        expectations_dict = port_to_lint.all_expectations_dict()

        for path in port_to_lint.extra_expectations_files():
            if host.filesystem.exists(path):
                expectations_dict[path] = host.filesystem.read_text_file(path)

        for expectations_file in expectations_dict:

            if expectations_file in files_linted:
                continue

            try:
                test_expectations.TestExpectations(
                    port_to_lint,
                    expectations_dict={expectations_file: expectations_dict[expectations_file]},
                    is_lint_mode=True)
            except test_expectations.ParseError as error:
                _log.error('')
                for warning in error.warnings:
                    _log.error(warning)
                    failures.append('%s: %s' % (expectations_file, warning))
                _log.error('')
            files_linted.add(expectations_file)
    return failures


def check_virtual_test_suites(host, options):
    port = host.port_factory.get(options=options)
    fs = host.filesystem
    layout_tests_dir = port.layout_tests_dir()
    virtual_suites = port.virtual_test_suites()

    failures = []
    for suite in virtual_suites:
        comps = [layout_tests_dir] + suite.name.split('/') + ['README.txt']
        path_to_readme = fs.join(*comps)
        if not fs.exists(path_to_readme):
            failure = 'LayoutTests/%s/README.txt is missing (each virtual suite must have one).' % suite.name
            _log.error(failure)
            failures.append(failure)
    if failures:
        _log.error('')
    return failures


def check_smoke_tests(host, options):
    port = host.port_factory.get(options=options)
    smoke_tests_file = host.filesystem.join(port.layout_tests_dir(), 'SmokeTests')
    failures = []
    if not host.filesystem.exists(smoke_tests_file):
        return failures

    smoke_tests = host.filesystem.read_text_file(smoke_tests_file)
    line_number = 0
    parsed_lines = {}
    for line in smoke_tests.split('\n'):
        line_number += 1
        line = line.split('#')[0].strip()
        if not line:
            continue
        failure = ''
        if line in parsed_lines:
            failure = '%s:%d duplicate with line %d: %s' % (smoke_tests_file, line_number, parsed_lines[line], line)
        elif not port.test_exists(line):
            failure = '%s:%d Test does not exist: %s' % (smoke_tests_file, line_number, line)
        if failure:
            _log.error(failure)
            failures.append(failure)
        parsed_lines[line] = line_number
    if failures:
        _log.error('')
    return failures


def run_checks(host, options):
    failures = []
    failures.extend(lint(host, options))
    failures.extend(check_virtual_test_suites(host, options))
    failures.extend(check_smoke_tests(host, options))

    if options.json:
        with open(options.json, 'w') as f:
            json.dump(failures, f)

    if failures:
        _log.error('Lint failed.')
        return 1
    else:
        _log.info('Lint succeeded.')
        return 0


def main(argv, stderr, host=None):
    parser = optparse.OptionParser(option_list=platform_options(use_globs=True))
    parser.add_option('--json', help='Path to JSON output file')
    parser.add_option('--verbose', action='store_true', default=False,
                      help='log extra details that may be helpful when debugging')
    options, _ = parser.parse_args(argv)

    if not host:
        if options.platform and 'test' in options.platform:
            # It's a bit lame to import mocks into real code, but this allows the user
            # to run tests against the test platform interactively, which is useful for
            # debugging test failures.
            from webkitpy.common.host_mock import MockHost
            host = MockHost()
        else:
            host = Host()

    if options.verbose:
        configure_logging(logging_level=logging.DEBUG, stream=stderr)
        # Print full stdout/stderr when a command fails.
        host.executive.error_output_limit = None
    else:
        # PRESUBMIT.py relies on our output, so don't include timestamps.
        configure_logging(logging_level=logging.INFO, stream=stderr, include_time=False)

    try:
        # Need to generate MANIFEST.json since some expectations correspond to WPT
        # tests that aren't files and only exist in the manifest.
        _log.debug('Generating MANIFEST.json for web-platform-tests ...')
        WPTManifest.ensure_manifest(host)
        exit_status = run_checks(host, options)
    except KeyboardInterrupt:
        exit_status = exit_codes.INTERRUPTED_EXIT_STATUS
    except Exception as error:  # pylint: disable=broad-except
        print >> stderr, '\n%s raised: %s' % (error.__class__.__name__, error)
        traceback.print_exc(file=stderr)
        exit_status = exit_codes.EXCEPTIONAL_EXIT_STATUS

    return exit_status
