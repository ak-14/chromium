# Copyright (C) 2010 Google Inc. All rights reserved.
# Copyright (C) 2010 Gabor Rapcsanyi (rgabor@inf.u-szeged.hu), University of Szeged
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

"""The Manager orchestrates the overall process of running layout tests.

This includes finding tests to run, reading the test expectations,
starting the required helper servers, deciding the order and way to
run the tests, retrying failed tests, and collecting the test results,
including crash logs and mismatches with expectations.

The Manager object has a constructor and one main method called run.
"""

import json
import logging
import random
import sys
import time

from webkitpy.common import add_blinkpy  # pylint: disable=unused-import
from webkitpy.common import exit_codes
from webkitpy.common.net.file_uploader import FileUploader
from webkitpy.common.path_finder import PathFinder
from webkitpy.layout_tests.controllers.layout_test_finder import LayoutTestFinder
from webkitpy.layout_tests.controllers.layout_test_runner import LayoutTestRunner
from webkitpy.layout_tests.controllers.test_result_writer import TestResultWriter
from webkitpy.layout_tests.layout_package import json_results_generator
from webkitpy.layout_tests.models import test_expectations
from webkitpy.layout_tests.models import test_failures
from webkitpy.layout_tests.models import test_run_results
from webkitpy.layout_tests.models.test_input import TestInput
from blinkpy.tool import grammar
from blinkpy.w3c.wpt_manifest import WPTManifest

_log = logging.getLogger(__name__)

TestExpectations = test_expectations.TestExpectations


class Manager(object):
    """A class for managing running a series of layout tests."""

    HTTP_SUBDIR = 'http'
    PERF_SUBDIR = 'perf'
    WEBSOCKET_SUBDIR = 'websocket'
    ARCHIVED_RESULTS_LIMIT = 25

    def __init__(self, port, options, printer):
        """Initializes test runner data structures.

        Args:
            port: An object implementing platform-specific functionality.
            options: An options argument which contains command line options.
            printer: A Printer object to record updates to.
        """
        self._port = port
        self._filesystem = port.host.filesystem
        self._options = options
        self._printer = printer

        self._expectations = None
        self._http_server_started = False
        self._wptserve_started = False
        self._websockets_server_started = False

        self._results_directory = self._port.results_directory()
        self._finder = LayoutTestFinder(self._port, self._options)
        self._path_finder = PathFinder(port.host.filesystem)
        self._runner = LayoutTestRunner(self._options, self._port, self._printer, self._results_directory, self._test_is_slow)

    def run(self, args):
        """Runs the tests and return a RunDetails object with the results."""
        start_time = time.time()
        self._printer.write_update('Collecting tests ...')
        running_all_tests = False

        if not args or any('external' in path for path in args):
            self._printer.write_update('Generating MANIFEST.json for web-platform-tests ...')
            WPTManifest.ensure_manifest(self._port.host)
            self._printer.write_update('Completed generating manifest.')

        self._printer.write_update('Collecting tests ...')
        try:
            paths, all_test_names, running_all_tests = self._collect_tests(args)
        except IOError:
            # This is raised if --test-list doesn't exist
            return test_run_results.RunDetails(exit_code=exit_codes.NO_TESTS_EXIT_STATUS)

        # Create a sorted list of test files so the subset chunk,
        # if used, contains alphabetically consecutive tests.
        if self._options.order == 'natural':
            all_test_names.sort(key=self._port.test_key)
        elif self._options.order == 'random':
            all_test_names.sort()
            random.Random(self._options.seed).shuffle(all_test_names)

        test_names, tests_in_other_chunks = self._finder.split_into_chunks(all_test_names)

        self._printer.write_update('Parsing expectations ...')
        self._expectations = test_expectations.TestExpectations(self._port, test_names)

        tests_to_run, tests_to_skip = self._prepare_lists(paths, test_names)

        self._expectations.remove_tests_from_expectations(tests_in_other_chunks)

        self._printer.print_found(
            len(all_test_names), len(test_names), len(tests_to_run),
            self._options.repeat_each, self._options.iterations)

        # Check to make sure we're not skipping every test.
        if not tests_to_run:
            _log.critical('No tests to run.')
            return test_run_results.RunDetails(exit_code=exit_codes.NO_TESTS_EXIT_STATUS)

        exit_code = self._set_up_run(tests_to_run)
        if exit_code:
            return test_run_results.RunDetails(exit_code=exit_code)

        if self._options.num_retries is None:
            # Don't retry failures if an explicit list of tests was passed in.
            should_retry_failures = len(paths) < len(test_names)
            # Retry failures 3 times by default.
            if should_retry_failures:
                self._options.num_retries = 3
        else:
            should_retry_failures = self._options.num_retries > 0

        try:
            self._start_servers(tests_to_run)
            if self._options.watch:
                run_results = self._run_test_loop(tests_to_run, tests_to_skip)
            else:
                run_results = self._run_test_once(tests_to_run, tests_to_skip, should_retry_failures)
            initial_results, all_retry_results, enabled_pixel_tests_in_retry = run_results
        finally:
            self._stop_servers()
            self._clean_up_run()

        # Some crash logs can take a long time to be written out so look
        # for new logs after the test run finishes.
        self._printer.write_update('Looking for new crash logs ...')
        self._look_for_new_crash_logs(initial_results, start_time)
        for retry_attempt_results in all_retry_results:
            self._look_for_new_crash_logs(retry_attempt_results, start_time)

        self._printer.write_update('Summarizing results ...')
        summarized_full_results = test_run_results.summarize_results(
            self._port, self._expectations, initial_results, all_retry_results,
            enabled_pixel_tests_in_retry)
        summarized_failing_results = test_run_results.summarize_results(
            self._port, self._expectations, initial_results, all_retry_results,
            enabled_pixel_tests_in_retry, only_include_failing=True)

        exit_code = summarized_failing_results['num_regressions']
        if exit_code > exit_codes.MAX_FAILURES_EXIT_STATUS:
            _log.warning('num regressions (%d) exceeds max exit status (%d)',
                         exit_code, exit_codes.MAX_FAILURES_EXIT_STATUS)
            exit_code = exit_codes.MAX_FAILURES_EXIT_STATUS

        if not self._options.dry_run:
            self._write_json_files(summarized_full_results, summarized_failing_results, initial_results, running_all_tests)

            self._upload_json_files()

            self._copy_results_html_file(self._results_directory, 'results.html')
            self._copy_results_html_file(self._results_directory, 'legacy-results.html')
            if initial_results.keyboard_interrupted:
                exit_code = exit_codes.INTERRUPTED_EXIT_STATUS
            else:
                if initial_results.interrupted:
                    exit_code = exit_codes.EARLY_EXIT_STATUS
                if self._options.show_results and (exit_code or initial_results.total_failures):
                    self._port.show_results_html_file(
                        self._filesystem.join(self._results_directory, 'results.html'))
                self._printer.print_results(time.time() - start_time, initial_results)

        return test_run_results.RunDetails(
            exit_code, summarized_full_results, summarized_failing_results,
            initial_results, all_retry_results, enabled_pixel_tests_in_retry)

    def _run_test_loop(self, tests_to_run, tests_to_skip):
        # Don't show results in a new browser window because we're already
        # printing the link to diffs in the loop
        self._options.show_results = False

        while True:
            initial_results, all_retry_results, enabled_pixel_tests_in_retry = self._run_test_once(
                tests_to_run, tests_to_skip, should_retry_failures=False)
            for name in initial_results.failures_by_name:
                failure = initial_results.failures_by_name[name][0]
                if isinstance(failure, test_failures.FailureTextMismatch):
                    full_test_path = self._filesystem.join(self._results_directory, name)
                    filename, _ = self._filesystem.splitext(full_test_path)
                    pretty_diff_path = 'file://' + filename + '-pretty-diff.html'
                    self._printer.writeln('Link to pretty diff:')
                    self._printer.writeln(pretty_diff_path + '\n')
            self._printer.writeln('Finished running tests')

            user_input = self._port.host.user.prompt(
                'Interactive watch mode: (q)uit (r)etry\n').lower()

            if user_input == 'q' or user_input == 'quit':
                return (initial_results, all_retry_results, enabled_pixel_tests_in_retry)

    def _run_test_once(self, tests_to_run, tests_to_skip, should_retry_failures):
        enabled_pixel_tests_in_retry = False

        num_workers = self._port.num_workers(int(self._options.child_processes))

        initial_results = self._run_tests(
            tests_to_run, tests_to_skip, self._options.repeat_each, self._options.iterations,
            num_workers)

        # Don't retry failures when interrupted by user or failures limit exception.
        should_retry_failures = should_retry_failures and not (
            initial_results.interrupted or initial_results.keyboard_interrupted)

        tests_to_retry = self._tests_to_retry(initial_results)
        all_retry_results = []
        if should_retry_failures and tests_to_retry:
            enabled_pixel_tests_in_retry = self._force_pixel_tests_if_needed()

            for retry_attempt in xrange(1, self._options.num_retries + 1):
                if not tests_to_retry:
                    break

                _log.info('')
                _log.info('Retrying %s, attempt %d of %d...',
                          grammar.pluralize('unexpected failure', len(tests_to_retry)),
                          retry_attempt, self._options.num_retries)

                retry_results = self._run_tests(tests_to_retry,
                                                tests_to_skip=set(),
                                                repeat_each=1,
                                                iterations=1,
                                                num_workers=num_workers,
                                                retry_attempt=retry_attempt)
                all_retry_results.append(retry_results)

                tests_to_retry = self._tests_to_retry(retry_results)

            if enabled_pixel_tests_in_retry:
                self._options.pixel_tests = False
        return (initial_results, all_retry_results, enabled_pixel_tests_in_retry)

    def _collect_tests(self, args):
        return self._finder.find_tests(args, test_list=self._options.test_list,
                                       fastest_percentile=self._options.fastest)

    def _is_http_test(self, test):
        return (
            test.startswith(self.HTTP_SUBDIR + self._port.TEST_PATH_SEPARATOR) or
            self._is_websocket_test(test) or
            self._port.TEST_PATH_SEPARATOR + self.HTTP_SUBDIR + self._port.TEST_PATH_SEPARATOR in test
        )

    def _is_websocket_test(self, test):
        if self._port.should_use_wptserve(test):
            return False

        return self.WEBSOCKET_SUBDIR + self._port.TEST_PATH_SEPARATOR in test

    def _http_tests(self, test_names):
        return set(test for test in test_names if self._is_http_test(test))

    def _is_perf_test(self, test):
        return self.PERF_SUBDIR == test or (self.PERF_SUBDIR + self._port.TEST_PATH_SEPARATOR) in test

    def _prepare_lists(self, paths, test_names):
        tests_to_skip = self._finder.skip_tests(paths, test_names, self._expectations, self._http_tests(test_names))
        tests_to_run = [test for test in test_names if test not in tests_to_skip]

        return tests_to_run, tests_to_skip

    def _test_input_for_file(self, test_file):
        return TestInput(test_file,
                         self._options.slow_time_out_ms if self._test_is_slow(test_file) else self._options.time_out_ms,
                         self._test_requires_lock(test_file))

    def _test_requires_lock(self, test_file):
        """Returns True if the test needs to be locked when running multiple
        instances of this test runner.

        Perf tests are locked because heavy load caused by running other
        tests in parallel might cause some of them to time out.
        """
        return self._is_http_test(test_file) or self._is_perf_test(test_file)

    def _test_is_slow(self, test_file):
        expectations = self._expectations.model().get_expectations(test_file)
        return (test_expectations.SLOW in expectations or
                self._port.is_slow_wpt_test(test_file))

    def _needs_servers(self, test_names):
        return any(self._test_requires_lock(test_name) for test_name in test_names)

    def _rename_results_folder(self):
        try:
            timestamp = time.strftime(
                "%Y-%m-%d-%H-%M-%S", time.localtime(
                    self._filesystem.mtime(self._filesystem.join(self._results_directory, 'results.html'))))
        except (IOError, OSError) as error:
            # It might be possible that results.html was not generated in previous run, because the test
            # run was interrupted even before testing started. In those cases, don't archive the folder.
            # Simply override the current folder contents with new results.
            import errno
            if error.errno in (errno.EEXIST, errno.ENOENT):
                self._printer.write_update('No results.html file found in previous run, skipping it.')
            return None
        archived_name = ''.join((self._filesystem.basename(self._results_directory), '_', timestamp))
        archived_path = self._filesystem.join(self._filesystem.dirname(self._results_directory), archived_name)
        self._filesystem.move(self._results_directory, archived_path)

    def _delete_dirs(self, dir_list):
        for dir_path in dir_list:
            self._filesystem.rmtree(dir_path)

    def _limit_archived_results_count(self):
        results_directory_path = self._filesystem.dirname(self._results_directory)
        file_list = self._filesystem.listdir(results_directory_path)
        results_directories = []
        for name in file_list:
            file_path = self._filesystem.join(results_directory_path, name)
            if self._filesystem.isdir(file_path) and self._results_directory in file_path:
                results_directories.append(file_path)
        results_directories.sort(key=self._filesystem.mtime)
        self._printer.write_update('Clobbering excess archived results in %s' % results_directory_path)
        self._delete_dirs(results_directories[:-self.ARCHIVED_RESULTS_LIMIT])

    def _set_up_run(self, test_names):
        self._printer.write_update('Checking build ...')
        if self._options.build:
            exit_code = self._port.check_build(self._needs_servers(test_names), self._printer)
            if exit_code:
                _log.error('Build check failed')
                return exit_code

        if self._options.clobber_old_results:
            self._clobber_old_results()
        elif self._filesystem.exists(self._results_directory):
            self._limit_archived_results_count()
            # Rename the existing results folder for archiving.
            self._rename_results_folder()

        # Create the output directory if it doesn't already exist.
        self._port.host.filesystem.maybe_make_directory(self._results_directory)

        exit_code = self._port.setup_test_run()
        if exit_code:
            _log.error('Build setup failed')
            return exit_code

        # Check that the system dependencies (themes, fonts, ...) are correct.
        if not self._options.nocheck_sys_deps:
            self._printer.write_update('Checking system dependencies ...')
            exit_code = self._port.check_sys_deps(self._needs_servers(test_names))
            if exit_code:
                return exit_code

        return exit_codes.OK_EXIT_STATUS

    def _run_tests(self, tests_to_run, tests_to_skip, repeat_each, iterations,
                   num_workers, retry_attempt=0):

        test_inputs = []
        for _ in xrange(iterations):
            # TODO(crbug.com/650747): We may want to switch the two loops below
            # to make the behavior consistent with gtest runner (--gtest_repeat
            # is an alias for --repeat-each now), which looks like "ABCABCABC".
            # And remember to update the help text when we do so.
            for test in tests_to_run:
                for _ in xrange(repeat_each):
                    test_inputs.append(self._test_input_for_file(test))
        return self._runner.run_tests(self._expectations, test_inputs,
                                      tests_to_skip, num_workers, retry_attempt)

    def _start_servers(self, tests_to_run):
        if any(self._port.is_wpt_test(test) for test in tests_to_run):
            self._printer.write_update('Starting WPTServe ...')
            self._port.start_wptserve()
            self._wptserve_started = True

        if self._port.requires_http_server() or any(self._is_http_test(test) for test in tests_to_run):
            self._printer.write_update('Starting HTTP server ...')
            self._port.start_http_server(additional_dirs={}, number_of_drivers=self._options.max_locked_shards)
            self._http_server_started = True

        if any(self._is_websocket_test(test) for test in tests_to_run):
            self._printer.write_update('Starting WebSocket server ...')
            self._port.start_websocket_server()
            self._websockets_server_started = True

    def _stop_servers(self):
        if self._wptserve_started:
            self._printer.write_update('Stopping WPTServe ...')
            self._wptserve_started = False
            self._port.stop_wptserve()
        if self._http_server_started:
            self._printer.write_update('Stopping HTTP server ...')
            self._http_server_started = False
            self._port.stop_http_server()
        if self._websockets_server_started:
            self._printer.write_update('Stopping WebSocket server ...')
            self._websockets_server_started = False
            self._port.stop_websocket_server()

    def _clean_up_run(self):
        _log.debug('Flushing stdout')
        sys.stdout.flush()
        _log.debug('Flushing stderr')
        sys.stderr.flush()
        _log.debug('Cleaning up port')
        self._port.clean_up_test_run()

    def _force_pixel_tests_if_needed(self):
        if self._options.pixel_tests:
            return False
        self._options.pixel_tests = True
        return True

    def _look_for_new_crash_logs(self, run_results, start_time):
        """Looks for and writes new crash logs, at the end of the test run.

        Since crash logs can take a long time to be written out if the system is
        under stress, do a second pass at the end of the test run.

        Args:
            run_results: The results of the test run.
            start_time: Time the tests started at. We're looking for crash
                logs after that time.
        """
        crashed_processes = []
        for test, result in run_results.unexpected_results_by_name.iteritems():
            if result.type != test_expectations.CRASH:
                continue
            for failure in result.failures:
                if not isinstance(failure, test_failures.FailureCrash):
                    continue
                if failure.has_log:
                    continue
                crashed_processes.append([test, failure.process_name, failure.pid])

        sample_files = self._port.look_for_new_samples(crashed_processes, start_time)
        if sample_files:
            for test, sample_file in sample_files.iteritems():
                writer = TestResultWriter(self._filesystem, self._port, self._port.results_directory(), test)
                writer.copy_sample_file(sample_file)

        crash_logs = self._port.look_for_new_crash_logs(crashed_processes, start_time)
        if crash_logs:
            for test, (crash_log, crash_site) in crash_logs.iteritems():
                writer = TestResultWriter(self._filesystem, self._port, self._port.results_directory(), test)
                writer.write_crash_log(crash_log)
                run_results.unexpected_results_by_name[test].crash_site = crash_site

    def _clobber_old_results(self):
        dir_above_results_path = self._filesystem.dirname(self._results_directory)
        self._printer.write_update('Clobbering old results in %s.' % dir_above_results_path)
        if not self._filesystem.exists(dir_above_results_path):
            return
        file_list = self._filesystem.listdir(dir_above_results_path)
        results_directories = []
        for name in file_list:
            file_path = self._filesystem.join(dir_above_results_path, name)
            if self._filesystem.isdir(file_path) and self._results_directory in file_path:
                results_directories.append(file_path)
        self._delete_dirs(results_directories)

        # Port specific clean-up.
        self._port.clobber_old_port_specific_results()

    def _tests_to_retry(self, run_results):
        # TODO(ojan): This should also check that result.type != test_expectations.MISSING
        # since retrying missing expectations is silly. But that's a bit tricky since we
        # only consider the last retry attempt for the count of unexpected regressions.
        return [result.test_name for result in run_results.unexpected_results_by_name.values(
        ) if result.type != test_expectations.PASS]

    def _write_json_files(self, summarized_full_results, summarized_failing_results, initial_results, running_all_tests):
        _log.debug("Writing JSON files in %s.", self._results_directory)

        # FIXME: Upload stats.json to the server and delete times_ms.
        times_trie = json_results_generator.test_timings_trie(initial_results.results_by_name.values())
        times_json_path = self._filesystem.join(self._results_directory, 'times_ms.json')
        json_results_generator.write_json(self._filesystem, times_trie, times_json_path)

        # Save out the times data so we can use it for --fastest in the future.
        if running_all_tests:
            bot_test_times_path = self._port.bot_test_times_path()
            self._filesystem.maybe_make_directory(self._filesystem.dirname(bot_test_times_path))
            json_results_generator.write_json(self._filesystem, times_trie, bot_test_times_path)

        stats_trie = self._stats_trie(initial_results)
        stats_path = self._filesystem.join(self._results_directory, 'stats.json')
        self._filesystem.write_text_file(stats_path, json.dumps(stats_trie))

        full_results_path = self._filesystem.join(self._results_directory, 'full_results.json')
        json_results_generator.write_json(self._filesystem, summarized_full_results, full_results_path)

        full_results_jsonp_path = self._filesystem.join(self._results_directory, 'full_results_jsonp.js')
        json_results_generator.write_json(self._filesystem,
                                          summarized_full_results,
                                          full_results_jsonp_path,
                                          callback='ADD_FULL_RESULTS')
        full_results_path = self._filesystem.join(self._results_directory, 'failing_results.json')
        # We write failing_results.json out as jsonp because we need to load it
        # from a file url for results.html and Chromium doesn't allow that.
        json_results_generator.write_json(self._filesystem, summarized_failing_results, full_results_path, callback='ADD_RESULTS')

        # Write out the JSON files suitable for other tools to process.
        # As the output can be quite large (as there are 60k+ tests) we also
        # support only outputting the failing results.
        if self._options.json_failing_test_results:
            # FIXME(tansell): Make sure this includes an *unexpected* results
            # (IE Passing when expected to be failing.)
            json_results_generator.write_json(self._filesystem, summarized_failing_results, self._options.json_failing_test_results)
        if self._options.json_test_results:
            json_results_generator.write_json(self._filesystem, summarized_full_results, self._options.json_test_results)

        _log.debug('Finished writing JSON files.')

    def _upload_json_files(self):
        if not self._options.test_results_server:
            return

        if not self._options.master_name:
            _log.error('--test-results-server was set, but --master-name was not.  Not uploading JSON files.')
            return

        _log.debug('Uploading JSON files for builder: %s', self._options.builder_name)
        attrs = [('builder', self._options.builder_name),
                 ('testtype', self._options.step_name),
                 ('master', self._options.master_name)]

        files = [(name, self._filesystem.join(self._results_directory, name))
                 for name in ['failing_results.json', 'full_results.json', 'times_ms.json']]

        url = 'https://%s/testfile/upload' % self._options.test_results_server
        # Set uploading timeout in case appengine server is having problems.
        # 120 seconds are more than enough to upload test results.
        uploader = FileUploader(url, 120)
        try:
            response = uploader.upload_as_multipart_form_data(self._filesystem, files, attrs)
            if response:
                if response.code == 200:
                    _log.debug('JSON uploaded.')
                else:
                    _log.debug('JSON upload failed, %d: "%s"', response.code, response.read())
            else:
                _log.error('JSON upload failed; no response returned')
        except IOError as err:
            _log.error('Upload failed: %s', err)

    def _copy_results_html_file(self, destination_dir, filename):
        """Copies a file from the template directory to the results directory."""
        template_dir = self._path_finder.path_from_layout_tests('fast', 'harness')
        source_path = self._filesystem.join(template_dir, filename)
        destination_path = self._filesystem.join(destination_dir, filename)
        # Note that the results.html template file won't exist when
        # we're using a MockFileSystem during unit tests, so make sure
        # it exists before we try to copy it.
        if self._filesystem.exists(source_path):
            self._filesystem.copyfile(source_path, destination_path)

    def _stats_trie(self, initial_results):
        def _worker_number(worker_name):
            return int(worker_name.split('/')[1]) if worker_name else -1

        stats = {}
        for result in initial_results.results_by_name.values():
            if result.type != test_expectations.SKIP:
                stats[result.test_name] = {'results': (_worker_number(result.worker_name), result.test_number, result.pid, int(
                    result.test_run_time * 1000), int(result.total_run_time * 1000))}
        stats_trie = {}
        for name, value in stats.iteritems():
            json_results_generator.add_path_to_trie(name, value, stats_trie)
        return stats_trie
