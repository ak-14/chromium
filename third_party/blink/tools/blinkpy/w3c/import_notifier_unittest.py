# -*- coding: utf-8 -*-
# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import unittest

from webkitpy.common.checkout.git_mock import MockGit
from webkitpy.common.host_mock import MockHost
from webkitpy.common.system.executive_mock import mock_git_commands
from webkitpy.common.system.filesystem_mock import MockFileSystem
from blinkpy.w3c.local_wpt_mock import MockLocalWPT
from blinkpy.w3c.import_notifier import ImportNotifier, TestFailure
from blinkpy.w3c.wpt_expectations_updater import UMBRELLA_BUG


class ImportNotifierTest(unittest.TestCase):

    def setUp(self):
        self.host = MockHost()
        # Mock a virtual test suite at virtual/gpu/external/wpt/foo.
        self.host.filesystem = MockFileSystem({
            '/mock-checkout/third_party/WebKit/LayoutTests/VirtualTestSuites':
            '[{"prefix": "gpu", "base": "external/wpt/foo", "args": ["--foo"]}]'
        })
        self.git = self.host.git()
        self.local_wpt = MockLocalWPT()
        self.notifier = ImportNotifier(self.host, self.git, self.local_wpt)

    def test_find_changed_baselines_of_tests(self):
        changed_files = [
            'third_party/WebKit/LayoutTests/external/wpt/foo/bar.html',
            'third_party/WebKit/LayoutTests/external/wpt/foo/bar-expected.txt',
            'third_party/WebKit/LayoutTests/platform/linux/external/wpt/foo/bar-expected.txt',
            'third_party/WebKit/LayoutTests/external/wpt/random_stuff.html',
        ]
        self.git.changed_files = lambda: changed_files
        self.assertEqual(self.notifier.find_changed_baselines_of_tests(['external/wpt/foo/bar.html']),
                         {'external/wpt/foo/bar.html': [
                             'third_party/WebKit/LayoutTests/external/wpt/foo/bar-expected.txt',
                             'third_party/WebKit/LayoutTests/platform/linux/external/wpt/foo/bar-expected.txt',
                         ]})

        self.assertEqual(self.notifier.find_changed_baselines_of_tests(set()), {})

    def test_more_failures_in_baseline_more_fails(self):
        # Replacing self.host.executive won't work here, because ImportNotifier
        # has been instantiated with a MockGit backed by an empty MockExecutive.
        executive = mock_git_commands({
            'diff': ('diff --git a/foo-expected.txt b/foo-expected.txt\n'
                     '--- a/foo-expected.txt\n'
                     '+++ b/foo-expected.txt\n'
                     '-FAIL an old failure\n'
                     '+FAIL new failure 1\n'
                     '+FAIL new failure 2\n')
        })
        self.notifier.git = MockGit(executive=executive)
        self.assertTrue(self.notifier.more_failures_in_baseline('foo-expected.txt'))
        self.assertEqual(executive.calls, [['git', 'diff', '-U0', 'origin/master', '--', 'foo-expected.txt']])

    def test_more_failures_in_baseline_fewer_fails(self):
        executive = mock_git_commands({
            'diff': ('diff --git a/foo-expected.txt b/foo-expected.txt\n'
                     '--- a/foo-expected.txt\n'
                     '+++ b/foo-expected.txt\n'
                     '-FAIL an old failure\n'
                     '-FAIL new failure 1\n'
                     '+FAIL new failure 2\n')
        })
        self.notifier.git = MockGit(executive=executive)
        self.assertFalse(self.notifier.more_failures_in_baseline('foo-expected.txt'))

    def test_more_failures_in_baseline_same_fails(self):
        executive = mock_git_commands({
            'diff': ('diff --git a/foo-expected.txt b/foo-expected.txt\n'
                     '--- a/foo-expected.txt\n'
                     '+++ b/foo-expected.txt\n'
                     '-FAIL an old failure\n'
                     '+FAIL a new failure\n')
        })
        self.notifier.git = MockGit(executive=executive)
        self.assertFalse(self.notifier.more_failures_in_baseline('foo-expected.txt'))

    def test_examine_baseline_changes(self):
        self.host.filesystem.write_text_file(
            '/mock-checkout/third_party/WebKit/LayoutTests/external/wpt/foo/OWNERS',
            'test@chromium.org'
        )
        changed_test_baselines = {'external/wpt/foo/bar.html': [
            'third_party/WebKit/LayoutTests/external/wpt/foo/bar-expected.txt',
            'third_party/WebKit/LayoutTests/platform/linux/external/wpt/foo/bar-expected.txt',
        ]}
        gerrit_url_with_ps = 'https://crrev.com/c/12345/3/'
        self.notifier.more_failures_in_baseline = lambda _: True
        self.notifier.examine_baseline_changes(changed_test_baselines, gerrit_url_with_ps)

        self.assertEqual(
            self.notifier.new_failures_by_directory,
            {'external/wpt/foo': [
                TestFailure(TestFailure.BASELINE_CHANGE, 'external/wpt/foo/bar.html',
                            baseline_path='third_party/WebKit/LayoutTests/external/wpt/foo/bar-expected.txt',
                            gerrit_url_with_ps=gerrit_url_with_ps),
                TestFailure(TestFailure.BASELINE_CHANGE, 'external/wpt/foo/bar.html',
                            baseline_path='third_party/WebKit/LayoutTests/platform/linux/external/wpt/foo/bar-expected.txt',
                            gerrit_url_with_ps=gerrit_url_with_ps),
            ]}
        )

    def test_examine_new_test_expectations(self):
        self.host.filesystem.write_text_file(
            '/mock-checkout/third_party/WebKit/LayoutTests/external/wpt/foo/OWNERS',
            'test@chromium.org'
        )
        test_expectations = {'external/wpt/foo/bar.html': [
            'crbug.com/12345 [ Linux ] external/wpt/foo/bar.html [ Fail ]',
            'crbug.com/12345 [ Win ] external/wpt/foo/bar.html [ Timeout ]',
        ]}
        self.notifier.examine_new_test_expectations(test_expectations)
        self.assertEqual(
            self.notifier.new_failures_by_directory,
            {'external/wpt/foo': [
                TestFailure(TestFailure.NEW_EXPECTATION, 'external/wpt/foo/bar.html',
                            expectation_line='crbug.com/12345 [ Linux ] external/wpt/foo/bar.html [ Fail ]'),
                TestFailure(TestFailure.NEW_EXPECTATION, 'external/wpt/foo/bar.html',
                            expectation_line='crbug.com/12345 [ Win ] external/wpt/foo/bar.html [ Timeout ]'),
            ]}
        )

        self.notifier.new_failures_by_directory = {}
        self.notifier.examine_new_test_expectations({})
        self.assertEqual(self.notifier.new_failures_by_directory, {})

    def test_format_commit_list(self):
        imported_commits = [('SHA1', 'Subject 1'),
                            # Use non-ASCII chars to really test Unicode handling.
                            ('SHA2', u'ABC~‾¥≈¤･・•∙·☼★星🌟星★☼·∙•・･¤≈¥‾~XYZ')]

        def _is_commit_affecting_directory(commit, directory):
            self.assertIn(commit, ('SHA1', 'SHA2'))
            self.assertEqual(directory, 'foo')
            return commit == 'SHA1'

        self.local_wpt.is_commit_affecting_directory = _is_commit_affecting_directory
        self.assertEqual(
            self.notifier.format_commit_list(imported_commits, '/mock-checkout/third_party/WebKit/LayoutTests/external/wpt/foo'),
            u'Subject 1: https://github.com/w3c/web-platform-tests/commit/SHA1 [affecting this directory]\n'
            u'ABC~‾¥≈¤･・•∙·☼★星🌟星★☼·∙•・･¤≈¥‾~XYZ: https://github.com/w3c/web-platform-tests/commit/SHA2\n'
        )

    def test_find_owned_directory_non_virtual(self):
        self.host.filesystem.write_text_file(
            '/mock-checkout/third_party/WebKit/LayoutTests/external/wpt/foo/OWNERS',
            'test@chromium.org'
        )
        self.assertEqual(self.notifier.find_owned_directory('external/wpt/foo/bar.html'), 'external/wpt/foo')
        self.assertEqual(self.notifier.find_owned_directory('external/wpt/foo/bar/baz.html'), 'external/wpt/foo')

    def test_find_owned_directory_virtual(self):
        self.host.filesystem.write_text_file(
            '/mock-checkout/third_party/WebKit/LayoutTests/external/wpt/foo/OWNERS',
            'test@chromium.org'
        )
        self.assertEqual(self.notifier.find_owned_directory('virtual/gpu/external/wpt/foo/bar.html'), 'external/wpt/foo')

    def test_create_bugs_from_new_failures(self):
        self.host.filesystem.write_text_file(
            '/mock-checkout/third_party/WebKit/LayoutTests/external/wpt/foo/OWNERS',
            '# COMPONENT: Blink>Infra>Ecosystem\n'
            '# WPT-NOTIFY: true\n'
            'foolip@chromium.org\n'
        )
        self.host.filesystem.write_text_file(
            '/mock-checkout/third_party/WebKit/LayoutTests/external/wpt/bar/OWNERS',
            'test@chromium.org'
        )
        self.notifier.new_failures_by_directory = {
            'external/wpt/foo': [TestFailure(TestFailure.NEW_EXPECTATION, 'external/wpt/foo/baz.html',
                                             expectation_line='crbug.com/12345 external/wpt/foo/baz.html [ Fail ]')],
            'external/wpt/bar': [TestFailure(TestFailure.NEW_EXPECTATION, 'external/wpt/bar/baz.html',
                                             expectation_line='crbug.com/12345 external/wpt/bar/baz.html [ Fail ]')]
        }
        bugs = self.notifier.create_bugs_from_new_failures('SHA_START', 'SHA_END', 'https://crrev.com/c/12345')

        # Only one directory has WPT-NOTIFY enabled.
        self.assertEqual(len(bugs), 1)
        # The formatting of imported commits and new failures are already tested.
        self.assertEqual(bugs[0].body['cc'], ['foolip@chromium.org', 'robertma@chromium.org'])
        self.assertEqual(bugs[0].body['components'], ['Blink>Infra>Ecosystem'])
        self.assertEqual(bugs[0].body['summary'],
                         '[WPT] New failures introduced in external/wpt/foo by import https://crrev.com/c/12345')

    def test_no_bugs_filed_in_dry_run(self):
        def unreachable(_):
            self.fail('MonorailAPI should not be instantiated in dry_run.')

        self.notifier._get_monorail_api = unreachable  # pylint: disable=protected-access
        self.notifier.file_bugs([], True)


class TestFailureTest(unittest.TestCase):

    def test_test_failure_to_str_baseline_change(self):
        failure = TestFailure(
            TestFailure.BASELINE_CHANGE, 'external/wpt/foo/bar.html',
            baseline_path='third_party/WebKit/LayoutTests/external/wpt/foo/bar-expected.txt',
            gerrit_url_with_ps='https://crrev.com/c/12345/3/')
        self.assertEqual(str(failure),
                         'external/wpt/foo/bar.html new failing tests: https://crrev.com/c/12345/3/'
                         'third_party/WebKit/LayoutTests/external/wpt/foo/bar-expected.txt')

        platform_failure = TestFailure(
            TestFailure.BASELINE_CHANGE, 'external/wpt/foo/bar.html',
            baseline_path='third_party/WebKit/LayoutTests/platform/linux/external/wpt/foo/bar-expected.txt',
            gerrit_url_with_ps='https://crrev.com/c/12345/3/')
        self.assertEqual(str(platform_failure),
                         '[ Linux ] external/wpt/foo/bar.html new failing tests: https://crrev.com/c/12345/3/'
                         'third_party/WebKit/LayoutTests/platform/linux/external/wpt/foo/bar-expected.txt')

    def test_test_failure_to_str_new_expectation(self):
        failure = TestFailure(
            TestFailure.NEW_EXPECTATION, 'external/wpt/foo/bar.html',
            expectation_line='crbug.com/12345 [ Linux ] external/wpt/foo/bar.html [ Fail ]'
        )
        self.assertEqual(str(failure),
                         'crbug.com/12345 [ Linux ] external/wpt/foo/bar.html [ Fail ]')

        failure_with_umbrella_bug = TestFailure(
            TestFailure.NEW_EXPECTATION, 'external/wpt/foo/bar.html',
            expectation_line=UMBRELLA_BUG + ' external/wpt/foo/bar.html [ Fail ]'
        )
        self.assertEqual(str(failure_with_umbrella_bug),
                         'external/wpt/foo/bar.html [ Fail ]')
