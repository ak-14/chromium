# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import unittest

from webkitpy.common.host_mock import MockHost
from webkitpy.common.system.executive_mock import mock_git_commands
from blinkpy.w3c.chromium_commit import ChromiumCommit
from blinkpy.w3c.chromium_commit_mock import MockChromiumCommit
from blinkpy.w3c.chromium_exportable_commits import (
    _exportable_commits_since,
    get_commit_export_state,
    CommitExportState
)
from blinkpy.w3c.local_wpt_mock import MockLocalWPT
from blinkpy.w3c.wpt_github import PullRequest
from blinkpy.w3c.wpt_github_mock import MockWPTGitHub


class ChromiumExportableCommitsTest(unittest.TestCase):

    # TODO(qyearsley): Add a test for exportable_commits_over_last_n_commits.

    def test_exportable_commits_since(self):
        host = MockHost()
        host.executive = mock_git_commands({
            'show': 'fake message',
            'rev-list': 'add087a97844f4b9e307d9a216940582d96db306',
            'rev-parse': 'add087a97844f4b9e307d9a216940582d96db306',
            'crrev-parse': 'add087a97844f4b9e307d9a216940582d96db306',
            'diff': 'fake diff',
            'diff-tree': 'third_party/WebKit/LayoutTests/external/wpt/some\n'
                         'third_party/WebKit/LayoutTests/external/wpt/files',
            'format-patch': 'hey I\'m a patch',
            'footers': 'cr-rev-position',
        }, strict=True)

        commits, _ = _exportable_commits_since(
            'beefcafe', host, MockLocalWPT(test_patch=[(True, '')]), MockWPTGitHub(pull_requests=[]))
        self.assertEqual(len(commits), 1)
        self.assertIsInstance(commits[0], ChromiumCommit)
        self.assertEqual(host.executive.calls, [
            ['git', 'rev-parse', '--show-toplevel'],
            ['git', 'rev-list', 'beefcafe..HEAD', '--reverse', '--',
             'add087a97844f4b9e307d9a216940582d96db306/third_party/WebKit/LayoutTests/external/wpt/'],
            ['git', 'footers', '--position', 'add087a97844f4b9e307d9a216940582d96db306'],
            ['git', 'show', '--format=%B', '--no-patch', 'add087a97844f4b9e307d9a216940582d96db306'],
            ['git', 'diff-tree', '--name-only', '--no-commit-id', '-r', 'add087a97844f4b9e307d9a216940582d96db306', '--',
             '/mock-checkout/third_party/WebKit/LayoutTests/external/wpt'],
            ['git', 'format-patch', '-1', '--stdout', 'add087a97844f4b9e307d9a216940582d96db306', '--',
             'third_party/WebKit/LayoutTests/external/wpt/some', 'third_party/WebKit/LayoutTests/external/wpt/files'],
        ])

    def test_exportable_commits_since_require_clean_by_default(self):
        host = MockHost()
        host.executive = mock_git_commands({
            'diff-tree': 'third_party/WebKit/LayoutTests/external/wpt/some_files',
            'footers': 'cr-rev-position',
            'format-patch': 'hey I\'m a patch',
            'rev-list': 'add087a97844f4b9e307d9a216940582d96db306\n'
                        'add087a97844f4b9e307d9a216940582d96db307\n'
                        'add087a97844f4b9e307d9a216940582d96db308\n'
        })
        local_wpt = MockLocalWPT(test_patch=[
            (True, ''),
            (False, 'patch failure'),
            (True, ''),
        ])

        commits, _ = _exportable_commits_since(
            'beefcafe', host, local_wpt, MockWPTGitHub(pull_requests=[]))
        self.assertEqual(len(commits), 2)

    def test_exportable_commits_since_not_require_clean(self):
        host = MockHost()
        host.executive = mock_git_commands({
            'diff-tree': 'third_party/WebKit/LayoutTests/external/wpt/some_files',
            'footers': 'cr-rev-position',
            'format-patch': 'hey I\'m a patch',
            'rev-list': 'add087a97844f4b9e307d9a216940582d96db306\n'
                        'add087a97844f4b9e307d9a216940582d96db307\n'
                        'add087a97844f4b9e307d9a216940582d96db308\n'
        })
        local_wpt = MockLocalWPT(test_patch=[
            (True, ''),
            (False, 'patch failure'),
            (True, ''),
        ])

        commits, _ = _exportable_commits_since(
            'beefcafe', host, local_wpt, MockWPTGitHub(pull_requests=[]), require_clean=False)
        self.assertEqual(len(commits), 3)

    def test_get_commit_export_state(self):
        commit = MockChromiumCommit(MockHost())
        github = MockWPTGitHub(pull_requests=[])
        self.assertEqual(get_commit_export_state(commit, MockLocalWPT(test_patch=[(True, '')]), github),
                         (CommitExportState.EXPORTABLE_CLEAN, ''))

    def test_commit_with_noexport_is_not_exportable(self):
        # Patch is not tested if the commit is ignored based on the message, hence empty MockLocalWPT.

        commit = MockChromiumCommit(MockHost(), body='Message\nNo-Export: true')
        github = MockWPTGitHub(pull_requests=[])
        self.assertEqual(get_commit_export_state(commit, MockLocalWPT(), github), (CommitExportState.IGNORED, ''))

        # The older NOEXPORT tag also makes it non-exportable.
        old_commit = MockChromiumCommit(MockHost(), body='Message\nNOEXPORT=true')
        self.assertEqual(get_commit_export_state(old_commit, MockLocalWPT(), github), (CommitExportState.IGNORED, ''))

        # No-Export/NOEXPORT in a revert CL also makes it non-exportable.
        revert = MockChromiumCommit(MockHost(), body='Revert of Message\n> No-Export: true')
        self.assertEqual(get_commit_export_state(revert, MockLocalWPT(), github), (CommitExportState.IGNORED, ''))
        old_revert = MockChromiumCommit(MockHost(), body='Revert of Message\n> NOEXPORT=true')
        self.assertEqual(get_commit_export_state(old_revert, MockLocalWPT(), github), (CommitExportState.IGNORED, ''))

    def test_commit_that_starts_with_import_is_not_exportable(self):
        commit = MockChromiumCommit(MockHost(), subject='Import message')
        github = MockWPTGitHub(pull_requests=[])
        self.assertEqual(get_commit_export_state(commit, MockLocalWPT(), github), (CommitExportState.IGNORED, ''))

    def test_commit_that_has_open_pr_is_exportable(self):
        commit = MockChromiumCommit(MockHost(), change_id='I00decade')
        github = MockWPTGitHub(pull_requests=[
            PullRequest('PR2', 2, 'body\nChange-Id: I00decade', 'open', []),
        ])
        self.assertEqual(get_commit_export_state(commit, MockLocalWPT(test_patch=[(True, '')]), github),
                         (CommitExportState.EXPORTABLE_CLEAN, ''))

    def test_commit_that_has_closed_but_not_merged_pr(self):
        commit = MockChromiumCommit(MockHost(), change_id='I00decade')
        github = MockWPTGitHub(pull_requests=[
            PullRequest('PR2', 2, 'body\nChange-Id: I00decade', 'closed', []),
        ])
        # Regardless of verify_merged_pr, abandoned PRs are always exported.
        self.assertEqual(get_commit_export_state(commit, MockLocalWPT(), github, verify_merged_pr=False),
                         (CommitExportState.EXPORTED, ''))
        self.assertEqual(get_commit_export_state(commit, MockLocalWPT(), github, verify_merged_pr=True),
                         (CommitExportState.EXPORTED, ''))

    def test_commit_that_has_merged_pr_and_found_locally(self):
        commit = MockChromiumCommit(MockHost(), change_id='I00decade')
        github = MockWPTGitHub(pull_requests=[
            PullRequest('PR2', 2, 'body\nChange-Id: I00decade', 'closed', []),
        ], merged_index=0)
        self.assertEqual(get_commit_export_state(commit, MockLocalWPT(change_ids=['I00decade']), github, verify_merged_pr=False),
                         (CommitExportState.EXPORTED, ''))
        self.assertEqual(get_commit_export_state(commit, MockLocalWPT(change_ids=['I00decade']), github, verify_merged_pr=True),
                         (CommitExportState.EXPORTED, ''))

    def test_commit_that_has_merged_pr_but_not_found_locally(self):
        commit = MockChromiumCommit(MockHost(), change_id='I00decade')
        github = MockWPTGitHub(pull_requests=[
            PullRequest('PR2', 2, 'body\nChange-Id: I00decade', 'closed', []),
        ], merged_index=0)
        # verify_merged_pr should be False by default.
        self.assertEqual(get_commit_export_state(commit, MockLocalWPT(), github),
                         (CommitExportState.EXPORTED, ''))
        self.assertEqual(get_commit_export_state(commit, MockLocalWPT(test_patch=[(True, '')]), github, verify_merged_pr=True),
                         (CommitExportState.EXPORTABLE_CLEAN, ''))

    def test_commit_that_produces_errors(self):
        commit = MockChromiumCommit(MockHost())
        github = MockWPTGitHub(pull_requests=[])
        self.assertEqual(get_commit_export_state(commit, MockLocalWPT(test_patch=[(False, 'error')]), github),
                         (CommitExportState.EXPORTABLE_DIRTY, 'error'))

    def test_commit_that_produces_empty_diff(self):
        commit = MockChromiumCommit(MockHost())
        github = MockWPTGitHub(pull_requests=[])
        self.assertEqual(get_commit_export_state(commit, MockLocalWPT(test_patch=[(False, '')]), github),
                         (CommitExportState.EXPORTABLE_DIRTY, ''))
