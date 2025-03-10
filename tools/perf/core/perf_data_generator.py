#!/usr/bin/env vpython
# Copyright 2016 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# pylint: disable=too-many-lines

"""Script to generate chromium.perf.json in
the src/testing/buildbot directory and benchmark.csv in the src/tools/perf
directory. Maintaining these files by hand is too unwieldy.
Note: chromium.perf.fyi.json is updated manuall for now until crbug.com/757933
is complete.
"""
import argparse
import collections
import csv
import filecmp
import json
import os
import re
import sys
import sets
import tempfile


from core import path_util
path_util.AddTelemetryToPath()

from telemetry import benchmark as benchmark_module
from telemetry import decorators

from py_utils import discover

from core.sharding_map_generator import load_benchmark_sharding_map


_UNSCHEDULED_TELEMETRY_BENCHMARKS = set([
  'experimental.startup.android.coldish'
  ])


ANDROID_BOT_TO_DEVICE_TYPE_MAP = {
  'Android Swarming N5X Tester': 'Nexus 5X',
  'Android Nexus5X Perf': 'Nexus 5X',
  'Android Nexus5 Perf': 'Nexus 5',
  'Android Nexus6 Perf': 'Nexus 6',
  'Android Nexus7v2 Perf': 'Nexus 7',
  'Android One Perf': 'W6210 (4560MMX_b fingerprint)',
  'Android Nexus5X WebView Perf': 'Nexus 5X',
  'Android Nexus6 WebView Tester': 'Nexus 6',
}

SVELTE_DEVICE_LIST = ['W6210 (4560MMX_b fingerprint)']


def add_builder(waterfall, name, additional_compile_targets=None):
  waterfall['builders'][name] = added = {}
  if additional_compile_targets:
    added['additional_compile_targets'] = additional_compile_targets

  return waterfall

def add_tester(waterfall, name, perf_id, platform, target_bits=64,
               num_host_shards=1, num_device_shards=1, swarming=None,
               replace_system_webview=False):
  """ Adds tester named |name| to |waterfall|.

  Tests can be added via 'perf_tests', which expects a 2 element tuple of
  (isolate_name, shard), or via 'perf_tests_with_args', which allows you
  to specify command line arguments for the tests. 'perf_tests_with_args'
  expects a tuple of 4 elements: (name, shard, test_args, isolate_name).
  'test_args' is a list of strings pass via the test's command line.
  """
  del perf_id # this will be needed
  waterfall['testers'][name] = {
    'platform': platform,
    'num_device_shards': num_device_shards,
    'num_host_shards': num_host_shards,
    'target_bits': target_bits,
    'replace_system_webview': replace_system_webview,
  }

  if swarming:
    waterfall['testers'][name]['swarming_dimensions'] = swarming
    waterfall['testers'][name]['swarming'] = True

  return waterfall


# Additional compile targets to add to builders.
# On desktop builders, chromedriver is added as an additional compile target.
# The perf waterfall builds this target for each commit, and the resulting
# ChromeDriver is archived together with Chrome for use in bisecting.
# This can be used by Chrome test team, as well as by google3 teams for
# bisecting Chrome builds with their web tests. For questions or to report
# issues, please contact johnchen@chromium.org and stgao@chromium.org.
BUILDER_ADDITIONAL_COMPILE_TARGETS = {
    'Android Compile': ['microdump_stackwalk', 'angle_perftests'],
    'Android arm64 Compile': ['microdump_stackwalk', 'angle_perftests'],
    'Linux Builder': ['chromedriver'],
    'Mac Builder': ['chromedriver'],
    'Win Builder': ['chromedriver'],
    'Win x64 Builder': ['chromedriver'],
}


def get_waterfall_config():
  waterfall = {'builders':{}, 'testers': {}}

  for builder, targets in BUILDER_ADDITIONAL_COMPILE_TARGETS.items():
    waterfall = add_builder(
        waterfall, builder, additional_compile_targets=targets)

  # These configurations are taken from chromium_perf.py in
  # build/scripts/slave/recipe_modules/chromium_tests and must be kept in sync
  # to generate the correct json for each tester
  waterfall = add_tester(
    waterfall, 'Android Nexus5X Perf', 'android-nexus5X', 'android',
    swarming=[
      {
       'os': 'Android',
       'pool': 'Chrome-perf',
       'device_ids': [
           'build73-b1--device1', 'build73-b1--device2', 'build73-b1--device3',
           'build73-b1--device4', 'build73-b1--device5', 'build73-b1--device6',
           'build73-b1--device7',
           'build74-b1--device1', 'build74-b1--device2', 'build74-b1--device3',
           'build74-b1--device4', 'build74-b1--device5', 'build74-b1--device6',
           'build74-b1--device7',
           'build75-b1--device1', 'build75-b1--device2', 'build75-b1--device3',
           'build75-b1--device4', 'build75-b1--device5', 'build75-b1--device6',
           'build75-b1--device7',
          ],
       'perf_tests': [
         ('tracing_perftests', 'build73-b1--device2'),
         ('gpu_perftests', 'build73-b1--device2'),
         ('media_perftests', 'build74-b1--device7'),
         ('components_perftests', 'build74-b1--device1'),
       ],
       'perf_tests_with_args': [
         ('angle_perftests', 'build73-b1--device4', ['--shard-timeout=300'],
           'angle_perftests'),
       ]
      }
    ])
  waterfall = add_tester(
    waterfall, 'Android Nexus5 Perf', 'android-nexus5', 'android',
    swarming=[
      {
       'os': 'Android',
       'pool': 'Chrome-perf',
       'device_ids': [
           'build13-b1--device1', 'build13-b1--device2', 'build13-b1--device3',
           'build13-b1--device4', 'build13-b1--device5', 'build13-b1--device6',
           'build13-b1--device7',
           'build14-b1--device1', 'build14-b1--device2', 'build14-b1--device3',
           'build14-b1--device4', 'build14-b1--device5', 'build14-b1--device6',
           'build14-b1--device7',
           'build48-b1--device1', 'build48-b1--device2', 'build48-b1--device3',
           'build48-b1--device4', 'build48-b1--device5', 'build48-b1--device6',
           'build48-b1--device7',
          ],
       'perf_tests': [
         ('tracing_perftests', 'build13-b1--device2'),
         ('gpu_perftests', 'build13-b1--device2'),
         ('components_perftests', 'build48-b1--device5'),
        ],
       'perf_tests_with_args': [
         ('angle_perftests', 'build13-b1--device3', ['--shard-timeout=300'],
           'angle_perftests'),
       ]
      }
    ])

  waterfall = add_tester(
    waterfall, 'Android Nexus6 Perf', 'android-nexus6', 'android',
    swarming=[
      {
       'os': 'Android',
       'pool': 'Chrome-perf',
       'device_ids': [
           'build15-b1--device1', 'build15-b1--device2', 'build15-b1--device3',
           'build15-b1--device4', 'build15-b1--device5', 'build15-b1--device6',
           'build15-b1--device7',
           'build16-b1--device1', 'build16-b1--device2', 'build16-b1--device3',
           'build16-b1--device4', 'build16-b1--device5', 'build16-b1--device6',
           'build16-b1--device7',
           'build45-b1--device1', 'build45-b1--device2', 'build45-b1--device3',
           'build45-b1--device4', 'build45-b1--device5', 'build45-b1--device6',
           'build45-b1--device7',
          ],
       'perf_tests': [
         ('tracing_perftests', 'build15-b1--device2'),
         ('gpu_perftests', 'build16-b1--device2'),
        ]
      }
    ])

  waterfall = add_tester(
    waterfall, 'Android Nexus7v2 Perf', 'android-nexus7v2', 'android',
    swarming=[
      {
       'os': 'Android',
       'pool': 'Chrome-perf',
       'device_ids': [
           'build9-b1--device1', 'build9-b1--device2', 'build9-b1--device3',
           'build9-b1--device4', 'build9-b1--device5', 'build9-b1--device6',
           'build9-b1--device7',
           'build10-b1--device1', 'build10-b1--device2', 'build10-b1--device3',
           'build10-b1--device4', 'build10-b1--device5', 'build10-b1--device6',
           'build10-b1--device7',
           'build49-b1--device1', 'build49-b1--device2', 'build49-b1--device3',
           'build49-b1--device4', 'build49-b1--device5', 'build49-b1--device6',
           'build49-b1--device7',
          ],
       'perf_tests': [
         ('tracing_perftests', 'build9-b1--device2'),
         ('gpu_perftests', 'build10-b1--device2'),
        ],
       'perf_tests_with_args': [
         ('angle_perftests', 'build49-b1--device7', ['--shard-timeout=300'],
           'angle_perftests'),
       ]
      }
    ])

  waterfall = add_tester(
    waterfall, 'Android One Perf', 'android-nexus7v2', 'android',
    swarming=[
      {
       'os': 'Android',
       'pool': 'Chrome-perf',
       'device_ids': [
           'build17-b1--device1', 'build17-b1--device2', 'build17-b1--device3',
           'build17-b1--device4', 'build17-b1--device5', 'build17-b1--device6',
           'build17-b1--device7',
           'build18-b1--device1', 'build18-b1--device2', 'build18-b1--device3',
           'build18-b1--device4', 'build18-b1--device5', 'build18-b1--device6',
           'build18-b1--device7',
           'build47-b1--device1', 'build47-b1--device2', 'build47-b1--device3',
           'build47-b1--device4', 'build47-b1--device5', 'build47-b1--device6',
           'build47-b1--device7',
          ],
       'perf_tests': [
         ('tracing_perftests', 'build17-b1--device2'),
         # ('gpu_perftests', 'build18-b1--device2'), https://crbug.com/775219
        ]
      }
    ])

  waterfall = add_tester(
    waterfall, 'Android Nexus5X WebView Perf', 'android-webview-nexus5X',
    'android', swarming=[
      {
       'os': 'Android',
       'pool': 'chrome.tests.perf',
       'device_ids': [
           'build188-b7--device1', 'build188-b7--device2',
           'build188-b7--device3', 'build188-b7--device4',
           'build188-b7--device5', 'build188-b7--device6',
           'build188-b7--device7',
           'build189-b7--device1', 'build189-b7--device2',
           'build189-b7--device3', 'build189-b7--device4',
           'build189-b7--device5', 'build189-b7--device6',
           'build189-b7--device7',
           'build190-b7--device1', 'build190-b7--device2',
           'build190-b7--device3', 'build190-b7--device4',
           'build190-b7--device5', 'build190-b7--device6',
           'build190-b7--device7',
          ],
      }
    ], replace_system_webview=True)

  waterfall = add_tester(
    waterfall, 'Android Nexus6 WebView Perf', 'android-webview-nexus6',
    'android', swarming=[
      {
       'os': 'Android',
       'pool': 'Chrome-perf',
       'device_ids': [
           'build112-b1--device1', 'build112-b1--device2',
           'build112-b1--device3', 'build112-b1--device4',
           'build112-b1--device5', 'build112-b1--device6',
           'build112-b1--device7',
           'build113-b1--device1', 'build113-b1--device2',
           'build113-b1--device3', 'build113-b1--device4',
           'build113-b1--device5', 'build113-b1--device6',
           'build113-b1--device7',
           'build114-b1--device1', 'build114-b1--device2',
           'build114-b1--device3', 'build114-b1--device4',
           'build114-b1--device5', 'build114-b1--device6',
           'build114-b1--device7',
          ],
      }
    ], replace_system_webview=True)

  waterfall = add_tester(
    waterfall, 'Win 10 High-DPI Perf', 'win-high-dpi', 'win',
    swarming=[
      {
       'gpu': '8086:1616',
       'os': 'Windows-10',
       'pool': 'Chrome-perf',
       'device_ids': [
           'build117-b1', 'build118-b1',
           'build119-b1', 'build120-b1',
           'build180-b4' # Added in https://crbug.com/695613
          ]
      }
    ])
  waterfall = add_tester(
    waterfall, 'Win 10 Perf', 'chromium-rel-win10', 'win',
    swarming=[
      {
       'gpu': '8086:5912',
       'os': 'Windows-10',
       'pool': 'Chrome-perf',
       'device_ids': [
           'build189-a9', 'build190-a9',
           'build191-a9', 'build192-a9', 'build193-a9'
          ],
       'perf_tests': [
         ('media_perftests', 'build189-a9'),
         ('views_perftests', 'build190-a9'),
         ('components_perftests', 'build191-a9')]
      }
    ])
  waterfall = add_tester(
    waterfall, 'Win 8 Perf', 'chromium-rel-win8-dual', 'win',
    swarming=[
      {
       'gpu': '102b:0532',
       'os': 'Windows-2012ServerR2-SP0',
       'pool': 'Chrome-perf',
       'device_ids': [
           'build143-m1', 'build144-m1',
           'build145-m1', 'build146-m1', 'build147-m1'
          ],
       'perf_tests': [
         ('load_library_perf_tests', 'build145-m1'),
         ('performance_browser_tests', 'build145-m1'),
         ('media_perftests', 'build146-m1')]
      }
    ])
  waterfall = add_tester(
    waterfall, 'Win 7 Perf', 'chromium-rel-win7-dual',
    'win', target_bits=32,
    swarming=[
      {
       'gpu': '102b:0532',
       'os': 'Windows-2008ServerR2-SP1',
       'pool': 'Chrome-perf',
       'device_ids': [
           'build185-m1', 'build186-m1',
           'build187-m1', 'build188-m1', 'build189-m1'
          ],
       'perf_tests': [
         ('load_library_perf_tests', 'build187-m1'),
         # crbug.com/735679
         # ('performance_browser_tests', 'build187-m1'),
         ('media_perftests', 'build188-m1'),
         ('components_perftests', 'build189-m1')]
      }
    ])
  waterfall = add_tester(
    waterfall, 'Win 7 x64 Perf',
    'chromium-rel-win7-x64-dual', 'win',
    swarming=[
      {
       'gpu': '102b:0532',
       'os': 'Windows-2008ServerR2-SP1',
       'pool': 'Chrome-perf',
       'device_ids': [
           'build138-m1', 'build139-m1',
           'build140-m1', 'build141-m1', 'build142-m1'
          ],
       'perf_tests': [
         ('load_library_perf_tests', 'build140-m1'),
         ('performance_browser_tests', 'build140-m1')]
      }
    ])
  waterfall = add_tester(
    waterfall, 'Win 7 ATI GPU Perf',
    'chromium-rel-win7-gpu-ati', 'win',
    swarming=[
      {
       'gpu': '1002:6613',
       'os': 'Windows-2008ServerR2-SP1',
       'pool': 'Chrome-perf',
       'device_ids': [
           'build101-m1', 'build102-m1',
           'build103-m1', 'build104-m1', 'build105-m1'
          ],
       'perf_tests': [
         # crbug.com/785291
         # ('angle_perftests', 'build103-m1'),
         ('load_library_perf_tests', 'build103-m1'),
         ('performance_browser_tests', 'build103-m1'),
         ('media_perftests', 'build104-m1')]
      }
    ])
  waterfall = add_tester(
    waterfall, 'Win 7 Intel GPU Perf',
    'chromium-rel-win7-gpu-intel', 'win',
    swarming=[
      {
       'gpu': '8086:041a',
       'os': 'Windows-2008ServerR2-SP1',
       'pool': 'Chrome-perf',
       'device_ids': [
           'build164-m1', 'build165-m1',
           'build166-m1', 'build167-m1', 'build168-m1'
          ],
       'perf_tests': [
         ('angle_perftests', 'build166-m1'),
         ('load_library_perf_tests', 'build166-m1'),
         ('performance_browser_tests', 'build166-m1')]
      }
    ])
  waterfall = add_tester(
    waterfall, 'Win 7 Nvidia GPU Perf',
    'chromium-rel-win7-gpu-nvidia', 'win',
    swarming=[
      {
       'gpu': '10de:1cb3',
       'os': 'Windows-2008ServerR2-SP1',
       'pool': 'Chrome-perf',
       'device_ids': [
           'build92-m1', 'build93-m1',
           'build94-m1', 'build95-m1', 'build96-m1'
          ],
       'perf_tests': [
         ('angle_perftests', 'build94-m1'),
         ('load_library_perf_tests', 'build94-m1'),
         # crbug.com/735679
         # ('performance_browser_tests', 'build94-m1'),
         ('media_perftests', 'build95-m1')
        ],
        'perf_tests_with_args': [
         ('passthrough_command_buffer_perftests', 'build94-m1',
          ['--use-cmd-decoder=passthrough', '--use-angle=gl-null'],
          'command_buffer_perftests'),
         ('validating_command_buffer_perftests', 'build94-m1',
          ['--use-cmd-decoder=validating', '--use-stub'],
          'command_buffer_perftests')]
      }
    ])

  waterfall = add_tester(
    waterfall, 'Mac 10.12 Perf', 'chromium-rel-mac12',
    'mac',
    swarming=[
      {
       'os': 'Mac-10.12',
       'gpu': '8086:0a2e',
       'pool': 'Chrome-perf',
       'device_ids': [
           'build158-m1', 'build159-m1', 'build160-m1',
           'build161-m1', 'build162-m1'],
       'perf_tests': [
         ('net_perftests', 'build159-m1'),
         ('views_perftests', 'build160-m1'),
       ]
      }
    ])
  waterfall = add_tester(
    waterfall, 'Mac Pro 10.11 Perf',
    'chromium-rel-mac11-pro', 'mac',
    swarming=[
      {
       'gpu': '1002:6821',
       'os': 'Mac-10.11',
       'pool': 'Chrome-perf',
       'device_ids': [
           'build128-b1', 'build129-b1',
           'build130-b1', 'build131-b1', 'build132-b1'
          ],
       'perf_tests': [
         ('performance_browser_tests', 'build132-b1')
       ]
      }
    ])
  waterfall = add_tester(
    waterfall, 'Mac Air 10.11 Perf',
    'chromium-rel-mac11-air', 'mac',
    swarming=[
      {
       'gpu': '8086:1626',
       'os': 'Mac-10.11',
       'pool': 'Chrome-perf',
       'device_ids': [
           'build123-b1', 'build124-b1',
           'build125-b1', 'build126-b1', 'build127-b1'
          ],
       'perf_tests': [
         ('performance_browser_tests', 'build126-b1')
       ]
      }
    ])

  return waterfall


def generate_isolate_script_entry(swarming_dimensions, test_args,
    isolate_name, step_name, ignore_task_failure,
    override_compile_targets=None,
    swarming_timeout=None,
    io_timeout=None):
  result = {
    'args': test_args,
    'isolate_name': isolate_name,
    'name': step_name,
  }
  if override_compile_targets:
    result['override_compile_targets'] = override_compile_targets
  if swarming_dimensions:
    result['swarming'] = {
      # Always say this is true regardless of whether the tester
      # supports swarming. It doesn't hurt.
      'can_use_on_swarming_builders': True,
      'expiration': 10 * 60 * 60, # 10 hour timeout
      'hard_timeout': swarming_timeout if swarming_timeout else 10800, # 3 hours
      'ignore_task_failure': ignore_task_failure,
      'io_timeout': io_timeout if io_timeout else 1200, # 20 minutes
      'dimension_sets': swarming_dimensions,
      'upload_test_results': True,
    }
  return result


BENCHMARKS_TO_OUTPUT_HISTOGRAMS = [
    'dummy_benchmark.noisy_benchmark_1',
    'dummy_benchmark.stable_benchmark_1',
    'blink_perf.bindings',
    'blink_perf.canvas',
    'blink_perf.css',
    'blink_perf.dom',
    'blink_perf.events',
    'blink_perf.image_decoder',
    'blink_perf.layout',
    'blink_perf.owp_storage',
    'blink_perf.paint',
    'blink_perf.parser',
    'blink_perf.shadow_dom',
    'blink_perf.svg',
    'memory.top_10_mobile'
]


def generate_telemetry_test(swarming_dimensions, benchmark_name, browser):
  # The step name must end in 'test' or 'tests' in order for the
  # results to automatically show up on the flakiness dashboard.
  # (At least, this was true some time ago.) Continue to use this
  # naming convention for the time being to minimize changes.

  test_args = [
    benchmark_name,
    '-v',
    '--upload-results',
    '--browser=%s' % browser
  ]
  # When this is enabled on more than just windows machines we will need
  # --device=android

  if benchmark_name in BENCHMARKS_TO_OUTPUT_HISTOGRAMS:
    test_args.append('--output-format=histograms')
  else:
    test_args.append('--output-format=chartjson')

  ignore_task_failure = False
  step_name = benchmark_name
  if browser == 'reference':
    # If there are more than 5 failures, usually the whole ref build benchmark
    # will fail & the reference browser binary need to be updated.
    # Also see crbug.com/707236 for more context.
    test_args.append('--max-failures=5')
    test_args.append('--output-trace-tag=_ref')
    step_name += '.reference'
    # We ignore the failures on reference builds since there is little we can do
    # to fix them except waiting for the reference build to update.
    ignore_task_failure = True

  isolate_name = 'telemetry_perf_tests'
  if browser == 'android-webview':
    test_args.append(
        '--webview-embedder-apk=../../out/Release/apks/SystemWebViewShell.apk')
    isolate_name = 'telemetry_perf_webview_tests'

  return generate_isolate_script_entry(
      swarming_dimensions, test_args, isolate_name,
      step_name, ignore_task_failure=ignore_task_failure,
      override_compile_targets=[isolate_name],
      swarming_timeout=BENCHMARK_SWARMING_TIMEOUTS.get(benchmark_name),
      io_timeout=BENCHMARK_SWARMING_IO_TIMEOUTS.get(benchmark_name))


def script_test_enabled_on_tester(master, test, tester_name, shard):
  for enabled_tester in test['testers'].get(master, []):
    if enabled_tester['name'] == tester_name:
      if shard in enabled_tester['shards']:
        return True
  return False


def get_swarming_dimension(dimension, device_id):
  assert device_id in dimension['device_ids']

  complete_dimension = {
    'id': device_id,
    'os': dimension['os'],
    'pool': dimension['pool'],
  }
  if 'gpu' in dimension:
    complete_dimension['gpu'] = dimension['gpu']
  return complete_dimension


def generate_cplusplus_isolate_script_entry(
    dimension, name, shard, test_args, isolate_name):
  return generate_isolate_script_entry(
      [get_swarming_dimension(dimension, shard)], test_args, isolate_name,
         name, ignore_task_failure=False)


def generate_cplusplus_isolate_script_test(dimension):
  return [
    generate_cplusplus_isolate_script_entry(
        dimension, name, shard, [], name)
    for name, shard in dimension['perf_tests']
  ]


def generate_cplusplus_isolate_script_test_with_args(dimension):
  return [
    generate_cplusplus_isolate_script_entry(
        dimension, name, shard, test_args, isolate_name)
    for name, shard, test_args, isolate_name
        in dimension['perf_tests_with_args']
  ]


def ShouldBenchmarksBeScheduled(
    benchmark, name, os_name, browser_name):
  # StoryExpectations uses finder_options.browser_type, platform.GetOSName,
  # platform.GetDeviceTypeName, and platform.IsSvelte to determine if the
  # the expectation test condition is true and the test should be disabled.
  # This class is used as a placeholder for finder_options and platform since
  # we do not have enough information to create those objection.
  class ExpectationData(object):
    def __init__(self, browser_type, os_name, device_type_name):
      self._browser_type = browser_type
      self._os_name = os_name
      self._is_svelte = False
      if os_name == 'android' and device_type_name in SVELTE_DEVICE_LIST:
        self._is_svelte = True
      self._device_type_name = device_type_name

    def GetOSName(self):
      return self._os_name

    def GetDeviceTypeName(self):
      return self._device_type_name if self._device_type_name else ''

    @property
    def browser_type(self):
      return self._browser_type

    def IsSvelte(self):
      return self._is_svelte

  # OS names are the exact OS names. We need ExpectationData to return OS names
  # that are consistent with platform_backend in telemetry to work.
  def sanitize_os_name(os_name):
    lower_name = os_name.lower()
    if 'win' in lower_name:
      return 'win'
    if 'mac' in lower_name:
      return 'mac'
    if 'android' in lower_name:
      return 'android'
    if 'ubuntu' in lower_name or 'linux' in lower_name:
      return 'linux'
    if lower_name == 'skynet':
      print ('OS name appears to be for testing purposes. If this is in error '
             'file a bug.')
      return 'TEST'
    raise TypeError('Unknown OS name detected.')

  device_type_name = ANDROID_BOT_TO_DEVICE_TYPE_MAP.get(name)
  os_name = sanitize_os_name(os_name)
  e = ExpectationData(browser_name, os_name, device_type_name)

  b = benchmark()
  # TODO(rnephew): As part of the refactoring of TestConditions this will
  # be refactored to make more sense. SUPPORTED_PLATFORMS was not the original
  # intended use of TestConditions, so we actually want to test the opposite.
  # If ShouldDisable() returns true, we should schedule the benchmark here.
  return any(t.ShouldDisable(e, e) for t in b.SUPPORTED_PLATFORMS)


def generate_telemetry_tests(name, tester_config, benchmarks,
                             benchmark_sharding_map,
                             benchmark_ref_build_blacklist):
  isolated_scripts = []
  # First determine the browser that you need based on the tester
  browser_name = ''
  if tester_config['platform'] == 'android':
    if tester_config.get('replace_system_webview', False):
      browser_name = 'android-webview'
    else:
      browser_name = 'android-chromium'
  elif (tester_config['platform'] == 'win'
    and tester_config['target_bits'] == 64):
    browser_name = 'release_x64'
  else:
    browser_name ='release'

  for benchmark in benchmarks:
    # First figure out swarming dimensions this test needs to be triggered on.
    # For each set of dimensions it is only triggered on one of the devices
    swarming_dimensions = []
    for dimension in tester_config['swarming_dimensions']:
      device = None
      sharding_map = benchmark_sharding_map.get(name, None)
      device = sharding_map.get(benchmark.Name(), None)
      if not device:
        raise ValueError('No sharding map for benchmark %r found. Please '
                         'add the benchmark to '
                         '_UNSCHEDULED_TELEMETRY_BENCHMARKS list, '
                         'then file a bug with Speed>Benchmarks>Waterfall '
                         'component and assign to eyaich@ or ashleymarie@ to '
                         'schedule the benchmark on the perf waterfall.' % (
                             benchmark.Name()))
      swarming_dimensions.append(get_swarming_dimension(
          dimension, device))

    if not ShouldBenchmarksBeScheduled(
        benchmark, name, swarming_dimensions[0]['os'], browser_name):
      continue

    test = generate_telemetry_test(
      swarming_dimensions, benchmark.Name(), browser_name)
    isolated_scripts.append(test)
    # Now create another executable for this benchmark on the reference browser
    # if it is not blacklisted from running on the reference browser.
    # Webview doesn't have a reference build right now.
    if not tester_config.get('replace_system_webview', False) and (
        benchmark.Name() not in benchmark_ref_build_blacklist):
      reference_test = generate_telemetry_test(
        swarming_dimensions, benchmark.Name(),'reference')
      isolated_scripts.append(reference_test)

  return isolated_scripts


# Overrides the default 2 hour timeout for swarming tasks.
BENCHMARK_SWARMING_TIMEOUTS = {
    'loading.desktop': 14400, # 4 hours (crbug.com/753798)
    'loading.mobile': 16200, # 4.5 hours
    'system_health.memory_mobile': 14400, # 4 hours (crbug.com/775242)
    'system_health.memory_desktop': 10800, # 3 hours
}


# Overrides the default 10m swarming I/O timeout.
BENCHMARK_SWARMING_IO_TIMEOUTS = {
    'jetstream': 1200, # 20 minutes
}


# Devices which are broken right now. Tests will not be scheduled on them.
# Please add a comment with a bug for replacing the device.
BLACKLISTED_DEVICES = []


# List of benchmarks that are to never be run with reference builds.
BENCHMARK_REF_BUILD_BLACKLIST = [
  'loading.desktop',  # Long running benchmark.
  'loading.mobile',  # Long running benchmark.
  'power.idle_platform',  # No browser used in benchmark.
  'v8.runtime_stats.top_25',  # Long running benchmark.
]



def current_benchmarks():
  benchmarks_dir = os.path.join(
      path_util.GetChromiumSrcDir(), 'tools', 'perf', 'benchmarks')
  top_level_dir = os.path.dirname(benchmarks_dir)

  all_benchmarks = []

  for b in discover.DiscoverClasses(
      benchmarks_dir, top_level_dir, benchmark_module.Benchmark,
      index_by_class_name=True).values():
    if not b.Name() in _UNSCHEDULED_TELEMETRY_BENCHMARKS:
      all_benchmarks.append(b)

  return sorted(all_benchmarks, key=lambda b: b.Name())


def remove_blacklisted_device_tests(tests, blacklisted_devices):
  new_tests = []
  blacklist_device_to_test = collections.defaultdict(list)
  for test in tests:
    if test.get('swarming', None):
      swarming = test['swarming']
      new_dimensions = []

      for dimension in swarming['dimension_sets']:
        if dimension['id'] in blacklisted_devices:
          blacklist_device_to_test[dimension['id']].append(test['name'])
          continue
        new_dimensions.append(dimension)
      if not new_dimensions:
        continue
    new_tests.append(test)

  return new_tests, {
      device: sorted(tests) for device, tests
      in blacklist_device_to_test.items()}


def generate_all_tests(waterfall):
  tests = {}

  all_benchmarks = current_benchmarks()
  benchmark_sharding_map = load_benchmark_sharding_map()

  for name, config in waterfall['testers'].iteritems():
    assert config.get('swarming', False), 'Only swarming config is supported'
    # Our current configuration only ever has one set of swarming dimensions
    # Make sure this still holds true
    if len(config['swarming_dimensions']) > 1:
      raise Exception('Invalid assumption on number of swarming dimensions')
    # Generate benchmarks
    isolated_scripts = generate_telemetry_tests(
        name, config, all_benchmarks, benchmark_sharding_map,
        BENCHMARK_REF_BUILD_BLACKLIST)
    # Generate swarmed non-telemetry tests if present
    if config['swarming_dimensions'][0].get('perf_tests', False):
      isolated_scripts += generate_cplusplus_isolate_script_test(
        config['swarming_dimensions'][0])
    if config['swarming_dimensions'][0].get('perf_tests_with_args', False):
      isolated_scripts += generate_cplusplus_isolate_script_test_with_args(
        config['swarming_dimensions'][0])

    isolated_scripts, devices_to_test_skipped = remove_blacklisted_device_tests(
        isolated_scripts, BLACKLISTED_DEVICES)
    if devices_to_test_skipped:
      for device, skipped_tests in devices_to_test_skipped.items():
        print (
          'Device "%s" is blacklisted. These benchmarks are not scheduled:' % (
              device))
        for test in skipped_tests:
          print ' * %s' % test
    tests[name] = {
      'isolated_scripts': sorted(isolated_scripts, key=lambda x: x['name'])
    }

  for name, config in waterfall['builders'].iteritems():
    tests[name] = config

  tests['AAAAA1 AUTOGENERATED FILE DO NOT EDIT'] = {}
  tests['AAAAA2 See //tools/perf/generate_perf_data to make changes'] = {}
  return tests


def update_all_tests(waterfall, file_path):
  tests = generate_all_tests(waterfall)
  # Add in the migrated testers for the new recipe.
  get_new_recipe_testers(NEW_PERF_RECIPE_MIGRATED_TESTERS, tests)
  with open(file_path, 'w') as fp:
    json.dump(tests, fp, indent=2, separators=(',', ': '), sort_keys=True)
    fp.write('\n')
  verify_all_tests_in_benchmark_csv(tests,
                                    get_all_waterfall_benchmarks_metadata())


# not_scheduled means this test is not scheduled on any of the chromium.perf
# waterfalls. Right now, all the below benchmarks are scheduled, but some other
# benchmarks are not scheduled, because they're disabled on all platforms.
BenchmarkMetadata = collections.namedtuple(
    'BenchmarkMetadata', 'emails component not_scheduled')
NON_TELEMETRY_BENCHMARKS = {
    'angle_perftests': BenchmarkMetadata(
        'jmadill@chromium.org, chrome-gpu-perf-owners@chromium.org',
        'Internals>GPU>ANGLE', False),
    'validating_command_buffer_perftests': BenchmarkMetadata(
        'piman@chromium.org, chrome-gpu-perf-owners@chromium.org',
        'Internals>GPU', False),
    'passthrough_command_buffer_perftests': BenchmarkMetadata(
        'piman@chromium.org, chrome-gpu-perf-owners@chromium.org',
        'Internals>GPU>ANGLE', False),
    'net_perftests': BenchmarkMetadata('xunjieli@chromium.org', None, False),
    'gpu_perftests': BenchmarkMetadata(
        'reveman@chromium.org, chrome-gpu-perf-owners@chromium.org',
        'Internals>GPU', False),
    'tracing_perftests': BenchmarkMetadata(
        'kkraynov@chromium.org, primiano@chromium.org', None, False),
    'load_library_perf_tests': BenchmarkMetadata(
        'xhwang@chromium.org, crouleau@chromium.org',
        'Internals>Media>Encrypted', False),
    'media_perftests': BenchmarkMetadata('crouleau@chromium.org', None, False),
    'performance_browser_tests': BenchmarkMetadata(
        'miu@chromium.org', None, False),
    'views_perftests': BenchmarkMetadata(
        'tapted@chromium.org', 'Internals>Views', False),
    'components_perftests': BenchmarkMetadata(
        'csharrison@chromium.org', None, False)
}


# If you change this dictionary, run tools/perf/generate_perf_data
NON_WATERFALL_BENCHMARKS = {
    'sizes (mac)': BenchmarkMetadata('tapted@chromium.org', None, False),
    'sizes (win)': BenchmarkMetadata('grt@chromium.org', None, False),
    'sizes (linux)': BenchmarkMetadata('thestig@chromium.org', None, False),
    'resource_sizes': BenchmarkMetadata(
        'agrieve@chromium.org, rnephew@chromium.org, perezju@chromium.org',
        None, False),
    'supersize_archive': BenchmarkMetadata('agrieve@chromium.org', None, False),
}


# Returns a dictionary mapping waterfall benchmark name to benchmark owner
# metadata
def get_all_waterfall_benchmarks_metadata():
  return get_all_benchmarks_metadata(NON_TELEMETRY_BENCHMARKS)


def get_all_benchmarks_metadata(metadata):
  benchmark_list = current_benchmarks()

  for benchmark in benchmark_list:
    emails = decorators.GetEmails(benchmark)
    if emails:
      emails = ', '.join(emails)
    metadata[benchmark.Name()] = BenchmarkMetadata(
        emails, decorators.GetComponent(benchmark), False)
  return metadata


def verify_all_tests_in_benchmark_csv(tests, benchmark_metadata):
  benchmark_names = sets.Set(benchmark_metadata)
  test_names = sets.Set()
  for t in tests:
    scripts = []
    if 'isolated_scripts' in tests[t]:
      scripts = tests[t]['isolated_scripts']
    elif 'scripts' in tests[t]:
      scripts = tests[t]['scripts']
    else:
      assert(t in BUILDER_ADDITIONAL_COMPILE_TARGETS
             or t.startswith('AAAAA')), 'Unknown test data %s' % t
    for s in scripts:
      name = s['name']
      name = re.sub('\\.reference$', '', name)
      # TODO(eyaich): Determine new way to generate ownership based
      # on the benchmark bot map instead of on the generated tests
      # for new perf recipe.
      if name is 'performance_test_suite':
        continue
      test_names.add(name)

  # Disabled tests are filtered out of the waterfall json. Add them back here.
  for name, data in benchmark_metadata.items():
    if data.not_scheduled:
      test_names.add(name)

  error_messages = []
  for test in benchmark_names - test_names:
    error_messages.append('Remove ' + test + ' from NON_TELEMETRY_BENCHMARKS')
  for test in test_names - benchmark_names:
    error_messages.append('Add ' + test + ' to NON_TELEMETRY_BENCHMARKS')

  assert benchmark_names == test_names, ('Please update '
      'NON_TELEMETRY_BENCHMARKS as below:\n' + '\n'.join(error_messages))

  _verify_benchmark_owners(benchmark_metadata)


# Verify that all benchmarks have owners except those on the whitelist.
def _verify_benchmark_owners(benchmark_metadata):
  unowned_benchmarks = set()
  for benchmark_name in benchmark_metadata:
    if benchmark_metadata[benchmark_name].emails == None:
      unowned_benchmarks.add(benchmark_name)

  assert not unowned_benchmarks, (
      'All benchmarks must have owners. Please add owners for the following '
      'benchmarks:\n%s' % '\n'.join(unowned_benchmarks))


def update_benchmark_csv(file_path):
  """Updates go/chrome-benchmarks.

  Updates telemetry/perf/benchmark.csv containing the current benchmark names,
  owners, and components. Requires that all benchmarks have owners.
  """
  header_data = [['AUTOGENERATED FILE DO NOT EDIT'],
      ['See //tools/perf/generate_perf_data.py to make changes'],
      ['Benchmark name', 'Individual owners', 'Component']
  ]

  csv_data = []
  all_benchmarks = NON_TELEMETRY_BENCHMARKS
  all_benchmarks.update(NON_WATERFALL_BENCHMARKS)
  benchmark_metadata = get_all_benchmarks_metadata(all_benchmarks)
  _verify_benchmark_owners(benchmark_metadata)

  for benchmark_name in benchmark_metadata:
    csv_data.append([
        benchmark_name,
        benchmark_metadata[benchmark_name].emails,
        benchmark_metadata[benchmark_name].component
    ])

  csv_data = sorted(csv_data, key=lambda b: b[0])
  csv_data = header_data + csv_data

  with open(file_path, 'wb') as f:
    writer = csv.writer(f, lineterminator="\n")
    writer.writerows(csv_data)


def validate_tests(waterfall, waterfall_file, benchmark_file):
  up_to_date = True

  waterfall_tempfile = tempfile.NamedTemporaryFile(delete=False).name
  benchmark_tempfile = tempfile.NamedTemporaryFile(delete=False).name

  try:
    update_all_tests(waterfall, waterfall_tempfile)
    up_to_date &= filecmp.cmp(waterfall_file, waterfall_tempfile)

    update_benchmark_csv(benchmark_tempfile)
    up_to_date &= filecmp.cmp(benchmark_file, benchmark_tempfile)
  finally:
    os.remove(waterfall_tempfile)
    os.remove(benchmark_tempfile)

  return up_to_date


# This section is how we will generate json with the new perf recipe.
# We will only be generating one entry per isolate in the new world.
# Right now this is simply adding and/or updating chromium.perf.fyi.json
# until migration is complete.  See crbug.com/757933 for more info.
#
# To add a new isolate, add an entry to the 'tests' section.  Supported
# values in this json are:
# isolate: the name of the isolate you are trigger
# test_suite: name of the test suite if different than the isolate
#     that you want to show up as the test name
# extra_args: args that need to be passed to the script target
#     of the isolate you are running.
# shards: shard indices that you want the isolate to run on.  If omitted
#     will run on all shards.
# telemetry: boolean indicating if this is a telemetry test.  If omitted
#     assumed to be true.
NEW_PERF_RECIPE_FYI_TESTERS = {
  'testers' : {
    'Mac 10.13 Laptop High End': {
      'tests': [
        {
          'isolate': 'performance_test_suite',
        },
        {
          'isolate': 'net_perftests',
          'shards': [0],
          'telemetry': False,
        },
        {
          'isolate': 'views_perftests',
          'shards': [1],
          'telemetry': False,
        }
      ],
      'platform': 'mac',
      'dimension': {
        'pool': 'Chrome-perf-fyi',
        'os': 'Mac-10.13',
        'gpu': '1002:6821'
      },
      'device_ids': [
          'build246-a9', 'build247-a9', 'build248-a9', 'build249-a9',
          'build250-a9', 'build251-a9', 'build252-a9', 'build253-a9',
          'build254-a9', 'build255-a9', 'build256-a9', 'build257-a9',
          'build258-a9', 'build259-a9', 'build260-a9', 'build261-a9',
          'build262-a9', 'build263-a9', 'build264-a9', 'build265-a9',
          'build266-a9', 'build267-a9', 'build268-a9', 'build269-a9',
          'build270-a9', 'build271-a9'
      ],
    },
    'One Buildbot Step Test Builder': {
      'tests': [
        {
          'isolate': 'telemetry_perf_tests_experimental',
          'extra_args': ['--xvfb'],
        },
        {
          'isolate': 'load_library_perf_tests',
          'shards': [0],
          'telemetry': False,
        }
      ],
      'platform': 'linux',
      'dimension': {
        'pool': 'chrome.tests.perf-fyi',
        'os': 'Linux',
      },
      'testing': True,
      'device_ids': [
          'swarm77-c7',
          'swarm78-c7',
          'swarm79-c7'
      ],
    },
    'Android Go': {
      'tests': [
        {
          'name': 'performance_test_suite',
          'isolate': 'performance_test_suite',
        }
      ],
      'platform': 'android',
      'dimension': {
        'pool': 'chrome.tests.perf-fyi',
        'os': 'Android',
      },
      'device_ids': [
          'build30-a7--device1', 'build30-a7--device2', 'build30-a7--device3',
          'build30-a7--device4', 'build30-a7--device5', 'build30-a7--device6',
          'build30-a7--device7', 'build31-a7--device1', 'build31-a7--device2',
          'build31-a7--device3', 'build31-a7--device4', 'build31-a7--device5',
          'build31-a7--device6', 'build31-a7--device7'
      ],
    }
  }
}


NEW_PERF_RECIPE_MIGRATED_TESTERS = {
  'testers' : {
    'mac-10_12_laptop_low_end-perf': {
      'tests': [
        {
          'isolate': 'performance_test_suite',
        },
        {
          'isolate': 'load_library_perf_tests',
          'shards': [0],
          'telemetry': False,
        }
      ],
      'platform': 'mac',
      'dimension': {
        'pool': 'chrome.tests.perf',
        'os': 'Mac-10.12',
        'gpu': '8086:1626'
      },
      'device_ids': [
          'build41-a7', 'build42-a7', 'build43-a7', 'build44-a7',
          'build45-a7', 'build46-a7', 'build47-a7', 'build48-a7',
          'build49-a7', 'build50-a7', 'build51-a7', 'build52-a7',
          'build53-a7', 'build54-a7', 'build55-a7', 'build56-a7',
          'build57-a7', 'build58-a7', 'build59-a7', 'build60-a7',
          'build61-a7', 'build62-a7', 'build63-a7', 'build64-a7',
          'build65-a7', 'build66-a7'
      ],
    },
    'linux-perf': {
      'tests': [
        # Add views_perftests, crbug.com/811766
        {
          'isolate': 'performance_test_suite',
        },
        {
          'isolate': 'load_library_perf_tests',
          'shards': [0],
          'telemetry': False,
        },
        {
          'isolate': 'net_perftests',
          'shards': [1],
          'telemetry': False,
        },
        {
          'isolate': 'tracing_perftests',
          'shards': [2],
          'telemetry': False,
        },
        {
          'isolate': 'media_perftests',
          'shards': [3],
          'telemetry': False,
        }
      ],
      'platform': 'linux',
      'dimension': {
        'gpu': '10de:1cb3',
        'os': 'Ubuntu-14.04',
        'pool': 'chrome.tests.perf',
      },
      'device_ids': [
          'build67-a7', 'build68-a7', 'build69-a7', 'build70-a7',
          'build71-a7', 'build72-a7', 'build73-a7', 'build74-a7',
          'build75-a7', 'build76-a7', 'build77-a7', 'build78-a7',
          'build79-a7', 'build80-a7', 'build81-a7', 'build82-a7',
          'build83-a7', 'build84-a7', 'build85-a7', 'build86-a7',
          'build87-a7', 'build88-a7', 'build89-a7', 'build90-a7',
          'build91-a7', 'build92-a7'
      ],
    }
  }
}
def add_common_test_properties(test_entry, tester_config, test_spec):
  dimensions = []
  index = 0
  for device_id in tester_config['device_ids']:
    run_on_shard = True
    if test_spec.get('shards', False):
      # If specific shards are specified, only generate
      # a entry for the specified shards
      if index not in test_spec['shards']:
        run_on_shard = False
    if run_on_shard:
      dimensions.append({'id': device_id})
    index = index + 1
  test_entry['trigger_script'] = {
      'script': '//testing/trigger_scripts/perf_device_trigger.py',
      'args': [
          '--multiple-trigger-configs',
          json.dumps(dimensions),
          '--multiple-dimension-script-verbose',
          'True'
      ],
  }
  test_entry['merge'] = {
      'script': '//tools/perf/process_perf_results.py',
      'args': [
        '--service-account-file',
        '/creds/service_accounts/service-account-chromium-perf-histograms.json'
      ],
  }
  return len(dimensions)


def generate_telemetry_args(tester_config):
  # First determine the browser that you need based on the tester
  browser_name = ''
  # For trybot testing we always use the reference build
  if tester_config.get('testing', False):
    browser_name = 'reference'
  elif tester_config['platform'] == 'android':
    if tester_config.get('replace_system_webview', False):
      browser_name = 'android-webview'
    else:
      browser_name = 'android-chromium'
  elif (tester_config['platform'] == 'win'
    and tester_config['target_bits'] == 64):
    browser_name = 'release_x64'
  else:
    browser_name ='release'

  test_args = [
    '-v',
    '--browser=%s' % browser_name,
    '--upload-results'
  ]

  if browser_name == 'android-webview':
    test_args.append(
        '--webview-embedder-apk=../../out/Release/apks/SystemWebViewShell.apk')

  # Appending testing=true if we only want to run a subset of benchmarks
  # for quicker testing
  if tester_config.get('testing', False):
    test_args.append('--testing=true')

  return test_args

def generate_non_telemetry_args():
  # --non-telemetry tells run_performance_tests.py that this test needs
  #   to be executed differently
  # --migrated-test tells run_performance_test_wrapper that this has
  #   non-telemetry test has been migrated to the new recipe.
  return [
    '--non-telemetry=true',
    '--migrated-test=true'
  ]

def generate_performance_test(tester_config, test):
  if test.get('telemetry', True):
    test_args = generate_telemetry_args(tester_config)
  else:
    test_args = generate_non_telemetry_args()
  # Append any additional args specific to an isolate
  test_args += test.get('extra_args', [])
  isolate_name = test['isolate']

  # Check to see if the name is different than the isolate
  test_suite = isolate_name
  if test.get('test_suite', False):
    test_suite = test['test_suite']

  result = {
    'args': test_args,
    'isolate_name': isolate_name,
    'name': test_suite,
    'override_compile_targets': [
      isolate_name
    ]
  }
  shards = add_common_test_properties(result, tester_config, test)
  result['swarming'] = {
    # Always say this is true regardless of whether the tester
    # supports swarming. It doesn't hurt.
    'can_use_on_swarming_builders': True,
    'expiration': 10 * 60 * 60, # 10 hour timeout
    'hard_timeout': 10 * 60 * 60, # 10 hours for full suite
    'ignore_task_failure': False,
    'io_timeout': 30 * 60, # 30 minutes
    'dimension_sets': [
      tester_config['dimension']
    ],
    'upload_test_results': True,
    'shards': shards,
  }
  return result


def load_and_update_new_recipe_fyi_json():
  tests = {}
  filename = 'chromium.perf.fyi.json'
  buildbot_dir = os.path.join(
      path_util.GetChromiumSrcDir(), 'testing', 'buildbot')
  fyi_filepath = os.path.join(buildbot_dir, filename)
  with open(fyi_filepath) as fp_r:
    tests = json.load(fp_r)
  with open(fyi_filepath, 'w') as fp:
    # We have loaded what is there, we want to update or add
    # what we have listed here
    get_new_recipe_testers(NEW_PERF_RECIPE_FYI_TESTERS, tests)
    json.dump(tests, fp, indent=2, separators=(',', ': '), sort_keys=True)
    fp.write('\n')


def get_new_recipe_testers(testers, tests):
  for tester, tester_config in testers['testers'].iteritems():
    isolated_scripts = []
    for test in tester_config['tests']:
      isolated_scripts.append(generate_performance_test(tester_config, test))
    tests[tester] = {
      'isolated_scripts': sorted(isolated_scripts, key=lambda x: x['name'])
    }


def main(args):
  parser = argparse.ArgumentParser(
      description=('Generate perf test\' json config and benchmark.csv. '
                   'This needs to be done anytime you add/remove any existing'
                   'benchmarks in tools/perf/benchmarks.'))
  parser.add_argument(
      '--validate-only', action='store_true', default=False,
      help=('Validate whether the perf json generated will be the same as the '
            'existing configs. This does not change the contain of existing '
            'configs'))
  options = parser.parse_args(args)

  waterfall_file = os.path.join(
      path_util.GetChromiumSrcDir(), 'testing', 'buildbot',
      'chromium.perf.json')

  benchmark_file = os.path.join(
      path_util.GetChromiumSrcDir(), 'tools', 'perf', 'benchmark.csv')

  if options.validate_only:
    if validate_tests(get_waterfall_config(), waterfall_file, benchmark_file):
      print 'All the perf JSON config files are up-to-date. \\o/'
      return 0
    else:
      print ('The perf JSON config files are not up-to-date. Please run %s '
             'without --validate-only flag to update the perf JSON '
             'configs and benchmark.csv.') % sys.argv[0]
      return 1
  else:
    load_and_update_new_recipe_fyi_json()
    update_all_tests(get_waterfall_config(), waterfall_file)
    update_benchmark_csv(benchmark_file)
  return 0
