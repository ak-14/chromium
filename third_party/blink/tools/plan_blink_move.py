#!/usr/bin/env vpython
# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os
import re
import sys

sys.path.append(os.path.join(os.path.dirname(__file__),
                             '..', 'renderer', 'build', 'scripts'))
from blinkbuild.name_style_converter import NameStyleConverter
from webkitpy.common.system.filesystem import FileSystem


def relative_dest(fs, filename):
    """Returns a destination path string for given filename.

    |filename| is a path relative to third_party/WebKit, and the resultant path
    is relative to third_party/blink.
    """
    dest = None
    if filename.startswith('Source'):
        dest = re.sub(r'^Source', 'renderer', filename)
    elif filename.startswith('common') or filename.startswith('public'):
        dest = filename
    else:
        raise ValueError('|filename| must start with "common", "public", or "Source": %s' % filename)
    if filename.endswith(('.h', '.cpp', '.mm', '.idl', '.typemap', '.proto', 'Settings.json5')):
        dirname, basename = fs.split(dest)
        basename, ext = fs.splitext(basename)
        # Skip some inspector-related files. #includes for these files are
        # generated by a script outside of Blink.
        if (re.match(r'Inspector.*Agent', basename)
                or basename.startswith('AdTracker')
                or basename == 'InspectorTraceEvents'
                or basename == 'PerformanceMonitor'
                or basename == 'PlatformTraceEventsAgent'):
            return dest
        if filename.endswith('.cpp'):
            ext = '.cc'
        # WebKit.h should be renamed to blink.h.
        if basename == 'WebKit' and ext == '.h':
            basename = 'blink'
        if basename.lower() != basename:
            basename = NameStyleConverter(basename).to_snake_case()
        return fs.join(dirname, basename + ext)
    return dest


def start_with_list(name, prefixes):
    if len(prefixes) == 0:
        return True
    for prefix in prefixes:
        if name.startswith(prefix):
            return True
    return False


def plan_blink_move(fs, prefixes):
    """Returns (source, dest) path pairs.

    The source paths are relative to third_party/WebKit,
    and the dest paths are relative to third_party/blink.
    The paths use os.sep as the path part separator.
    """
    blink_dir = fs.join(fs.dirname(__file__), '..')
    webkit_dir = fs.join(blink_dir, '..', '..', 'third_party', 'WebKit')
    source_files = fs.files_under(fs.join(webkit_dir, 'Source'))
    source_files += fs.files_under(fs.join(webkit_dir, 'common'))
    source_files += fs.files_under(fs.join(webkit_dir, 'public'))

    # It's possible to check git.exists() here, but we don't do it due to slow
    # performance. We should check it just before executing git command.

    source_files = [f[len(webkit_dir) + 1:] for f in source_files]
    return [(f, relative_dest(fs, f)) for f in source_files
            if f.find('node_modules') == -1 and start_with_list(f, prefixes)]


def main():
    fs = FileSystem()
    file_pairs = plan_blink_move(fs, sys.argv[1:])
    print 'Show renaming plan. It contains files not in the repository.'
    print '<Source path relative to third_party/WebKit> => <Destination path relative to third_party/blink>'
    for pair in file_pairs:
        print '%s\t=>\t%s' % pair


if __name__ == '__main__':
    main()
