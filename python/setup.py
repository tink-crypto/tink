# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ==============================================================================
"""Setup for Tink package with pip."""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

from distutils import spawn
import glob
import os
import posixpath
import re
import shutil
import subprocess
import sys

import setuptools
from setuptools.command import build_ext


here = os.path.dirname(os.path.abspath(__file__))


def _get_tink_version():
  """Parses the version number from VERSION file."""
  with open(os.path.join(here, 'VERSION')) as f:
    try:
      version_line = next(
          line for line in f if line.startswith('TINK_VERSION_LABEL'))
    except StopIteration:
      raise ValueError('Version not defined in python/VERSION')
    else:
      return version_line.split(' = ')[-1].strip('\n \'"')

# Check Bazel enviroment and set executable
if spawn.find_executable('bazelisk'):
  bazel = 'bazelisk'
elif spawn.find_executable('bazel'):
  bazel = 'bazel'
else:
  sys.stderr.write('Could not find bazel executable. Please install bazel to'
                   'compile the Tink Python package.')
  sys.exit(-1)

# Find the Protocol Compiler.
if 'PROTOC' in os.environ and os.path.exists(os.environ['PROTOC']):
  protoc = os.environ['PROTOC']
else:
  protoc = spawn.find_executable('protoc')


def _generate_proto(source):
  """Invokes the Protocol Compiler to generate a _pb2.py."""

  output = source.replace('.proto', '_pb2.py')

  if (not os.path.exists(output) or
      (os.path.exists(source) and
       os.path.getmtime(source) > os.path.getmtime(output))):
    print('Generating %s...' % output)

    if not os.path.exists(source):
      sys.stderr.write('Cannot find required file: %s\n' % source)
      sys.exit(-1)

    if protoc is None:
      sys.stderr.write(
          'protoc is not installed nor found in ../src.  Please compile it '
          'or install the binary package.\n')
      sys.exit(-1)

    protoc_command = [protoc, '-I.', '--python_out=.', source]
    if subprocess.call(protoc_command) != 0:
      sys.exit(-1)

for proto_file in glob.glob('tink/proto/*.proto'):
  _generate_proto(proto_file)


def _parse_requirements(path):
  with open(os.path.join(here, path)) as f:
    return [
        line.rstrip()
        for line in f
        if not (line.isspace() or line.startswith('#'))
    ]


def _patch_workspace(workspace_content):
  """Change inclusion of the other WORKSPACEs in Tink to be absolute.

  Setuptools builds in a temporary folder, therefore the relative paths can not
  be resolved. Instead we use the http_archives during the build.

  Args:
    workspace_content: The original tink/python WORKSPACE.
  Returns:
    The workspace_content using http_archive for tink_base and tink_cc.
  """
  # This is run by pip from a temporary folder which breaks the WORKSPACE paths.
  # This replaces the paths with the latest http_archive.
  # In order to override this with a local WORKSPACE use the
  # TINK_PYTHON_SETUPTOOLS_OVERRIDE_BASE_PATH environment variable.

  if 'TINK_PYTHON_SETUPTOOLS_OVERRIDE_BASE_PATH' in os.environ:
    base_path = os.environ['TINK_PYTHON_SETUPTOOLS_OVERRIDE_BASE_PATH']
    workspace_content = re.sub(r'(?<="tink_base",\n    path = ").*(?=\n)',
                               base_path + '",  # Modified by setup.py',
                               workspace_content)
    workspace_content = re.sub(r'(?<="tink_cc",\n    path = ").*(?=\n)',
                               base_path + '/cc' + '",  # Modified by setup.py',
                               workspace_content)
  else:
    # If not base is specified use the latest version from GitHub
    # Add http_archive load
    workspace_lines = workspace_content.split('\n')
    http_archive_load = ('load("@bazel_tools//tools/build_defs/repo:http.bzl", '
                         '"http_archive")')
    workspace_content = '\n'.join([workspace_lines[0], http_archive_load] +
                                  workspace_lines[1:])

    base = ('local_repository(\n'
            '    name = "tink_base",\n'
            '    path = "..",\n'
            ')\n')

    cc = ('local_repository(\n'
          '    name = "tink_cc",\n'
          '    path = "../cc",\n'
          ')\n')

    base_patched = (
        '# Modified by setup.py\n'
        'http_archive(\n'
        '    name = "tink_base",\n'
        '    urls = ["https://github.com/google/tink/archive/master.zip"],\n'
        '    strip_prefix = "tink-master/",\n'
        ')\n')

    cc_patched = (
        '# Modified by setup.py\n'
        'http_archive(\n'
        '    name = "tink_cc",\n'
        '    urls = ["https://github.com/google/tink/archive/master.zip"],\n'
        '    strip_prefix = "tink-master/cc",\n'
        ')\n')

    workspace_content = workspace_content.replace(base, base_patched)
    workspace_content = workspace_content.replace(cc, cc_patched)
  return workspace_content


class BazelExtension(setuptools.Extension):
  """A C/C++ extension that is defined as a Bazel BUILD target."""

  def __init__(self, bazel_target, target_name=''):
    self.bazel_target = bazel_target
    self.relpath, self.target_name = (
        posixpath.relpath(bazel_target, '//').split(':'))
    if target_name:
      self.target_name = target_name
    ext_name = os.path.join(
        self.relpath.replace(posixpath.sep, os.path.sep), self.target_name)
    setuptools.Extension.__init__(self, ext_name, sources=[])


class BuildBazelExtension(build_ext.build_ext):
  """A command that runs Bazel to build a C/C++ extension."""

  def run(self):
    for ext in self.extensions:
      self.bazel_build(ext)
    build_ext.build_ext.run(self)

  def bazel_build(self, ext):
    # Change WORKSPACE to include tink_base and tink_cc from an archive
    with open('WORKSPACE', 'r') as f:
      workspace_contents = f.read()
    with open('WORKSPACE', 'w') as f:
      f.write(_patch_workspace(workspace_contents))

    if not os.path.exists(self.build_temp):
      os.makedirs(self.build_temp)

    # Ensure no artifacts from previous builds are reused (i.e. from builds
    # using a different Python version).
    bazel_clean_argv = [bazel, 'clean', '--expunge']
    self.spawn(bazel_clean_argv)

    bazel_argv = [
        bazel, 'build', ext.bazel_target,
        '--compilation_mode=' + ('dbg' if self.debug else 'opt'),
        '--incompatible_linkopts_to_linklibs'
        # TODO(https://github.com/bazelbuild/bazel/issues/9254): Remove linkopts
        # flag when issue is fixed.
    ]
    self.spawn(bazel_argv)
    ext_bazel_bin_path = os.path.join('bazel-bin', ext.relpath,
                                      ext.target_name + '.so')
    ext_dest_path = self.get_ext_fullpath(ext.name)
    ext_dest_dir = os.path.dirname(ext_dest_path)
    if not os.path.exists(ext_dest_dir):
      os.makedirs(ext_dest_dir)
    shutil.copyfile(ext_bazel_bin_path, ext_dest_path)


setuptools.setup(
    name='tink',
    version=_get_tink_version(),
    url='https://github.com/google/tink',
    description='A multi-language, cross-platform library that provides '
    'cryptographic APIs that are secure, easy to use correctly, '
    'and hard(er) to misuse.',
    author='Tink Developers',
    author_email='tink-users@googlegroups.com',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    # Contained modules and scripts.
    packages=setuptools.find_packages(),
    install_requires=_parse_requirements('requirements.txt'),
    cmdclass=dict(build_ext=BuildBazelExtension),
    ext_modules=[
        BazelExtension('//tink/cc/pybind:tink_bindings'),
    ],
    zip_safe=False,
    # PyPI package information.
    classifiers=[
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Topic :: Software Development :: Libraries',
    ],
    license='Apache 2.0',
    keywords='tink cryptography',
)
