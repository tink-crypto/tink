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

import glob
import os
import posixpath
import shutil
import subprocess
import textwrap

import setuptools
from setuptools.command import build_ext
from setuptools.command import sdist


_PROJECT_BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def _get_tink_version():
  """Parses the version number from VERSION file."""
  with open(os.path.join(_PROJECT_BASE_DIR, 'VERSION')) as f:
    try:
      version_line = next(
          line for line in f if line.startswith('TINK_VERSION_LABEL')
      )
    except StopIteration as e:
      raise ValueError(
          f'Version not defined in {_PROJECT_BASE_DIR}/VERSION'
      ) from e
    else:
      return version_line.split(' = ')[-1].strip('\n \'"')


_TINK_VERSION = _get_tink_version()


def _get_bazel_command():
  """Finds the bazel command."""
  if shutil.which('bazelisk'):
    return 'bazelisk'
  elif shutil.which('bazel'):
    return 'bazel'
  raise FileNotFoundError(
      'Could not find bazel executable. Please install '
      'bazel to compile the Tink Python package.'
  )


def _get_protoc_command():
  """Finds the protoc command."""
  if 'PROTOC' in os.environ and os.path.exists(os.environ['PROTOC']):
    return os.environ['PROTOC']
  protoc_path = shutil.which('protoc')
  if protoc_path is None:
    raise FileNotFoundError(
        'Could not find protoc executable. Please install '
        'protoc to compile the Tink Python package.'
    )
  return protoc_path


def _generate_proto(protoc, source):
  """Invokes the Protocol Compiler to generate a _pb2.py."""

  if not os.path.exists(source):
    raise FileNotFoundError('Cannot find required file: {}'.format(source))

  output = source.replace('.proto', '_pb2.py')

  if os.path.exists(output) and os.path.getmtime(source) < os.path.getmtime(
      output
  ):
    # No need to regenerate if output is newer than source.
    return

  print('Generating {}...'.format(output))
  protoc_args = [protoc, '-I.', '--python_out=.', source]
  subprocess.run(args=protoc_args, check=True)


def _parse_requirements(filename):
  with open(os.path.join(_PROJECT_BASE_DIR, filename)) as f:
    return [
        line.rstrip()
        for line in f
        if not (line.isspace() or line.startswith('#'))
    ]


def _patch_workspace(workspace_file):
  """Update the Bazel workspace with valid repository references.

  When installing the sdist, e.g., with `pip install tink --no-binary` or
  `python3 -m pip install -v path/to/sdist.tar.gz`, setuptools unpacks the
  sdist in a temporary folder that contains only the python/ folder, and then
  builds it. As a consequence, relative local_repository paths that are set by
  default in python/WORKSPACE don't exist (or worst, they may exist by
  chance!).

  By default, the local_repository() rules will be replaced with http_archive()
  rules which contain URLs that point to an archive of the Tink GitHub
  repository as of the latest commit as of the master branch.

  This behavior can be modified via the following environment variables, in
  order of precedence:

    * TINK_PYTHON_SETUPTOOLS_OVERRIDE_BASE_PATH
        Instead of using http_archive() rules, update the local_repository()
        rules with the specified alternative local path. This allows for
        building using a local copy of the project (e.g. for testing).

    * TINK_PYTHON_SETUPTOOLS_TAGGED_VERSION
        Instead of providing a URL of an archive of the current master branch,
        instead link to an archive that correspond with the tagged version (e.g.
        for creating release artifacts).

  Args:
    workspace_file: The tink/python WORKSPACE.
  """

  with open(workspace_file, 'r') as f:
    workspace_content = f.read()

  if 'TINK_PYTHON_SETUPTOOLS_TAGGED_VERSION' in os.environ:
    tagged_version = os.environ['TINK_PYTHON_SETUPTOOLS_TAGGED_VERSION']
    archive_filename = 'v{}.zip'.format(tagged_version)
    archive_prefix = 'tink-{}'.format(tagged_version)
    workspace_content = _patch_with_http_archive(
        workspace_content, archive_filename, archive_prefix
    )
  else:
    workspace_content = _patch_with_http_archive(
        workspace_content, 'master.zip', 'tink-master'
    )

  with open(workspace_file, 'w') as f:
    f.write(workspace_content)


def _patch_with_http_archive(workspace_content, filename, prefix):
  """Replaces local_repository() rules with http_archive() rules."""

  workspace_lines = workspace_content.split('\n')
  http_archive_load = (
      'load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")'
  )

  if http_archive_load not in workspace_content:
    workspace_content = '\n'.join(
        [workspace_lines[0], http_archive_load] + workspace_lines[1:]
    )

  cc = textwrap.dedent("""\
      local_repository(
          name = "tink_cc",
          path = "../cc",
      )
      """)

  cc_patched = textwrap.dedent("""\
      # Modified by setup.py
      http_archive(
          name = "tink_cc",
          urls = ["https://github.com/google/tink/archive/{}"],
          strip_prefix = "{}/cc",
      )
      """.format(filename, prefix))

  return workspace_content.replace(cc, cc_patched)


class BazelExtension(setuptools.Extension):
  """A C/C++ extension that is defined as a Bazel BUILD target."""

  def __init__(self, bazel_target, target_name=''):
    self.bazel_target = bazel_target
    self.relpath, self.target_name = posixpath.relpath(
        bazel_target, '//'
    ).split(':')
    if target_name:
      self.target_name = target_name
    ext_name = os.path.join(
        self.relpath.replace(posixpath.sep, os.path.sep), self.target_name
    )
    setuptools.Extension.__init__(self, ext_name, sources=[])


class BuildBazelExtension(build_ext.build_ext):
  """A command that runs Bazel to build a C/C++ extension."""

  def __init__(self, dist):
    super(BuildBazelExtension, self).__init__(dist)
    self.bazel_command = _get_bazel_command()

  def run(self):
    for ext in self.extensions:
      self.bazel_build(ext)
    build_ext.build_ext.run(self)

  def bazel_build(self, ext):
    # Change WORKSPACE to include tink_cc from an archive
    _patch_workspace('WORKSPACE')

    if not os.path.exists(self.build_temp):
      os.makedirs(self.build_temp)

    # Ensure no artifacts from previous builds are reused (i.e. from builds
    # using a different Python version).
    bazel_clean_argv = [self.bazel_command, 'clean', '--expunge']
    self.spawn(bazel_clean_argv)

    bazel_argv = [
        self.bazel_command,
        'build',
        ext.bazel_target,
        '--compilation_mode=' + ('dbg' if self.debug else 'opt'),
    ]
    self.spawn(bazel_argv)
    ext_bazel_bin_path = os.path.join(
        'bazel-bin', ext.relpath, ext.target_name + '.so'
    )
    ext_dest_path = self.get_ext_fullpath(ext.name)
    ext_dest_dir = os.path.dirname(ext_dest_path)
    if not os.path.exists(ext_dest_dir):
      os.makedirs(ext_dest_dir)
    shutil.copyfile(ext_bazel_bin_path, ext_dest_path)


class SdistCmd(sdist.sdist):
  """A command that patches the workspace before creating an sdist."""

  def run(self):
    _patch_workspace('WORKSPACE')
    sdist.sdist.run(self)


def main():
  # Generate compiled protocol buffers.
  protoc_command = _get_protoc_command()
  for proto_file in glob.glob('tink/proto/*.proto'):
    _generate_proto(protoc_command, proto_file)

  gcpkms_extra_requirements = _parse_requirements('requirements_gcpkms.in')
  awskms_extra_requirements = _parse_requirements('requirements_awskms.in')
  hcvault_extra_requirements = _parse_requirements('requirements_hcvault.in')

  setuptools.setup(
      name='tink',
      version=_TINK_VERSION,
      url='https://github.com/google/tink',
      description=(
          'A multi-language, cross-platform library that provides '
          'cryptographic APIs that are secure, easy to use correctly, '
          'and hard(er) to misuse.'
      ),
      author='Tink Developers',
      author_email='tink-users@googlegroups.com',
      long_description=open('README.md').read(),
      long_description_content_type='text/markdown',
      # Contained modules and scripts.
      packages=setuptools.find_packages(),
      install_requires=_parse_requirements('requirements.in'),
      extras_require={
          'gcpkms': gcpkms_extra_requirements,
          'awskms': awskms_extra_requirements,
          'hcvault': hcvault_extra_requirements,
          'all': (
              gcpkms_extra_requirements
              + awskms_extra_requirements
              + hcvault_extra_requirements
          ),
      },
      cmdclass={
          'build_ext': BuildBazelExtension,
          'sdist': SdistCmd,
      },
      ext_modules=[
          BazelExtension('//tink/cc/pybind:tink_bindings'),
      ],
      zip_safe=False,
      # PyPI package information.
      classifiers=[
          'Programming Language :: Python',
          'Programming Language :: Python :: 3',
          'Programming Language :: Python :: 3.8',
          'Programming Language :: Python :: 3.9',
          'Programming Language :: Python :: 3.10',
          'Programming Language :: Python :: 3.11',
          'Topic :: Software Development :: Libraries',
      ],
      license='Apache 2.0',
      keywords='tink cryptography',
      python_requires='>=3.8',
  )


if __name__ == '__main__':
  main()
