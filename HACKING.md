# Hacking in the K2 Crypto Library

Copyright 2014 Google. Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

## Getting a copy of the source

1. Sign up at [Github](http://github.com).
2. (Optional) Generate and upload SSH keys (using
[these](https://help.github.com/articles/generating-ssh-keys) instructions).

On github, click on the account settings icon (top right), then “SSH keys” in
the menu (left), then on “Add an SSH Key” (top right).

Name the key whatever you want, and paste your id_rsa.pub file into the text
field.

3. [Fork](https://help.github.com/articles/fork-a-repo) your own copy of the
repo. 
** Also read
[Using Pull Requests](https://help.github.com/articles/using-pull-requests)

4.  Make a clone of the forked repo,
> git clone git@github.com:<your user name>/K2.git

5. Add the upstream repo
> git remote add upstream https://github.com/google/K2.git
> git fetch upstream

## General instructions about developing in K2

1. Follow the language specific guidelines (see the HACKING.md file in that

2. Include unit tests for all your changes. What makes a good unit test? Read
[The Art of Unit Testing by Roy Osherove](http://www.manning.com/osherove/)
or just Google "How to write a good unit test".

3. Be decriptive in your commit message - and remember, these messages are part
of the public record, so keep them polite and inoffensive.

4. Build your code in small, reviewable, testable chunks.  Merge frequently.

5. All files must start with the following copyright (adjust the year when you
touch a file that is out of date) - commented using the language-appropriate
commenting style.

## Protocol buffers

You must install version 2.5 of the
(protocol buffers tools)[https://developers.google.com/protocol-buffers/] to
build K2.  Earlier versions will not work.  Binaries are available for windows.
For other OSes, download the source, run 'configure' and 'make' and then put
the protoc binary on your path.

## Language specific HACKING.md files

To keep going, read the langauge specific HACKING.md files.

## K2 Specific Rules

1. Nothing gets merged into the master branch of the main repo unless all
automated tests pass.

2. Once a proto file is established by being included in a release, or by
having the line

> DO NOT EDIT - THIS PROTO FILE IS LOCKED. MAKE CHANGES IN A NEW FILE.

3. No binaries or sources from other projects should be included in the main
repo. Build systems should either download them art build time, or we will
require that developers download them separately.

## Porting K2 to other languages

You want to port K2 to another language? Fantastic! We really want people to do
that - thanks!

Early on we had a long 
[discusssion](https://groups.google.com/forum/#!topic/k2-crypto-dev/L8hhZfJdoa0)
about how to best support that. We decided that the core langauges would be
Java, CPP, and Python, because those were the languages that Google needed this
to be in.  And only those core languages would be required to be in the main
repository. But we wanted to make sure that we made it easy for people to
support other languages, so we adupted the rules above in order to make it
simple for maintainers of K2 in other languages to work in their own repositories.

So please join the k2-crypto-dev mailing list, and let us know about your
project.

You can also merge your port into the main repo, if you choose to, and:
* your port is passing the interoperability test;
* and it is mature complete enough that a vote on the k2-crypto-dev mailing list
approves the merge.

