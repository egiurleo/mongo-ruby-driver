# Evergreen Tests

This directory contains configuration and scripts used to run the driver's
test suite in Evergreen, MongoDB's continuous integration system.

## Running On Docker

It is possible to run the test suite on Docker. This executes all of the
shell scripts as if they were running in the Evergreen environment.

Use the following command:

    ./.evergreen/run-on-docker -d debian92 RVM_RUBY=ruby-2.7

The `-d` option specifies the distro to use. This must be one of the
Evergreen-recognized distros. The arguments are the environment variables as
would be set by Evergreen configuration (i.e. `config.yml` in this directory).
All arguments are optional.

By default the entire test suite is run (using mlaunch to launch the server);
to specify another script, use `-s` option:

    ./.evergreen/run-on-docker -s .evergreen/run-enterprise-auth-tests.sh