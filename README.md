Janus: SSH Agent with extension support
=======================================

Getting started
---------------

In order to be able to develop on this project and run the various examples you
need to have the following tool installed in your environment:

- [git](https://git-scm.com/)
- [go toolchain](https://golang.org/doc/install), starting from version 1.11
as the project is using the newly introduced
[modules feature](https://github.com/golang/go/wiki/Modules).
- [make](https://www.gnu.org/software/make/)

Build and run
--------------

You can run a simple development server by issuing the following commands:

- clone this repository: `git clone github.com/IxDay/janus`
- build the binary: `make`
- define an environment variable: `export SSH_AUTH_SOCK="$(pwd)/agent.sock"`
- run the binary: `./janus`

Alternatively, once the repository is cloned you can just type `make run` to 
launch the binary.