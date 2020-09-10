# Phishbeat

Welcome to Phishbeat, a lightweight shipper, designed to monitor certificate transparency logs for squatted domains (phishing domains).

Ensure that this folder is at the following location:
`${GOPATH}/src/github.com/stric-co/phishbeat`


## Getting Started with Phishbeat

### Requirements

* [Golang](https://golang.org/dl/) 1.7

### Elastic Detections
In the `_detections` folder, you will find two detection rules for the Elastic SIEM.

### Machine Learning
In the `_ml` folder, you'll find some Elastic Machine Learning jobs to compliment Phishbeat.

### Init Project
To get running with Phishbeat and also install the
dependencies, run the following command:

```
make setup
```

It will create a clean git history for each major step. Note that you can always rewrite the history if you wish before pushing your changes.

To push Phishbeat in the git repository, run the following commands:

```
git remote set-url origin https://github.com/stric-co/phishbeat
git push origin master
```

For further development, check out the [beat developer guide](https://www.elastic.co/guide/en/beats/libbeat/current/new-beat.html).

### Build

To build the binary for Phishbeat run the command below. This will generate a binary
in the same directory with the name phishbeat.

```
make
```


### Run

To run Phishbeat with debugging output enabled, run:

```
./phishbeat -c phishbeat.yml -e -d "*"
```


### Test

To test Phishbeat, run the following command:

```
make testsuite
```

alternatively:
```
make unit-tests
make system-tests
make integration-tests
make coverage-report
```

The test coverage is reported in the folder `./build/coverage/`

### Update

Each beat has a template for the mapping in elasticsearch and a documentation for the fields
which is automatically generated based on `fields.yml` by running the following command.

```
make update
```


### Cleanup

To clean Phishbeat source code, run the following command:

```
make fmt
```

To clean up the build directory and generated artifacts, run:

```
make clean
```


### Clone

To clone Phishbeat from the git repository, run the following commands:

```
mkdir -p ${GOPATH}/src/github.com/stric-co/phishbeat
git clone https://github.com/stric-co/phishbeat ${GOPATH}/src/github.com/stric-co/phishbeat
```


For further development, check out the [beat developer guide](https://www.elastic.co/guide/en/beats/libbeat/current/new-beat.html).


## Packaging

The beat frameworks provides tools to crosscompile and package your beat for different platforms. This requires [docker](https://www.docker.com/) and vendoring as described above. To build packages of your beat, run the following command:

```
make release
```

This will fetch and create all images required for the build process. The whole process to finish can take several minutes.


### Credit
Credit goes to:
- [DNSMorph](https://github.com/netevert/dnsmorph) for the logic around the generation of squatted domains.
