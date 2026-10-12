# Building Splunk Connect for Docker from source

This document explains how to build the plugin package (`splunk-logging-plugin.tar.gz`), run the tests, and install a build on a Docker host that has no build tools.

The plugin is built with Go 1.9.2 and `dep`, inside Docker. You only need Docker and `make` on the build machine.

## Standard build (amd64 Linux host)

On an amd64 Linux machine that can reach `github.com` and `go.googlesource.com`:

```
$ make package
```

This builds the plugin image with the `Dockerfile`, exports its root filesystem to `splunk-logging-plugin/`, and creates `splunk-logging-plugin.tar.gz`. Both are ignored by git.

Note that `make` (the default `all` target) also runs `docker plugin create splunk/docker-logging-plugin:latest`. That replaces any plugin with that name on the build machine. To build a test version under a different tag, use `make PLUGIN_TAG=<tag>`.

## Cross-building for amd64 on an arm64 machine (for example Apple Silicon)

`make package` builds for the architecture of the machine it runs on. On an arm64 machine it produces an arm64 plugin, which does not run on amd64 servers. In addition, the `dep ensure` step in the `Dockerfile` fails when `go.googlesource.com` cannot be reached.

The steps below avoid both problems:

- dependencies are vendored once, fetching the `golang.org/x` packages from their GitHub mirrors;
- the binary is cross-compiled for amd64;
- the plugin image is assembled for amd64 with `docker buildx`.

Run all commands from the repository root. Docker must support the `linux/amd64` platform: Docker Desktop does this out of the box, and `docker buildx ls` should list it.

1. Vendor the dependencies pinned in `Gopkg.lock`:

   ```
   $ docker run --rm --platform linux/amd64 \
       -v "$PWD":/go/src/github.com/splunk/splunk-logging-plugin \
       -w /go/src/github.com/splunk/splunk-logging-plugin \
       golang:1.9.2 sh -c '
         git config --global url."https://github.com/golang/".insteadOf "https://go.googlesource.com/" &&
         go get -u github.com/golang/dep/cmd/dep &&
         dep ensure -vendor-only'
   ```

   This creates `vendor/`, which is ignored by git. `-vendor-only` installs exactly the versions in `Gopkg.lock` without re-solving them.

2. Cross-compile a static amd64 binary into a temporary directory:

   ```
   $ BUILD_DIR=$(mktemp -d)
   $ docker run --rm \
       -v "$PWD":/go/src/github.com/splunk/splunk-logging-plugin \
       -w /go/src/github.com/splunk/splunk-logging-plugin \
       -v "$BUILD_DIR":/out \
       golang:1.9.2 sh -c 'CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -installsuffix cgo -o /out/splunk-logging-plugin .'
   $ file "$BUILD_DIR/splunk-logging-plugin"   # ELF 64-bit LSB executable, x86-64, statically linked
   ```

3. Build the amd64 plugin image from that binary:

   ```
   $ cat > "$BUILD_DIR/Dockerfile" <<'EOF'
   FROM --platform=linux/amd64 alpine:3.7
   RUN apk --no-cache add ca-certificates
   COPY splunk-logging-plugin /bin/splunk-logging-plugin
   WORKDIR /bin/
   ENTRYPOINT [ "/bin/splunk-logging-plugin" ]
   EOF
   $ docker buildx build --platform linux/amd64 \
       -t splunk/docker-logging-plugin:rootfs --load \
       -f "$BUILD_DIR/Dockerfile" "$BUILD_DIR"
   ```

   The image tag must be `splunk/docker-logging-plugin:rootfs`, because that is what the `Makefile` exports in the next step.

4. Create the plugin package (no compilation happens in this step):

   ```
   $ DOCKER_DEFAULT_PLATFORM=linux/amd64 make clean rootfs zip
   $ file splunk-logging-plugin/rootfs/bin/splunk-logging-plugin   # must say x86-64
   ```

5. Optionally check that Docker accepts the package, then remove the test registration:

   ```
   $ docker plugin create splunk/docker-logging-plugin:build-check ./splunk-logging-plugin/
   $ docker plugin inspect splunk/docker-logging-plugin:build-check --format '{{.Name}} {{.Config.Entrypoint}}'
   $ docker plugin rm splunk/docker-logging-plugin:build-check
   ```

6. Clean up:

   ```
   $ rm -rf "$BUILD_DIR"   # keep vendor/ if you plan to rebuild or run the tests
   ```

### Troubleshooting

- `mkdir: ./splunk-logging-plugin: Not a directory` during `make rootfs`: a file named `splunk-logging-plugin` (for example a binary from an earlier build) exists in the repository root. Move it away; the `Makefile` needs that name for the output directory.
- `dep ensure` fails with `Failed to connect to go.googlesource.com`: use the `insteadOf` rewrite and `dep ensure -vendor-only` shown in step 1.
- The dep install script fails to download a release binary: install `dep` with `go get -u github.com/golang/dep/cmd/dep` as shown in step 1.

## Running the tests

The tests need the vendored dependencies (step 1 above). Then:

```
$ docker run --rm \
    -v "$PWD":/go/src/github.com/splunk/splunk-logging-plugin \
    -w /go/src/github.com/splunk/splunk-logging-plugin \
    golang:1.9.2 sh -c 'gofmt -l *.go && go vet . && go test -count=1 .'
```

`gofmt -l` lists the files that are not formatted. `message_processor.go` and `partial_message_buffer.go` are already listed on the current code; any other file in the output needs `gofmt -w`.

To run the tests with the race detector, use the amd64 image. Go 1.9 has no race detector on arm64, and under emulation the run takes up to a minute:

```
$ docker run --rm --platform linux/amd64 \
    -v "$PWD":/go/src/github.com/splunk/splunk-logging-plugin \
    -w /go/src/github.com/splunk/splunk-logging-plugin \
    golang:1.9.2 go test -count=1 -race .
```

The tests use a local mock of the HTTP Event Collector and need no Splunk instance. The Python functional tests in `test/` do need a running Splunk instance; see `test/README.md`.

## Installing a build on a host without build tools

Copy `splunk-logging-plugin.tar.gz` to the target host, then:

```
$ tar -xzf splunk-logging-plugin.tar.gz
$ docker plugin create splunk/docker-logging-plugin:<tag> splunk-logging-plugin/
$ docker plugin set splunk/docker-logging-plugin:<tag> LOG_LEVEL=info   # optional, see the advanced options in README.md
$ docker plugin enable splunk/docker-logging-plugin:<tag>
```

Use a dedicated tag (for example `:test`) to try a build without replacing the plugin your containers already use. Then start a test container with `--log-driver splunk/docker-logging-plugin:<tag>`.

Environment options can only be changed while the plugin is disabled. To change them later, or to replace the plugin with a newer build, first stop the containers that use it, then run `docker plugin disable`, and afterwards `docker plugin set` or `docker plugin rm` followed by `docker plugin create`.
