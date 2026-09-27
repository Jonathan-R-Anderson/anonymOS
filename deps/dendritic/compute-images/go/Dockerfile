# Go catalogue runtime.
FROM golang:1.23-bookworm@sha256:2fe82a3f3e006b4f2a316c6a21f62b66e1de5d6a5b8a5ee1e0f8e2be13d4ba0f

# -trimpath removes absolute build paths from the binary, and GOFLAGS pins it
# for every invocation: two nodes with different working directories would
# otherwise produce different binaries from identical source.
ENV LC_ALL=C LANG=C TZ=UTC SOURCE_DATE_EPOCH=0 \
    GOFLAGS=-trimpath CGO_ENABLED=0 GOMAXPROCS=1

RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin compute
USER 10001:10001
WORKDIR /work
ENV GOCACHE=/tmp/gocache GOPATH=/tmp/gopath

COPY --chown=10001:10001 run.sh /usr/local/bin/run
ENTRYPOINT ["/usr/local/bin/run"]
