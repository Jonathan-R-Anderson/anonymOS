# C catalogue runtime.
FROM debian:bookworm-slim@sha256:2ccc7e39b0a6f504d252f807da1fc4b5bcd838e83e4dec3e2f57b2a4a64e7214

RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*

# SOURCE_DATE_EPOCH and -frandom-seed remove the two things that make a C build
# non-reproducible: embedded timestamps, and symbol names derived from a random
# seed that differs per compilation.
ENV LC_ALL=C LANG=C TZ=UTC SOURCE_DATE_EPOCH=0

RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin compute
USER 10001:10001
WORKDIR /work

COPY --chown=10001:10001 run.sh /usr/local/bin/run
ENTRYPOINT ["/usr/local/bin/run"]
