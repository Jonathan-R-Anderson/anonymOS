# Python catalogue runtime.
#
# Pinned to a digest rather than a tag: `python:3.12-slim` moves, and two nodes
# pulling it a week apart would run different interpreters and produce different
# output — which M5 would report as a disagreement rather than as drift.
FROM python:3.12-slim@sha256:2be8daddbb82756f7d1f2c7ece706aadcb284bf6ab6d769ea695cc3ed6016743

# Determinism. Each of these changes program output if left at its default:
# hash randomisation reorders dict iteration, locale changes sorting and number
# formatting, and timezone changes every date a program prints.
ENV PYTHONHASHSEED=0 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    LC_ALL=C \
    LANG=C \
    TZ=UTC \
    SOURCE_DATE_EPOCH=0 \
    OMP_NUM_THREADS=1 \
    MKL_NUM_THREADS=1

# Unprivileged. A submitted program has no reason to be root, and being root in
# a container is one CVE away from being root outside it.
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin compute
USER 10001:10001
WORKDIR /work

COPY --chown=10001:10001 run.sh /usr/local/bin/run
ENTRYPOINT ["/usr/local/bin/run"]
