FROM python:3.11-slim

# node for the JavaScript judge. No compilers, no curl, no git: the smaller the
# image, the less there is for submitted code to reach for.
RUN apt-get update \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir flask==3.0.3 gunicorn==22.0.0

WORKDIR /app
COPY runner.py /app/runner.py

# Unprivileged. The manifest also sets runAsNonRoot, a read-only root
# filesystem and allowPrivilegeEscalation:false; this is the last line of that,
# not the only one.
RUN useradd --system --uid 10001 --home /tmp --shell /usr/sbin/nologin runner
USER 10001

# Build-time selftest: prove containment works before the image can ship.
# A build that cannot kill an infinite loop or refuse a fork bomb is a build
# that must not reach a node.
RUN python -c "\
import runner; \
ok = runner.run_once('python', 'print(1+1)'); \
assert ok['ok'] and ok['stdout'].strip() == '2', ok; \
loop = runner.run_once('python', 'while True: pass'); \
assert loop['ok'] and (loop['timed_out'] or loop['exit_code'] != 0), loop; \
mem = runner.run_once('python', 'x = bytearray(10**10)'); \
assert mem['ok'] and mem['exit_code'] != 0, mem; \
print('containment selftest OK')"

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health',timeout=4).status==200 else 1)"

# Threads, not processes: each run already forks a child, and gunicorn workers
# would multiply the memory ceiling by the worker count.
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "2", "--threads", "4", \
     "--timeout", "60", "--access-logfile", "-", "runner:app"]
