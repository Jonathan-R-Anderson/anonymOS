# deps/decoy — the deterministic decoy activity generator engine (roadmap/INSTALLER.md §G).
# Portable C, no libc dependency in the engine itself; the test links libm for stats.
SELF := $(abspath .)
BLD  := $(SELF)/build
CC   ?= clang

.PHONY: test render h2 g2 clean
test: | $(BLD)
	$(CC) -O2 -I$(SELF) $(SELF)/decoy.c $(SELF)/test/decoy_test.c -lm -o $(BLD)/decoy-test
	$(BLD)/decoy-test

# §G G3.3 — render decoy events into a realistic, deterministic syslog (+ a visible sample)
render: | $(BLD)
	$(CC) -O2 -I$(SELF) $(SELF)/decoy.c $(SELF)/decoy_render.c $(SELF)/test/render_test.c -o $(BLD)/decoy-render
	$(BLD)/decoy-render

# §G2.2 — the honey-hashed, typo-tolerant decoy boot matcher.
g2: | $(BLD)
	$(CC) -O2 -I$(SELF) -I$(SELF)/g2 $(SELF)/decoy.c $(SELF)/g2/dm.c $(SELF)/test/dm_test.c -o $(BLD)/decoy-dm
	$(BLD)/decoy-dm

# §H2 — the Linux fake-log generator: write deterministic /var/log history; self-test it.
h2: | $(BLD)
	$(CC) -O2 -I$(SELF) $(SELF)/decoy.c $(SELF)/decoy_render.c $(SELF)/h2/fakelogd.c -o $(BLD)/fakelogd
	@rm -rf $(BLD)/h2a $(BLD)/h2b $(BLD)/h2c; mkdir -p $(BLD)/h2a $(BLD)/h2b $(BLD)/h2c
	@$(BLD)/fakelogd decoy-password  --root $(BLD)/h2a --start-day 100 --days 14
	@$(BLD)/fakelogd decoy-password  --root $(BLD)/h2b --start-day 100 --days 14
	@$(BLD)/fakelogd hidden-password --root $(BLD)/h2c --start-day 100 --days 14
	@echo "--- §H2 self-test ---"
	@diff -rq $(BLD)/h2a $(BLD)/h2b >/dev/null && echo "  [PASS] same password -> byte-identical /var/log" || echo "  [FAIL] not deterministic"
	@! diff -rq $(BLD)/h2a/var/log/syslog $(BLD)/h2c/var/log/syslog >/dev/null && echo "  [PASS] different password -> different /var/log" || echo "  [FAIL] password-insensitive"
	@grep -qE "sshd|sudo" $(BLD)/h2a/var/log/auth.log && echo "  [PASS] auth events routed to auth.log" || echo "  [FAIL] auth.log routing"
	@grep -qE "systemd|CRON|NetworkManager" $(BLD)/h2a/var/log/syslog && echo "  [PASS] system events routed to syslog" || echo "  [FAIL] syslog routing"
	@! grep -qE "Accepted publickey|session opened|authentication failure|COMMAND=" $(BLD)/h2a/var/log/syslog && echo "  [PASS] auth-event content NOT leaked into syslog" || echo "  [FAIL] auth content leaked to syslog"
	@echo "  auth.log sample:"; head -3 $(BLD)/h2a/var/log/auth.log | sed 's/^/    /'

$(BLD):
	@mkdir -p $@

clean:
	rm -rf $(BLD)
