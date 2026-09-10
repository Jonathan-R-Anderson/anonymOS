FROM ubuntu:20.04 AS dev
WORKDIR /maniwani
ENV DEBIAN_FRONTEND=noninteractive
# backend dependencies/frontend depndencies/uwsgi, python and associated plugins
RUN apt-get update && apt-get -y --no-install-recommends install python3 python3-pip \
	pipenv uwsgi-core uwsgi-plugin-python3 uwsgi-plugin-gevent-python3 python3-gevent curl && \
	curl -fsSL https://deb.nodesource.com/setup_18.x | bash - && \
	apt-get install -y nodejs && \
	node --version && npm --version
# install static build of ffmpeg and compress with upx
COPY backend/build-helpers/ffmpeg_bootstrap.py /maniwani/build-helpers/
WORKDIR /maniwani/build-helpers
RUN python3 ffmpeg_bootstrap.py && apt-get -y install upx-ucl && \
	chmod +w ../ffmpeg/ffmpeg && \
	upx -9 ../ffmpeg/ffmpeg && apt-get autoremove -y upx-ucl && \
	rm -rf /var/lib/apt/lists/*
WORKDIR /maniwani
COPY backend/Pipfile /maniwani
COPY backend/Pipfile.lock /maniwani
# `psycogreen` 1.0.2 ships as an sdist and its build step breaks with the
# transient setuptools/packaging combination pulled in by pipenv on Ubuntu 20.04.
# Build a wheel ahead of time with a compatible toolchain and let pip reuse it.
RUN python3 -m pip install --no-cache-dir --upgrade "setuptools<71" "packaging>=22" wheel && \
	mkdir -p /tmp/wheels && \
	python3 -m pip wheel --no-cache-dir --no-build-isolation --wheel-dir /tmp/wheels psycogreen==1.0.2
# Keep gevent/greenlet on the distro pair installed above. The lockfile's
# ancient gevent pin can resolve to a pip-installed ABI mismatch with the
# newer greenlet wheel, which breaks import during bootstrap.
RUN PIP_FIND_LINKS=/tmp/wheels pipenv install --system --deploy && \
	python3 -m pip uninstall -y gevent greenlet && \
	rm -rf /tmp/wheels
# `cryptography` backs the coordinator content-encryption keys (secp256k1 BIP32 +
# ECIES). It is installed here rather than via the Pipfile so the pinned lock's
# --deploy hash need not be regenerated; a manylinux wheel is used, no Rust build.
RUN python3 -m pip install --no-cache-dir "cryptography>=41,<44"
# `pypdf` strips the document-information dictionary from evidence PDFs
# (services/report_evidence.py). Without it a PDF attachment is REFUSED rather
# than stored unscrubbed, because a PDF carries the author, the producing
# application and often the full local path of the machine that made it.
#
# Installed here for the same reason as cryptography above, and NOT via the
# Pipfile: `pipenv install --deploy` fails outright when Pipfile and
# Pipfile.lock disagree, so adding a line to the Pipfile without regenerating
# the lock does not produce a missing dependency -- it produces a build that
# stops at this step. Pure Python, no wheel or toolchain concerns.
RUN python3 -m pip install --no-cache-dir "pypdf>=4,<6"
# `eth-account` signs the Treasury.releaseOrder transaction that delivers a
# purchase (services/token_delivery.py). Installed here for the same reason as
# cryptography above: outside the Pipfile so the pinned lock's --deploy hash
# need not be regenerated.
#
# It was listed in requirements.txt, which this image DOES NOT READ — the build
# installs from Pipfile.lock via pipenv. So the dependency looked declared and
# was absent, and automatic delivery reported itself configured while having no
# way to sign anything. requirements.txt is not the manifest for this image.
# Pinned BELOW 0.11 deliberately. From 0.11 eth-account depends on `ckzg`, which
# has no wheel for this image's Python 3.8 and builds from source — and the
# build needs `make`, which is not installed here. The failure is a compiler
# error deep in a pip log, not a resolver message, so it reads as unrelated.
#
# ckzg exists for EIP-4844 blob transactions. Nothing here sends one: this signs
# a plain type-2 call to Treasury.releaseOrder. 0.10 does that identically and
# pulls no build toolchain.
RUN python3 -m pip install --no-cache-dir "eth-account>=0.10,<0.11"
# point MANIWANI_CFG to the devmode config file
ENV MANIWANI_CFG=./deploy-configs/devmode.cfg
# build static frontend files
COPY backend/package.json /maniwani
COPY backend/package-lock.json /maniwani
COPY backend/Gulpfile.js /maniwani
COPY backend/scss /maniwani/scss
# Scratch is vendored from node_modules at BUILD time, not committed. The
# prebuilt bundle is 86 MB — 17 MB of application and 66 MB of media library
# (sprites, costumes, sounds) — and this repo already keeps large vendored
# artifacts out of git for exactly that reason (see storage-client/dist).
#
# It lands in static/ so it is served like every other asset, and node_modules
# is removed in the same layer so the 677 MB dependency tree never reaches the
# image.
RUN npm install \
 && npm run gulp \
 && mkdir -p /maniwani/static/scratch \
 && cp -r node_modules/scratch-gui/dist/. /maniwani/static/scratch/ \
 && cp node_modules/react/umd/react.production.min.js /maniwani/static/scratch/ \
 && cp node_modules/react-dom/umd/react-dom.production.min.js /maniwani/static/scratch/ \
 && rm -f /maniwani/static/scratch/*.map \
 && rm -rf node_modules
# build react render sidecar
WORKDIR /maniwani-frontend
COPY frontend/package.json /maniwani-frontend
COPY frontend/package-lock.json /maniwani-frontend
RUN npm install
COPY frontend/Loughran-McDonald_MasterDictionary_1993-2025.csv /maniwani-frontend/
COPY frontend/src /maniwani-frontend/src
COPY frontend/build-helpers /maniwani-frontend/build-helpers
COPY frontend/Gulpfile.js /maniwani-frontend
RUN npm run gulp
RUN cp -r build/* /maniwani-frontend/
COPY frontend/devmode-entrypoint.sh /maniwani-frontend
# TODO: how do we do this when running/deploying without docker?
RUN mkdir -p /maniwani/static/js
RUN cp /maniwani-frontend/build/client-bundle/*.js /maniwani/static/js/
RUN cp /maniwani-frontend/node_modules/gun/gun.js /maniwani/static/js/gun.js
# copy source files over
WORKDIR /maniwani
COPY backend/migrations /maniwani/migrations
COPY backend/*.py /maniwani/
COPY backend/blueprints /maniwani/blueprints
COPY backend/captcha /maniwani/captcha
COPY backend/anime-captcha /maniwani/anime-captcha
COPY backend/build-helpers /maniwani/build-helpers
COPY deploy-configs /maniwani/deploy-configs
COPY backend/model /maniwani/model
COPY backend/services /maniwani/services
# Maintenance/one-off CLIs. Previously omitted, so /maniwani/scripts did not exist
# in the image and nothing under backend/scripts/ could be run in the container.
COPY backend/scripts /maniwani/scripts
COPY backend/resources /maniwani/resources
# Static reference data shipped with the app (arcade question banks). This
# Dockerfile enumerates directories rather than copying backend/ wholesale, so
# a new data directory is invisible until it is named here -- the arcade
# rendered "the question bank isn't installed" for exactly this reason.
COPY backend/data /maniwani/data
COPY backend/static /maniwani/static
COPY backend/templates /maniwani/templates
# Fetch the CC0 IP->country database + Twemoji flag font for the board country
# flag feature (fail-soft: a download problem just leaves flags dormant).
RUN python3 build-helpers/geoip_bootstrap.py || true
COPY backend/docker-entrypoint.sh ./docker-entrypoint.sh
# bootstrap dev image
RUN python3 bootstrap.py
EXPOSE 5000

ENTRYPOINT ["sh", "./docker-entrypoint.sh", "devmode"]

FROM dev AS prod
WORKDIR /maniwani
# clean up dev image bootstrapping
RUN rm -f ./deploy-configs/test.db
RUN rm -rf uploads && mkdir -p uploads/attachments uploads/thumbs
RUN apt-get -y autoremove nodejs
ENV MANIWANI_CFG=./deploy-configs/maniwani.cfg
# chown and switch users for security purposes
RUN adduser --disabled-login maniwani
RUN chown -R maniwani:maniwani ./
# Shared log folder (mounted as a Docker volume at runtime). Created world
# writable so the non-root maniwani user can always write its log subdir.
RUN mkdir -p /var/log/maniwani && chown maniwani:maniwani /var/log/maniwani && chmod 0777 /var/log/maniwani
USER maniwani

# expose uWSGI
EXPOSE 3031
# expose internal plain HTTP listener for health checks and sidecars
EXPOSE 3032
ENTRYPOINT ["sh", "./docker-entrypoint.sh"]
