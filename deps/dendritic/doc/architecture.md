# Architecture

The project is organized around three runtime roles:

## Core Web App

- `app.py`, `blueprints/`, `model/`, `templates/`, `static/`
- `services/aggregator_sync/`

The web app owns user-facing state, rendering, moderation, and source-to-board import. The sync logic now lives under `services/aggregator_sync/` instead of one root-level script:

- `config.py`: sync constants and limits
- `state.py`: background-loop status and leader-lock handling
- `scraper_db.py`: read-only scraper SQLite access
- `text.py`: pure text translation and source-body normalization
- `media.py`: local/external media mirroring and thread deletion helpers
- `api.py`: board/source orchestration entrypoints

`aggregator_sync.py` is now a compatibility shim so older imports still resolve while the real implementation lives in the package.

## Scraper Workers

- `board_aggregators/fourchan_aggregator_plus/`

All chan scrapers share one image and differ only by environment. The scraper code is split into a package:

- `scraper_app/config.py`: environment parsing and site-specific constants
- `scraper_app/runtime.py`: Flask app, shared mutable state, Tor proxy helpers
- `scraper_app/storage.py`: SQLite schema, source persistence, failure bookkeeping
- `scraper_app/crawler.py`: fetch, challenge, parse, download, and crawl loop logic
- `scraper_app/routes.py`: HTTP routes for admin control, search, thread view, and status

`board_aggregators/fourchan_aggregator_plus/app.py` is now only the process entrypoint.

## Infrastructure Containers

- `postgres`: primary relational store
- `redis`: cache/pubsub
- `minio`: attachment storage
- `nginx`: public edge/proxy
- `maniwani`: main application
- `maniwani-frontend`: frontend asset build/runtime
- `fourchan-aggregator`, `eightchan-aggregator`, `sevenchan-aggregator`: scraper workers

## Compose Layout

The root `docker-compose.yml` groups services by role and uses shared anchors for scraper defaults. Site-specific services only declare what differs:

- site identity
- DB filename
- base URL / path style
- board bootstrap list
- 8chan-specific direct HTTP and thread-failure settings

That keeps the deployment topology readable without copying the same scraper settings across multiple services.
