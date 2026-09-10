/*
 * Shared, modular logging setup for all Maniwani Node services.
 *
 * Requiring this module once (at the very top of a service's entrypoint) tees
 * every console.{log,info,warn,error,debug} call to a per-service log file
 * inside the single shared log folder (a Docker volume mounted at
 * /var/log/maniwani), while still writing to the original stdout/stderr so
 * `docker logs` keeps working. Lines are tagged with the service name so it is
 * always obvious which container they came from.
 *
 * Zero dependencies; identical across every Node build context.
 *
 * Environment variables:
 *   LOG_DIR           Shared log folder. Default: /var/log/maniwani
 *   SERVICE_NAME      Identifies the container (subdir / file name).
 *   LOG_MAX_BYTES     Rotate after this many bytes. Default: 10 MiB.
 *   LOG_TO_STDOUT     Set falsey to disable echoing to the console.
 */

'use strict';

const fs = require('fs');
const path = require('path');

const DEFAULT_LOG_DIR = '/var/log/maniwani';

function envFlag(name, fallback) {
    const value = process.env[name];
    if (value === undefined) {
        return fallback;
    }
    const normalized = String(value).trim().toLowerCase();
    return ['', '0', 'false', 'no', 'off'].indexOf(normalized) === -1;
}

function intEnv(name, fallback) {
    const parsed = parseInt(process.env[name], 10);
    return Number.isFinite(parsed) ? parsed : fallback;
}

function serviceName() {
    return process.env.SERVICE_NAME || process.env.HOSTNAME || 'app';
}

function timestamp() {
    return new Date().toISOString();
}

function openLogStream(service) {
    const logDir = process.env.LOG_DIR || DEFAULT_LOG_DIR;
    const serviceDir = path.join(logDir, service);
    const logFile = path.join(serviceDir, service + '.log');
    const maxBytes = intEnv('LOG_MAX_BYTES', 10 * 1024 * 1024);

    fs.mkdirSync(serviceDir, { recursive: true });

    // Lightweight size-based rotation: keep a single previous file.
    try {
        const stats = fs.statSync(logFile);
        if (stats.size >= maxBytes) {
            fs.renameSync(logFile, logFile + '.1');
        }
    } catch (err) {
        // File does not exist yet — nothing to rotate.
    }

    return fs.createWriteStream(logFile, { flags: 'a' });
}

function install() {
    const service = serviceName();
    const echo = envFlag('LOG_TO_STDOUT', true);

    let stream = null;
    try {
        stream = openLogStream(service);
        stream.on('error', function () {
            stream = null; // Stop trying to write if the volume goes away.
        });
    } catch (err) {
        // Shared folder not writable — fall back to console only.
        if (echo) {
            // eslint-disable-next-line no-console
            console.error(
                '[' + service + '] file logging disabled: ' + (err && err.message)
            );
        }
    }

    const levels = {
        log: 'INFO',
        info: 'INFO',
        warn: 'WARN',
        error: 'ERROR',
        debug: 'DEBUG',
    };

    const util = require('util');
    const original = {};

    Object.keys(levels).forEach(function (method) {
        original[method] = console[method]
            ? console[method].bind(console)
            : console.log.bind(console);

        console[method] = function () {
            const message = util.format.apply(util, arguments);
            if (echo) {
                original[method](message);
            }
            if (stream) {
                try {
                    stream.write(
                        timestamp() +
                            ' ' +
                            levels[method] +
                            ' [' +
                            service +
                            '] ' +
                            message +
                            '\n'
                    );
                } catch (err) {
                    /* never let logging crash the app */
                }
            }
        };
    });

    console.log('logging initialised for service "' + service + '"');
}

install();

module.exports = { serviceName: serviceName };
