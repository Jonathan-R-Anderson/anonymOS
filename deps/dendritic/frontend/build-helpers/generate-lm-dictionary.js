const fs = require('fs');
const path = require('path');

const SOURCE_FILENAME = 'Loughran-McDonald_MasterDictionary_1993-2025.csv';
const OUTPUT_FILENAME = 'src/semantic/loughranMcDonaldDictionary.js';
// Numeric seed JSON consumed by the backend (in-memory LM anchor lookup +
// scripts/seed_word_sentiment.py). Emitted into the backend tree so the same
// weight math is not re-implemented in Python.
const SEED_OUTPUT_FILENAME = path.join('..', 'backend', 'data', 'loughran_mcdonald_seed.json');
// Must stay in sync with SENTIMENT_CATEGORY_WEIGHTS in src/semantic/threadSemantic.js.
const SENTIMENT_CATEGORY_WEIGHTS = {
    positive: 0.92,
    negative: -0.96,
    uncertainty: -0.34,
    litigious: -0.22,
    constraining: -0.3,
    strongModal: 0.08,
    weakModal: -0.1
};
const CATEGORY_COLUMNS = [
    { column: 'Negative', key: 'negative' },
    { column: 'Positive', key: 'positive' },
    { column: 'Uncertainty', key: 'uncertainty' },
    { column: 'Litigious', key: 'litigious' },
    { column: 'Strong_Modal', key: 'strongModal' },
    { column: 'Weak_Modal', key: 'weakModal' },
    { column: 'Constraining', key: 'constraining' }
];

function parseCsvLine(line) {
    const values = [];
    let current = '';
    let inQuotes = false;
    for (let index = 0; index < line.length; index += 1) {
        const character = line.charAt(index);
        if (character === '"') {
            if (inQuotes && line.charAt(index + 1) === '"') {
                current += '"';
                index += 1;
            } else {
                inQuotes = !inQuotes;
            }
            continue;
        }
        if (character === ',' && !inQuotes) {
            values.push(current);
            current = '';
            continue;
        }
        current += character;
    }
    values.push(current);
    return values;
}

function normalizeWord(value) {
    return String(value || '')
        .trim()
        .toLowerCase()
        .replace(/[^a-z0-9']/g, '')
        .replace(/^'+|'+$/g, '')
        .replace(/'/g, '');
}

function resolveSourcePath(baseDir) {
    const candidates = [
        path.resolve(baseDir, '..', SOURCE_FILENAME),
        path.resolve(baseDir, SOURCE_FILENAME)
    ];
    for (const candidate of candidates) {
        if (fs.existsSync(candidate)) {
            return candidate;
        }
    }
    throw new Error(
        'Could not find ' + SOURCE_FILENAME + ' next to the frontend build or repo root.'
    );
}

function buildDictionary(sourcePath) {
    const csv = fs.readFileSync(sourcePath, 'utf8').trim();
    const lines = csv.split(/\r?\n/);
    if (!lines.length) {
        throw new Error('The Loughran-McDonald CSV is empty.');
    }
    const header = parseCsvLine(lines[0]);
    const columnIndexes = {};
    header.forEach(function (name, index) {
        columnIndexes[name] = index;
    });
    const dictionary = {};

    lines.slice(1).forEach(function (line) {
        if (!line) {
            return;
        }
        const fields = parseCsvLine(line);
        const normalizedWord = normalizeWord(fields[columnIndexes.Word]);
        if (!normalizedWord) {
            return;
        }
        const categories = CATEGORY_COLUMNS.reduce(function (matched, definition) {
            const rawValue = fields[columnIndexes[definition.column]];
            if (Number(rawValue) > 0) {
                matched.push(definition.key);
            }
            return matched;
        }, []);
        if (!categories.length) {
            return;
        }
        dictionary[normalizedWord] = categories;
    });
    return dictionary;
}

function clamp(value, min, max) {
    return Math.max(min, Math.min(max, value));
}

// Port of stemToken() in src/semantic/threadSemantic.js (fallback lookup key).
function stemToken(token) {
    let normalized = token;
    if (normalized.length > 5 && normalized.endsWith('ies')) {
        normalized = normalized.slice(0, -3) + 'y';
    } else if (normalized.length > 5 && normalized.endsWith('ing')) {
        normalized = normalized.slice(0, -3);
    } else if (normalized.length > 4 && normalized.endsWith('ed')) {
        normalized = normalized.slice(0, -2);
    } else if (normalized.length > 4 && normalized.endsWith('ly')) {
        normalized = normalized.slice(0, -2);
    } else if (normalized.length > 4 && normalized.endsWith('es')) {
        normalized = normalized.slice(0, -2);
    } else if (
        normalized.length > 3 &&
        normalized.endsWith('s') &&
        !normalized.endsWith('ss') &&
        !normalized.endsWith('us') &&
        !normalized.endsWith('ous') &&
        !normalized.endsWith('is')
    ) {
        normalized = normalized.slice(0, -1);
    }
    return normalized;
}

// Mirrors the isolated-token computation in buildSentimentTokens (score in
// [-1, 1], magnitude in [0, 1.6]).
function scoreForCategories(categories) {
    let valence = categories.reduce(function (total, category) {
        return total + (SENTIMENT_CATEGORY_WEIGHTS[category] || 0);
    }, 0);
    valence = clamp(valence, -1.2, 1.2);
    const score = clamp(valence, -1, 1);
    const magnitude = clamp(Math.max(Math.abs(valence), categories.length / 2.9), 0, 1.6);
    return { score: score, magnitude: magnitude };
}

function buildSeed(dictionary) {
    const seed = {};
    Object.keys(dictionary).forEach(function (word) {
        const categories = dictionary[word];
        const scored = scoreForCategories(categories);
        seed[word] = {
            stem: stemToken(word),
            score: scored.score,
            magnitude: scored.magnitude,
            categories: categories
        };
    });
    return seed;
}

function writeSeedJson(outputPath, seed) {
    fs.mkdirSync(path.dirname(outputPath), { recursive: true });
    fs.writeFileSync(outputPath, JSON.stringify(seed));
}

function writeDictionaryModule(outputPath, dictionary) {
    const lines = [
        '// Generated by frontend/build-helpers/generate-lm-dictionary.js',
        '// Source: ../' + SOURCE_FILENAME,
        '',
        'const LM_SENTIMENT_LEXICON = ' + JSON.stringify(dictionary, null, 4) + ';',
        '',
        'export {',
        '    LM_SENTIMENT_LEXICON',
        '};',
        ''
    ];
    fs.mkdirSync(path.dirname(outputPath), { recursive: true });
    fs.writeFileSync(outputPath, lines.join('\n'));
}

function generateLoughranMcDonaldDictionary(baseDir) {
    const sourcePath = resolveSourcePath(baseDir);
    const outputPath = path.resolve(baseDir, OUTPUT_FILENAME);
    const dictionary = buildDictionary(sourcePath);
    writeDictionaryModule(outputPath, dictionary);
    const seedPath = path.resolve(baseDir, SEED_OUTPUT_FILENAME);
    let seedEntries = 0;
    try {
        const seed = buildSeed(dictionary);
        writeSeedJson(seedPath, seed);
        seedEntries = Object.keys(seed).length;
    } catch (error) {
        // Seeding is optional and must not break the frontend build.
        seedEntries = 0;
    }
    return {
        sourcePath: sourcePath,
        outputPath: outputPath,
        seedPath: seedPath,
        seedEntries: seedEntries,
        entries: Object.keys(dictionary).length
    };
}

module.exports = {
    generateLoughranMcDonaldDictionary
};
