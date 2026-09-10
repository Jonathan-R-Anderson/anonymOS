import { LM_SENTIMENT_LEXICON } from './loughranMcDonaldDictionary';

const SENTIMENT_DIMENSIONS = [
    'positive',
    'negative',
    'uncertainty',
    'litigious',
    'constraining',
    'strongModal',
    'weakModal'
];

const STOP_WORDS = buildStemmedLexicon([
    'a', 'about', 'above', 'after', 'again', 'against', 'all', 'am', 'an', 'and',
    'any', 'are', 'as', 'at', 'be', 'because', 'been', 'before', 'being', 'below',
    'between', 'both', 'but', 'by', 'can', 'could', 'did', 'do', 'does', 'doing',
    'down', 'during', 'each', 'few', 'for', 'from', 'further', 'had', 'has', 'have',
    'having', 'he', 'her', 'here', 'hers', 'herself', 'him', 'himself', 'his', 'how',
    'i', 'if', 'in', 'into', 'is', 'it', 'its', 'itself', 'just', 'me', 'more',
    'most', 'my', 'myself', 'now', 'of', 'off', 'on', 'once', 'only', 'or', 'other',
    'our', 'ours', 'ourselves', 'out', 'over', 'own', 'same',
    'she', 'should', 'so', 'some', 'such', 'than', 'that', 'the', 'their', 'theirs',
    'them', 'themselves', 'then', 'there', 'these', 'they', 'this', 'those', 'through',
    'to', 'under', 'until', 'up', 'was', 'we', 'were', 'what', 'when',
    'where', 'which', 'while', 'who', 'whom', 'why', 'will', 'with', 'would', 'you',
    'your', 'yours', 'yourself', 'yourselves', 'also', 'im', 'ive', 'youre', 'didnt',
    'theyre', 'thats', 'theres'
]);

const NEGATOR_WORDS = buildStemmedLexicon([
    'no', 'nor', 'not', 'never', 'without', 'hardly', 'barely', 'cannot', 'cant',
    'dont', 'doesnt', 'isnt', 'arent', 'wasnt', 'werent', 'wont', 'couldnt',
    'shouldnt', 'wouldnt', 'nothing', 'nowhere'
]);

const INTENSIFIER_WORDS = buildStemmedLexicon([
    'very', 'really', 'super', 'extremely', 'highly', 'deeply', 'wildly',
    'incredibly', 'seriously', 'too', 'totally', 'utterly'
]);

function clamp(value, min, max) {
    return Math.max(min, Math.min(max, value));
}

function decodeEntities(text) {
    if (!text) {
        return '';
    }
    return text.replace(/&(#x?[0-9a-f]+|[a-z]+);/gi, function (match, entity) {
        const normalized = String(entity).toLowerCase();
        if (normalized === 'amp') {
            return '&';
        }
        if (normalized === 'lt') {
            return '<';
        }
        if (normalized === 'gt') {
            return '>';
        }
        if (normalized === 'quot') {
            return '"';
        }
        if (normalized === 'apos') {
            return "'";
        }
        if (normalized === 'nbsp') {
            return ' ';
        }
        if (normalized.charAt(0) === '#') {
            const isHex = normalized.charAt(1) === 'x';
            const rawValue = isHex ? normalized.slice(2) : normalized.slice(1);
            const base = isHex ? 16 : 10;
            const codePoint = parseInt(rawValue, base);
            if (!isNaN(codePoint)) {
                try {
                    return String.fromCodePoint(codePoint);
                } catch (error) {
                    return match;
                }
            }
        }
        return match;
    });
}

function stripHtml(text) {
    return decodeEntities((text || '').replace(/<[^>]*>/g, ' '));
}

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

function buildStemmedLexicon(values) {
    return new Set((values || []).map(function (value) {
        return stemToken(String(value || '').toLowerCase());
    }).filter(Boolean));
}

function buildStemmedSentimentLexicon(lexicon) {
    return Object.keys(lexicon || {}).reduce(function (accumulator, word) {
        const stemmed = stemToken(String(word || '').toLowerCase());
        if (!stemmed) {
            return accumulator;
        }
        const categories = lexicon[word] || [];
        if (!accumulator[stemmed]) {
            accumulator[stemmed] = [];
        }
        categories.forEach(function (category) {
            if (accumulator[stemmed].indexOf(category) === -1) {
                accumulator[stemmed].push(category);
            }
        });
        return accumulator;
    }, {});
}

const LM_STEMMED_SENTIMENT_LEXICON = buildStemmedSentimentLexicon(LM_SENTIMENT_LEXICON);

function sentimentCategoriesForToken(normalizedValue, stemmedValue) {
    if (normalizedValue && LM_SENTIMENT_LEXICON[normalizedValue]) {
        return LM_SENTIMENT_LEXICON[normalizedValue];
    }
    if (stemmedValue && LM_STEMMED_SENTIMENT_LEXICON[stemmedValue]) {
        return LM_STEMMED_SENTIMENT_LEXICON[stemmedValue];
    }
    return null;
}

function isLmSentimentToken(normalizedValue, stemmedValue) {
    return !!sentimentCategoriesForToken(normalizedValue, stemmedValue);
}

function normalizeTokenValue(token) {
    return (token || '')
        .replace(/^'+|'+$/g, '')
        .replace(/'/g, '');
}

function extractTokenEntries(text) {
    const cleaned = stripHtml(text)
        .toLowerCase()
        .replace(/https?:\/\/\S+/g, ' ')
        .replace(/&gt;&gt;\d+/g, ' ')
        .replace(/>>\d+/g, ' ')
        .replace(/[\u2018\u2019]/g, "'")
        .replace(/[^a-z0-9'\s]+/g, ' ');
    const rawTokens = cleaned.match(/[a-z0-9']+/g) || [];
    const tokenEntries = [];
    rawTokens.forEach(function (token) {
        const displayValue = token.replace(/^'+|'+$/g, '');
        const normalizedValue = normalizeTokenValue(token);
        if (!normalizedValue || /^\d+$/.test(normalizedValue)) {
            return;
        }
        const stemmed = stemToken(normalizedValue);
        const isSentimentToken = isLmSentimentToken(normalizedValue, stemmed);
        if (
            !stemmed ||
            stemmed.length < 2 ||
            (STOP_WORDS.has(stemmed) && !isSentimentToken && !NEGATOR_WORDS.has(stemmed) && !INTENSIFIER_WORDS.has(stemmed))
        ) {
            return;
        }
        tokenEntries.push({
            display: displayValue,
            normalized: normalizedValue,
            stem: stemmed
        });
    });
    return tokenEntries;
}

// Selection-scoped variant of extractTokenEntries: keeps EVERY word (no stopword
// drop, no stemming for the key) so drag-selected text can be scored word by word.
// Stopwords are retained so negation/intensifier context still applies; they just
// score neutral and are not highlighted.
function extractSelectionTokenEntries(text) {
    const cleaned = stripHtml(text)
        .toLowerCase()
        .replace(/https?:\/\/\S+/g, ' ')
        .replace(/&gt;&gt;\d+/g, ' ')
        .replace(/>>\d+/g, ' ')
        .replace(/[‘’]/g, "'")
        .replace(/[^a-z0-9'\s]+/g, ' ');
    const rawTokens = cleaned.match(/[a-z0-9']+/g) || [];
    const tokenEntries = [];
    rawTokens.forEach(function (token) {
        const displayValue = token.replace(/^'+|'+$/g, '');
        const normalizedValue = normalizeTokenValue(token);
        if (!normalizedValue || /^\d+$/.test(normalizedValue)) {
            return;
        }
        tokenEntries.push({
            display: displayValue,
            normalized: normalizedValue,
            stem: stemToken(normalizedValue)
        });
    });
    return tokenEntries;
}

// Score a raw selection string into per-word sentiment tokens
// ([{token, normalized, stem, score, magnitude, color, profile, ...}]).
function scoreSelectionText(text) {
    return buildSentimentTokens(extractSelectionTokenEntries(text));
}

function preprocessText(text) {
    return extractTokenEntries(text).map(function (entry) {
        return entry.stem;
    });
}

function buildTermCounts(tokens) {
    const counts = {};
    tokens.forEach(function (token) {
        counts[token] = (counts[token] || 0) + 1;
    });
    return counts;
}

function vectorMagnitude(vector) {
    let total = 0;
    Object.keys(vector).forEach(function (key) {
        total += vector[key] * vector[key];
    });
    return Math.sqrt(total);
}

function normalizeVector(vector) {
    const magnitude = vectorMagnitude(vector);
    if (!magnitude) {
        return {};
    }
    const normalized = {};
    Object.keys(vector).forEach(function (key) {
        normalized[key] = vector[key] / magnitude;
    });
    return normalized;
}

function cosineSimilarity(vectorA, vectorB) {
    const keys = Object.keys(vectorA);
    if (!keys.length || !Object.keys(vectorB).length) {
        return 0;
    }
    let total = 0;
    keys.forEach(function (key) {
        if (vectorB[key]) {
            total += vectorA[key] * vectorB[key];
        }
    });
    return total;
}

function averageVectors(vectors) {
    if (!vectors.length) {
        return {};
    }
    const accumulator = {};
    vectors.forEach(function (vector) {
        Object.keys(vector).forEach(function (key) {
            accumulator[key] = (accumulator[key] || 0) + vector[key];
        });
    });
    Object.keys(accumulator).forEach(function (key) {
        accumulator[key] = accumulator[key] / vectors.length;
    });
    return normalizeVector(accumulator);
}

function topTerms(vector, limit) {
    return Object.keys(vector)
        .map(function (term) {
            return {term: term, weight: vector[term]};
        })
        .sort(function (left, right) {
            if (right.weight !== left.weight) {
                return right.weight - left.weight;
            }
            return left.term.localeCompare(right.term);
        })
        .slice(0, limit);
}

function topTermNames(vector, limit) {
    return topTerms(vector, limit).map(function (entry) {
        return entry.term;
    });
}

const SENTIMENT_CATEGORY_WEIGHTS = {
    positive: 0.92,
    negative: -0.96,
    uncertainty: -0.34,
    litigious: -0.22,
    constraining: -0.3,
    strongModal: 0.08,
    weakModal: -0.1
};

const SENTIMENT_CATEGORY_COLORS = {
    positive: [34, 197, 94],
    negative: [239, 68, 68],
    uncertainty: [245, 158, 11],
    litigious: [168, 85, 247],
    constraining: [14, 165, 233],
    strongModal: [217, 119, 6],
    weakModal: [99, 102, 241]
};

function emptySentimentProfile() {
    return {
        valence: 0,
        positive: 0,
        negative: 0,
        uncertainty: 0,
        litigious: 0,
        constraining: 0,
        strongModal: 0,
        weakModal: 0
    };
}

function cloneSentimentProfile(profile) {
    return Object.assign(emptySentimentProfile(), profile || {});
}

function addSentimentProfile(target, source, weight) {
    const nextWeight = weight === undefined ? 1 : weight;
    if (!source) {
        return target;
    }
    target.valence += (source.valence || 0) * nextWeight;
    SENTIMENT_DIMENSIONS.forEach(function (dimension) {
        target[dimension] += (source[dimension] || 0) * nextWeight;
    });
    return target;
}

function normalizeSentimentProfile(profile, divisor) {
    if (!divisor) {
        return emptySentimentProfile();
    }
    const normalized = emptySentimentProfile();
    normalized.valence = (profile.valence || 0) / divisor;
    SENTIMENT_DIMENSIONS.forEach(function (dimension) {
        normalized[dimension] = (profile[dimension] || 0) / divisor;
    });
    return normalized;
}

function averageSentimentProfiles(profiles) {
    if (!profiles.length) {
        return emptySentimentProfile();
    }
    const accumulator = emptySentimentProfile();
    profiles.forEach(function (profile) {
        addSentimentProfile(accumulator, profile, 1);
    });
    return normalizeSentimentProfile(accumulator, profiles.length);
}

function sentimentProfileMagnitude(profile) {
    return Math.max(
        Math.abs(profile && profile.valence ? profile.valence : 0),
        SENTIMENT_DIMENSIONS.reduce(function (total, dimension) {
            return total + Math.abs((profile && profile[dimension]) || 0);
        }, 0) / 2.9
    );
}

function dominantSentimentDimension(profile) {
    if (!profile) {
        return null;
    }
    let bestDimension = null;
    let bestValue = 0;
    SENTIMENT_DIMENSIONS.forEach(function (dimension) {
        const value = profile[dimension] || 0;
        if (value > bestValue) {
            bestValue = value;
            bestDimension = dimension;
        }
    });
    return bestDimension;
}

function tokenBaseSentimentProfile(entry) {
    const categories = sentimentCategoriesForToken(
        entry && entry.normalized,
        entry && entry.stem
    );
    if (!categories || !categories.length) {
        return null;
    }
    const profile = emptySentimentProfile();
    categories.forEach(function (category) {
        if (Object.prototype.hasOwnProperty.call(profile, category)) {
            profile[category] += 1;
        }
        profile.valence += SENTIMENT_CATEGORY_WEIGHTS[category] || 0;
    });
    profile.valence = clamp(profile.valence, -1.2, 1.2);
    return profile;
}

function negateSentimentProfile(profile) {
    const negated = emptySentimentProfile();
    negated.valence = clamp(
        -((profile.valence || 0) * 0.92) - ((profile.strongModal || 0) * 0.04),
        -1.3,
        1.3
    );
    negated.positive = (profile.negative || 0) * 0.82;
    negated.negative = ((profile.positive || 0) * 0.92) + ((profile.strongModal || 0) * 0.08);
    negated.uncertainty = (profile.uncertainty || 0) + ((profile.weakModal || 0) * 0.16) + ((profile.positive || 0) * 0.14);
    negated.litigious = profile.litigious || 0;
    negated.constraining = (profile.constraining || 0) + ((profile.negative || 0) * 0.1);
    negated.strongModal = (profile.strongModal || 0) * 0.55;
    negated.weakModal = (profile.weakModal || 0) + 0.18;
    return negated;
}

function contextualizeSentimentProfile(profile, tokenEntries, index) {
    if (!profile) {
        return null;
    }
    let contextualProfile = cloneSentimentProfile(profile);
    const previousEntry = index > 0 ? tokenEntries[index - 1] : null;
    const earlierEntry = index > 1 ? tokenEntries[index - 2] : null;
    let modifier = 1;
    if (previousEntry && INTENSIFIER_WORDS.has(previousEntry.stem)) {
        modifier += 0.32;
    }
    if (
        earlierEntry &&
        INTENSIFIER_WORDS.has(earlierEntry.stem) &&
        previousEntry &&
        NEGATOR_WORDS.has(previousEntry.stem)
    ) {
        modifier += 0.12;
    }
    if (previousEntry && NEGATOR_WORDS.has(previousEntry.stem)) {
        contextualProfile = negateSentimentProfile(contextualProfile);
    } else if (earlierEntry && NEGATOR_WORDS.has(earlierEntry.stem) && previousEntry && INTENSIFIER_WORDS.has(previousEntry.stem)) {
        contextualProfile = negateSentimentProfile(contextualProfile);
    }
    contextualProfile.valence = clamp(contextualProfile.valence * modifier, -1.3, 1.3);
    SENTIMENT_DIMENSIONS.forEach(function (dimension) {
        contextualProfile[dimension] = clamp(contextualProfile[dimension] * modifier, 0, 1.6);
    });
    return contextualProfile;
}

function sentimentScoreFromProfile(profile) {
    return clamp((profile && profile.valence) || 0, -1, 1);
}

function buildSentimentTokens(tokenEntries) {
    return (tokenEntries || []).map(function (entry, index) {
        const contextualProfile = contextualizeSentimentProfile(
            tokenBaseSentimentProfile(entry),
            tokenEntries,
            index
        );
        const profile = contextualProfile || emptySentimentProfile();
        const score = contextualProfile ? sentimentScoreFromProfile(profile) : 0;
        const magnitude = contextualProfile
            ? clamp(sentimentProfileMagnitude(profile), 0, 1.6)
            : 0;
        return {
            token: entry.display,
            normalized: entry.normalized,
            stem: entry.stem,
            score: score,
            color: sentimentColor(score, profile),
            profile: profile,
            magnitude: magnitude,
            dominantDimension: dominantSentimentDimension(profile)
        };
    });
}

function aggregateSentimentSignals(sentimentTokens) {
    if (!sentimentTokens.length) {
        return {
            score: 0,
            profile: emptySentimentProfile()
        };
    }
    const scoredTokens = sentimentTokens.filter(function (entry) {
        return entry.magnitude > 0;
    });
    if (!scoredTokens.length) {
        return {
            score: 0,
            profile: emptySentimentProfile()
        };
    }
    const aggregateProfile = averageSentimentProfiles(scoredTokens.map(function (entry) {
        return entry.profile;
    }));
    const totalWeight = scoredTokens.reduce(function (total, entry) {
        return total + Math.max(entry.magnitude || 0.18, 0.18);
    }, 0);
    const score = clamp(scoredTokens.reduce(function (total, entry) {
        const weight = Math.max(entry.magnitude || 0.18, 0.18);
        return total + (entry.score * weight);
    }, 0) / Math.max(totalWeight, 1), -1, 1);
    return {
        score: score,
        profile: aggregateProfile
    };
}

function buildSentimentBigrams(sentimentTokens) {
    if (sentimentTokens.length < 2) {
        return [];
    }
    const rows = [];
    for (let index = 0; index < sentimentTokens.length - 1; index += 1) {
        const left = sentimentTokens[index];
        const right = sentimentTokens[index + 1];
        const words = [left, right];
        const magnitude = words.reduce(function (total, word) {
            return total + Math.max(word.magnitude, 0.14);
        }, 0);
        if (magnitude < 0.16) {
            continue;
        }
        const profile = averageSentimentProfiles(words.map(function (word) {
            return word.profile;
        }));
        const score = clamp(
            words.reduce(function (total, word) {
                return total + word.score;
            }, 0) / words.length,
            -1,
            1
        );
        rows.push({
            id: 'bigram-' + index,
            label: left.token + ' ' + right.token,
            score: score,
            magnitude: magnitude,
            tone: summarizeSentiment(score, profile),
            profile: profile,
            words: words.map(function (word) {
                return {
                    token: word.token,
                    score: word.score,
                    color: word.color,
                    magnitude: Math.max(word.magnitude, 0.14),
                    dominantDimension: word.dominantDimension
                };
            })
        });
    }
    if (rows.length) {
        return rows;
    }
    return sentimentTokens.slice(0, Math.max(0, sentimentTokens.length - 1)).map(function (left, index) {
        const right = sentimentTokens[index + 1];
        return {
            id: 'bigram-fallback-' + index,
            label: left.token + ' ' + right.token,
            score: clamp((left.score + right.score) / 2, -1, 1),
            magnitude: 0.28,
            tone: 'mixed',
            profile: emptySentimentProfile(),
            words: [left, right].map(function (word) {
                return {
                    token: word.token,
                    score: word.score,
                    color: word.color,
                    magnitude: 0.14,
                    dominantDimension: word.dominantDimension
                };
            })
        };
    });
}

function rgbToHex(r, g, b) {
    return '#' + [r, g, b].map(function (value) {
        const clamped = clamp(Math.round(value), 0, 255);
        return clamped.toString(16).padStart(2, '0');
    }).join('');
}

function mixColor(colorA, colorB, ratio) {
    return rgbToHex(
        colorA[0] + (colorB[0] - colorA[0]) * ratio,
        colorA[1] + (colorB[1] - colorA[1]) * ratio,
        colorA[2] + (colorB[2] - colorA[2]) * ratio
    );
}

function hexToRgba(color, alpha) {
    if (!color || color.charAt(0) !== '#') {
        return color;
    }
    const normalized = color.length === 4
        ? '#' + color.charAt(1) + color.charAt(1) + color.charAt(2) + color.charAt(2) + color.charAt(3) + color.charAt(3)
        : color;
    const red = parseInt(normalized.slice(1, 3), 16);
    const green = parseInt(normalized.slice(3, 5), 16);
    const blue = parseInt(normalized.slice(5, 7), 16);
    return 'rgba(' + red + ', ' + green + ', ' + blue + ', ' + clamp(alpha, 0, 1) + ')';
}

function highlightableSentimentToken(token) {
    if (!token) {
        return false;
    }
    return (token.magnitude || 0) > 0.04 || Math.abs(token.score || 0) > 0.06;
}

function sentimentHighlightPalette(token) {
    const intensity = clamp((token && token.magnitude ? token.magnitude : 0) / 1.15, 0.12, 1);
    return {
        background: hexToRgba((token && token.color) || '#94a3b8', 0.14 + (intensity * 0.22)),
        border: hexToRgba((token && token.color) || '#94a3b8', 0.24 + (intensity * 0.24)),
        glow: hexToRgba((token && token.color) || '#94a3b8', 0.08 + (intensity * 0.16))
    };
}

function sentimentTokenTitle(token) {
    if (!token) {
        return '';
    }
    const tone = summarizeSentiment(token.score || 0, token.profile || emptySentimentProfile());
    const label = token.token || token.normalized || 'token';
    return label + ' • ' + tone + ' • score ' + (token.score || 0).toFixed(2);
}

function decorateHtmlWithSentiment(bodyHtml, sentimentTokens) {
    if (!bodyHtml || !sentimentTokens || !sentimentTokens.length) {
        return bodyHtml || '';
    }
    if (
        typeof window === 'undefined' ||
        typeof window.DOMParser !== 'function'
    ) {
        return bodyHtml;
    }

    try {
        const parser = new window.DOMParser();
        const parsedDocument = parser.parseFromString(
            '<div data-sentiment-root="true">' + bodyHtml + '</div>',
            'text/html'
        );
        const root = parsedDocument.body && parsedDocument.body.firstElementChild;
        if (!root) {
            return bodyHtml;
        }

        const textNodes = [];
        const walker = parsedDocument.createTreeWalker(root, 4, null, false);
        let currentTextNode = walker.nextNode();
        while (currentTextNode) {
            textNodes.push(currentTextNode);
            currentTextNode = walker.nextNode();
        }

        let tokenIndex = 0;
        textNodes.forEach(function (textNode) {
            const value = textNode.nodeValue || '';
            if (!value) {
                return;
            }
            const fragment = parsedDocument.createDocumentFragment();
            const matcher = /[A-Za-z0-9']+/g;
            let match = matcher.exec(value);
            let lastIndex = 0;

            while (match) {
                const word = match[0];
                const start = match.index;
                const end = start + word.length;
                const normalized = normalizeTokenValue(word.toLowerCase());
                const stemmed = normalized ? stemToken(normalized) : '';
                const nextToken = tokenIndex < sentimentTokens.length
                    ? sentimentTokens[tokenIndex]
                    : null;

                if (start > lastIndex) {
                    fragment.appendChild(parsedDocument.createTextNode(value.slice(lastIndex, start)));
                }

                if (
                    nextToken &&
                    normalized &&
                    !/^\d+$/.test(normalized) &&
                    (
                        nextToken.normalized === normalized ||
                        nextToken.stem === stemmed
                    )
                ) {
                    tokenIndex += 1;
                    if (highlightableSentimentToken(nextToken)) {
                        const palette = sentimentHighlightPalette(nextToken);
                        const span = parsedDocument.createElement('span');
                        span.className = 'post-sentiment-word';
                        span.style.setProperty('--post-sentiment-bg', palette.background);
                        span.style.setProperty('--post-sentiment-border', palette.border);
                        span.style.setProperty('--post-sentiment-glow', palette.glow);
                        span.title = sentimentTokenTitle(nextToken);
                        span.textContent = word;
                        fragment.appendChild(span);
                    } else {
                        fragment.appendChild(parsedDocument.createTextNode(word));
                    }
                } else {
                    fragment.appendChild(parsedDocument.createTextNode(word));
                }

                lastIndex = end;
                match = matcher.exec(value);
            }

            if (!lastIndex) {
                return;
            }
            if (lastIndex < value.length) {
                fragment.appendChild(parsedDocument.createTextNode(value.slice(lastIndex)));
            }
            if (textNode.parentNode) {
                textNode.parentNode.replaceChild(fragment, textNode);
            }
        });

        return root.innerHTML;
    } catch (error) {
        return bodyHtml;
    }
}

function sentimentColor(score, profile) {
    const neutral = [148, 163, 184];
    const positive = [34, 197, 94];
    const negative = [239, 68, 68];
    const dominantDimension = dominantSentimentDimension(profile);
    const dominantPalette = dominantDimension ? SENTIMENT_CATEGORY_COLORS[dominantDimension] : null;
    if (dominantPalette) {
        return mixColor(
            neutral,
            dominantPalette,
            clamp(sentimentProfileMagnitude(profile || emptySentimentProfile()) / 1.12, 0.18, 1)
        );
    }
    if (score >= 0) {
        return mixColor(neutral, positive, clamp(score, 0, 1));
    }
    return mixColor(neutral, negative, clamp(Math.abs(score), 0, 1));
}

function semanticTextForPost(post) {
    const subject = stripHtml(post.subject || '');
    const body = stripHtml(post.body || '');
    return (subject + ' ' + body).trim();
}

function snippet(text, maxLength) {
    if (!text) {
        return '';
    }
    if (text.length <= maxLength) {
        return text;
    }
    return text.slice(0, Math.max(0, maxLength - 1)).trim() + '…';
}

function uniqueValues(values) {
    return Array.from(new Set(values));
}

function keywordOverlap(leftTerms, rightTerms) {
    const rightSet = new Set(rightTerms);
    let overlap = 0;
    leftTerms.forEach(function (term) {
        if (rightSet.has(term)) {
            overlap += 1;
        }
    });
    return overlap;
}

function clusterAssignmentScore(document, cluster) {
    const similarity = cosineSimilarity(document.vector, cluster.centroid);
    const overlap = keywordOverlap(document.topTerms, cluster.keywords);
    const collision = overlap / Math.max(1, Math.min(document.topTerms.length, 4));
    return {
        similarity: similarity,
        collision: collision,
        score: (similarity * 0.72) + (collision * 0.28)
    };
}

function summarizeSentiment(score, profile) {
    if (profile) {
        const dominantDimension = dominantSentimentDimension(profile);
        const dominantValue = dominantDimension ? profile[dominantDimension] || 0 : 0;
        if (score >= 0.48 && (profile.positive || 0) >= 0.24) {
            if ((profile.strongModal || 0) >= 0.24) {
                return 'conviction positive';
            }
            return 'positive';
        }
        if (score >= 0.18) {
            if ((profile.strongModal || 0) >= 0.24) {
                return 'confident';
            }
            return 'leaning positive';
        }
        if (score <= -0.48) {
            if ((profile.litigious || 0) >= Math.max(profile.negative || 0, profile.uncertainty || 0, profile.constraining || 0)) {
                return 'legalistic';
            }
            if ((profile.constraining || 0) >= Math.max(profile.negative || 0, profile.uncertainty || 0, profile.litigious || 0)) {
                return 'restrictive';
            }
            if ((profile.uncertainty || 0) >= Math.max(profile.negative || 0, profile.litigious || 0, profile.constraining || 0)) {
                return 'uncertain';
            }
            return 'negative';
        }
        if (score <= -0.18) {
            if ((profile.weakModal || 0) >= 0.24) {
                return 'hedged';
            }
            if ((profile.uncertainty || 0) >= 0.24) {
                return 'uncertain';
            }
            return 'leaning negative';
        }
        if (dominantValue >= 0.28) {
            if (dominantDimension === 'uncertainty') {
                return 'uncertain';
            }
            if (dominantDimension === 'litigious') {
                return 'legalistic';
            }
            if (dominantDimension === 'constraining') {
                return 'restrictive';
            }
            if (dominantDimension === 'strongModal') {
                return 'forceful';
            }
            if (dominantDimension === 'weakModal') {
                return 'hedged';
            }
        }
    }
    if (score > 0.48) {
        return 'positive';
    }
    if (score > 0.18) {
        return 'leaning positive';
    }
    if (score < -0.48) {
        return 'negative';
    }
    if (score < -0.18) {
        return 'leaning negative';
    }
    return 'mixed';
}

function clusterDisplayLabel(cluster) {
    if (cluster.isMisc) {
        return 'Misc';
    }
    if (cluster.label) {
        return cluster.label;
    }
    return (cluster.keywords && cluster.keywords[0]) || cluster.id || 'cluster';
}

function buildClusterSummary(cluster, keywordList) {
    const count = cluster.memberIds.length;
    const sentimentLabel = summarizeSentiment(cluster.sentiment);
    const intro = count === 1 ? '1 comment' : count + ' comments';
    if (cluster.isMisc) {
        if (!keywordList.length) {
            return intro + ' sit on the semantic fringe with a ' + sentimentLabel + ' tone.';
        }
        return intro + ' sit on the semantic fringe around ' + keywordList.slice(0, 3).join(', ') + ' with a ' + sentimentLabel + ' tone.';
    }
    if (cluster.isOutlier) {
        if (!keywordList.length) {
            return intro + ' stands apart from the larger branches with a ' + sentimentLabel + ' tone.';
        }
        return intro + ' stands apart around ' + keywordList.slice(0, 3).join(', ') + ' with a ' + sentimentLabel + ' tone.';
    }
    if (!keywordList.length) {
        return intro + ' share a ' + sentimentLabel + ' tone.';
    }
    return intro + ' converge on ' + keywordList.slice(0, 3).join(', ') + ' with a ' + sentimentLabel + ' tone.';
}

function buildConversationSummary(documents, globalKeywords, clusters, conversationSentiment, conversationProfile) {
    if (!documents.length) {
        return 'No comments available.';
    }
    const topicPhrase = globalKeywords.length ? globalKeywords.slice(0, 4).join(', ') : 'the thread';
    const clusterKeywords = clusters
        .slice(0, 3)
        .map(function (cluster) {
            return clusterDisplayLabel(cluster);
        })
        .filter(Boolean);
    const sentimentLabel = summarizeSentiment(conversationSentiment, conversationProfile);
    let summary = documents.length + ' comments branch around ' + topicPhrase + '.';
    if (clusterKeywords.length) {
        summary += ' Major branches form around ' + clusterKeywords.join(', ') + '.';
    }
    summary += ' Overall sentiment is ' + sentimentLabel + '.';
    return summary;
}

function extractReplyReferences(text, validPostIds, ownDocumentId) {
    const matches = [];
    const seen = new Set();
    const iterator = /(?:>>|&gt;&gt;)(\d+)/g;
    let match = iterator.exec(text || '');
    while (match) {
        const referenceId = String(match[1]);
        if (
            validPostIds.has(referenceId) &&
            referenceId !== ownDocumentId &&
            !seen.has(referenceId)
        ) {
            seen.add(referenceId);
            matches.push(referenceId);
        }
        match = iterator.exec(text || '');
    }
    return matches;
}

function buildDocuments(posts) {
    const documentFrequency = {};
    const documents = posts.map(function (post, index) {
        const text = semanticTextForPost(post);
        const tokenEntries = extractTokenEntries(text);
        const bodyTokenEntries = extractTokenEntries((post && post.body) || '');
        const tokens = tokenEntries.map(function (entry) {
            return entry.stem;
        });
        const uniqueTokens = new Set(tokens);
        uniqueTokens.forEach(function (token) {
            documentFrequency[token] = (documentFrequency[token] || 0) + 1;
        });
        return {
            id: String(post.id),
            postId: post.id,
            threadId: post.thread_id,
            text: text,
            excerpt: snippet(text, 180),
            tokens: tokens,
            tokenEntries: tokenEntries,
            bodyTokenEntries: bodyTokenEntries,
            subject: post.subject || '',
            poster: post.poster,
            orderIndex: index,
            rawPost: post
        };
    });

    const totalDocuments = Math.max(1, documents.length);
    documents.forEach(function (document) {
        const counts = buildTermCounts(document.tokens);
        const vector = {};
        Object.keys(counts).forEach(function (term) {
            const tf = counts[term] / Math.max(1, document.tokens.length);
            const idf = Math.log((1 + totalDocuments) / (1 + (documentFrequency[term] || 0))) + 1;
            vector[term] = tf * idf;
        });
        document.vector = normalizeVector(vector);
        document.vectorMagnitude = vectorMagnitude(document.vector);
        document.topTerms = topTermNames(document.vector, 6);
        document.sentimentTokens = buildSentimentTokens(document.tokenEntries || []);
        document.bodySentimentTokens = buildSentimentTokens(document.bodyTokenEntries || []);
        const sentimentSignals = aggregateSentimentSignals(document.sentimentTokens);
        document.sentiment = sentimentSignals.score;
        document.sentimentProfile = sentimentSignals.profile;
        document.sentimentTone = summarizeSentiment(document.sentiment, document.sentimentProfile);
        document.sentimentBigrams = buildSentimentBigrams(document.sentimentTokens);
        document.color = sentimentColor(document.sentiment);
    });

    const validPostIds = new Set(documents.map(function (document) {
        return document.id;
    }));
    documents.forEach(function (document) {
        const referenceIds = extractReplyReferences(
            (document.rawPost && document.rawPost.body) || '',
            validPostIds,
            document.id
        );
        document.referenceIds = referenceIds;
        document.referencePostIds = referenceIds.map(function (referenceId) {
            return parseInt(referenceId, 10);
        });
    });
    return documents;
}

function orderDocumentsBySimilarity(members, anchorVector) {
    if (!members.length) {
        return [];
    }
    if (members.length === 1) {
        return members.slice();
    }
    const anchor = anchorVector && Object.keys(anchorVector).length
        ? anchorVector
        : averageVectors(members.map(function (member) {
            return member.vector;
        }));
    const remaining = members.slice().sort(function (left, right) {
        const leftScore = cosineSimilarity(left.vector, anchor);
        const rightScore = cosineSimilarity(right.vector, anchor);
        if (rightScore !== leftScore) {
            return rightScore - leftScore;
        }
        return left.postId - right.postId;
    });
    const ordered = [remaining.shift()];
    while (remaining.length) {
        const previous = ordered[ordered.length - 1];
        let bestIndex = 0;
        let bestScore = -Infinity;
        remaining.forEach(function (candidate, candidateIndex) {
            const continuity = cosineSimilarity(previous.vector, candidate.vector);
            const anchorScore = cosineSimilarity(candidate.vector, anchor);
            const score = (continuity * 0.72) + (anchorScore * 0.28);
            if (score > bestScore) {
                bestScore = score;
                bestIndex = candidateIndex;
                return;
            }
            if (score === bestScore && candidate.postId < remaining[bestIndex].postId) {
                bestIndex = candidateIndex;
            }
        });
        ordered.push(remaining.splice(bestIndex, 1)[0]);
    }
    return ordered;
}

function orderClustersBySimilarity(clusters) {
    if (clusters.length <= 2) {
        return clusters.slice();
    }
    const anchor = averageVectors(clusters.map(function (cluster) {
        return cluster.centroid;
    }));
    const remaining = clusters.slice().sort(function (left, right) {
        const leftScore = cosineSimilarity(left.centroid, anchor);
        const rightScore = cosineSimilarity(right.centroid, anchor);
        if (rightScore !== leftScore) {
            return rightScore - leftScore;
        }
        return left.id.localeCompare(right.id);
    });
    const ordered = [remaining.shift()];
    while (remaining.length) {
        const previous = ordered[ordered.length - 1];
        let bestIndex = 0;
        let bestScore = -Infinity;
        remaining.forEach(function (candidate, candidateIndex) {
            const score = clusterSimilarityScore(previous, candidate).score;
            if (score > bestScore) {
                bestScore = score;
                bestIndex = candidateIndex;
                return;
            }
            if (score === bestScore && candidate.id.localeCompare(remaining[bestIndex].id) < 0) {
                bestIndex = candidateIndex;
            }
        });
        ordered.push(remaining.splice(bestIndex, 1)[0]);
    }
    return ordered;
}

function commentLeafLabel(document) {
    const cleaned = (document.text || '').replace(/\s+/g, ' ').trim();
    if (!cleaned) {
        return '#' + document.postId;
    }
    return '#' + document.postId + ' ' + snippet(cleaned, 42);
}

function recomputeCluster(cluster, documents) {
    const members = cluster.memberIds.map(function (documentId) {
        return documents.find(function (document) {
            return document.id === documentId;
        });
    }).filter(Boolean);
    cluster.centroid = averageVectors(members.map(function (member) {
        return member.vector;
    }));
    cluster.keywords = topTermNames(cluster.centroid, 8);
    cluster.sentiment = members.length
        ? members.reduce(function (total, member) {
            return total + member.sentiment;
        }, 0) / members.length
        : 0;
    cluster.summary = buildClusterSummary(cluster, cluster.keywords);
    cluster.label = clusterDisplayLabel(cluster);
    return cluster;
}

function mergeClusters(left, right) {
    return {
        id: left.id,
        memberIds: left.memberIds.concat(right.memberIds),
        centroid: {},
        keywords: [],
        sentiment: 0,
        summary: ''
    };
}

function clusterSimilarityScore(left, right) {
    const similarity = cosineSimilarity(left.centroid, right.centroid);
    const overlap = keywordOverlap((left.keywords || []).slice(0, 4), (right.keywords || []).slice(0, 4));
    return {
        similarity: similarity,
        overlap: overlap,
        score: (similarity * 0.78) + ((Math.min(2, overlap) / 2) * 0.22)
    };
}

function consolidateOutlierClusters(outlierClusters, documents) {
    const bundles = [];
    outlierClusters.forEach(function (cluster) {
        let bestBundle = null;
        let bestScore = null;
        bundles.forEach(function (bundle) {
            const score = clusterSimilarityScore(cluster, bundle);
            if (bestScore === null || score.score > bestScore.score) {
                bestScore = score;
                bestBundle = bundle;
            }
        });
        if (bestScore && (bestScore.similarity >= 0.16 || bestScore.overlap >= 1)) {
            bestBundle.memberIds = bestBundle.memberIds.concat(cluster.memberIds);
            bestBundle.mergedClusterIds = bestBundle.mergedClusterIds.concat(cluster.id);
            recomputeCluster(bestBundle, documents);
            return;
        }
        bundles.push(recomputeCluster({
            id: cluster.id,
            memberIds: cluster.memberIds.slice(),
            centroid: cluster.centroid,
            keywords: cluster.keywords ? cluster.keywords.slice() : [],
            sentiment: cluster.sentiment,
            summary: cluster.summary,
            label: cluster.label,
            isMisc: false,
            isOutlier: false,
            mergedClusterIds: [cluster.id]
        }, documents));
    });
    return bundles;
}

function compressOutlierClusters(clusters, documents) {
    const anchoredClusters = [];
    const outlierClusters = [];
    clusters.forEach(function (cluster) {
        if (cluster.memberIds.length <= 1) {
            outlierClusters.push(cluster);
            return;
        }
        anchoredClusters.push(cluster);
    });
    if (!outlierClusters.length) {
        return clusters;
    }
    const bundledOutliers = consolidateOutlierClusters(outlierClusters, documents);
    const promotedClusters = bundledOutliers.filter(function (cluster) {
        return cluster.memberIds.length > 1;
    });
    const loneOutliers = bundledOutliers.filter(function (cluster) {
        return cluster.memberIds.length <= 1;
    });

    if (!anchoredClusters.length) {
        return promotedClusters.concat(loneOutliers.map(function (cluster) {
            return recomputeCluster(Object.assign({}, cluster, {
                isOutlier: true,
                isMisc: false,
                mergedClusterIds: cluster.mergedClusterIds && cluster.mergedClusterIds.length
                    ? cluster.mergedClusterIds
                    : [cluster.id]
            }), documents);
        }));
    }

    const compressedClusters = anchoredClusters.concat(promotedClusters);
    if (loneOutliers.length === 1) {
        compressedClusters.push(recomputeCluster(Object.assign({}, loneOutliers[0], {
            isOutlier: true,
            isMisc: false,
            mergedClusterIds: loneOutliers[0].mergedClusterIds && loneOutliers[0].mergedClusterIds.length
                ? loneOutliers[0].mergedClusterIds
                : [loneOutliers[0].id]
        }), documents));
        return compressedClusters;
    }
    if (!loneOutliers.length) {
        return compressedClusters;
    }
    compressedClusters.push(recomputeCluster({
        id: 'cluster-misc',
        memberIds: loneOutliers.reduce(function (accumulator, cluster) {
            return accumulator.concat(cluster.memberIds);
        }, []),
        centroid: {},
        keywords: [],
        sentiment: 0,
        summary: '',
        label: 'Misc',
        isMisc: true,
        isOutlier: false,
        mergedClusterIds: loneOutliers.reduce(function (accumulator, cluster) {
            return accumulator.concat(cluster.mergedClusterIds && cluster.mergedClusterIds.length
                ? cluster.mergedClusterIds
                : [cluster.id]);
        }, [])
    }, documents));
    return compressedClusters;
}

function buildClusters(documents) {
    if (!documents.length) {
        return [];
    }
    const sortedDocuments = documents.slice().sort(function (left, right) {
        if (right.tokens.length !== left.tokens.length) {
            return right.tokens.length - left.tokens.length;
        }
        return left.postId - right.postId;
    });

    let clusters = [];
    sortedDocuments.forEach(function (document, index) {
        if (!clusters.length) {
            clusters.push({
                id: 'cluster-1',
                memberIds: [document.id],
                centroid: document.vector,
                keywords: document.topTerms.slice(0, 8),
                sentiment: document.sentiment,
                summary: ''
            });
            return;
        }
        let bestCluster = null;
        let bestMatch = null;
        clusters.forEach(function (cluster) {
            const match = clusterAssignmentScore(document, cluster);
            if (bestMatch === null || match.score > bestMatch.score) {
                bestMatch = match;
                bestCluster = cluster;
            }
        });
        if (bestMatch && (bestMatch.score >= 0.34 || (bestMatch.similarity >= 0.24 && bestMatch.collision >= 0.5))) {
            bestCluster.memberIds.push(document.id);
            recomputeCluster(bestCluster, documents);
        } else {
            clusters.push({
                id: 'cluster-' + (index + 1),
                memberIds: [document.id],
                centroid: document.vector,
                keywords: document.topTerms.slice(0, 8),
                sentiment: document.sentiment,
                summary: ''
            });
        }
    });

    clusters = clusters.map(function (cluster) {
        return recomputeCluster(cluster, documents);
    });

    let merged = true;
    while (merged && clusters.length > 1) {
        merged = false;
        for (let leftIndex = 0; leftIndex < clusters.length && !merged; leftIndex += 1) {
            for (let rightIndex = leftIndex + 1; rightIndex < clusters.length; rightIndex += 1) {
                const left = clusters[leftIndex];
                const right = clusters[rightIndex];
                const similarity = cosineSimilarity(left.centroid, right.centroid);
                const overlap = keywordOverlap(left.keywords.slice(0, 5), right.keywords.slice(0, 5));
                if (similarity > 0.54 || overlap >= 3) {
                    const combined = recomputeCluster(mergeClusters(left, right), documents);
                    clusters.splice(rightIndex, 1);
                    clusters.splice(leftIndex, 1, combined);
                    merged = true;
                    break;
                }
            }
        }
    }

    clusters = compressOutlierClusters(clusters, documents).sort(function (left, right) {
        if (!!left.isMisc !== !!right.isMisc) {
            return left.isMisc ? 1 : -1;
        }
        if (!!left.isOutlier !== !!right.isOutlier) {
            return left.isOutlier ? 1 : -1;
        }
        if (right.memberIds.length !== left.memberIds.length) {
            return right.memberIds.length - left.memberIds.length;
        }
        return clusterDisplayLabel(left).localeCompare(clusterDisplayLabel(right));
    });

    const clusterIdRemap = {};
    clusters = clusters.map(function (cluster, index) {
        const previousIds = cluster.mergedClusterIds && cluster.mergedClusterIds.length
            ? cluster.mergedClusterIds
            : [cluster.id];
        const nextId = 'cluster-' + (index + 1);
        previousIds.forEach(function (previousId) {
            clusterIdRemap[previousId] = nextId;
        });
        cluster.id = nextId;
        return recomputeCluster(cluster, documents);
    });

    const clusterScores = {};
    documents.forEach(function (document) {
        if (document.clusterId && clusterIdRemap[document.clusterId]) {
            document.clusterId = clusterIdRemap[document.clusterId];
        }
        document.secondaryClusterIds = uniqueValues((document.secondaryClusterIds || [])
            .map(function (clusterId) {
                return clusterIdRemap[clusterId] || clusterId;
            })
            .filter(function (clusterId) {
                return clusterId && clusterId !== document.clusterId;
            }));
        const orderedMatches = clusters.map(function (cluster) {
            const match = clusterAssignmentScore(document, cluster);
            return {clusterId: cluster.id, match: match};
        }).sort(function (left, right) {
            return right.match.score - left.match.score;
        });
        document.clusterId = orderedMatches.length ? orderedMatches[0].clusterId : null;
        document.secondaryClusterIds = orderedMatches
            .slice(1)
            .filter(function (entry) {
                return entry.match.score >= 0.24;
            })
            .map(function (entry) {
                return entry.clusterId;
            });
        orderedMatches.forEach(function (entry) {
            if (!clusterScores[entry.clusterId]) {
                clusterScores[entry.clusterId] = {};
            }
            clusterScores[entry.clusterId][document.id] = entry.match.score;
        });
    });

    clusters.forEach(function (cluster) {
        cluster.memberIds = documents
            .filter(function (document) {
                return document.clusterId === cluster.id;
            })
            .map(function (document) {
                return document.id;
            });
        cluster.matchScores = clusterScores[cluster.id] || {};
        recomputeCluster(cluster, documents);
    });

    return clusters.filter(function (cluster) {
        return cluster.memberIds.length;
    });
}

function recomputeMemberGroup(group) {
    group.centroid = averageVectors(group.members.map(function (member) {
        return member.vector;
    }));
    group.keywords = topTermNames(group.centroid, 6);
    group.sentiment = group.members.length
        ? group.members.reduce(function (total, member) {
            return total + member.sentiment;
        }, 0) / group.members.length
        : 0;
    group.label = group.isMisc
        ? 'misc'
        : (group.label || group.keywords[0] || (group.members[0] ? group.members[0].topTerms[0] : 'branch') || 'branch');
    return group;
}

function mergeTreeSimilarityScore(left, right) {
    const similarity = cosineSimilarity(left.centroid || left.tfidfVector || {}, right.centroid || right.tfidfVector || {});
    const overlap = keywordOverlap((left.keywords || []).slice(0, 4), (right.keywords || []).slice(0, 4));
    return {
        similarity: similarity,
        overlap: overlap,
        score: (similarity * 0.84) + ((Math.min(2, overlap) / 2) * 0.16)
    };
}

function createCommentLeaf(document, cluster) {
    return {
        id: 'comment-' + document.id,
        post_id: document.postId,
        kind: 'comment',
        label: commentLeafLabel(document),
        cluster_id: cluster.id,
        secondary_cluster_ids: document.secondaryClusterIds,
        text: document.text,
        keywords: document.topTerms,
        summary: snippet(document.text, 160),
        sentiment: document.sentiment,
        tfidfVector: document.vector,
        centroid: document.vector,
        color: document.color,
        memberIds: [document.id],
        children: []
    };
}

function mergeHierarchyNodes(left, right, clusterId, mergeIndex) {
    const memberIds = left.memberIds.concat(right.memberIds);
    const centroid = averageVectors([left.centroid || left.tfidfVector || {}, right.centroid || right.tfidfVector || {}]);
    const keywords = topTermNames(centroid, 6);
    const sentimentTotal = (left.sentiment * left.memberIds.length) + (right.sentiment * right.memberIds.length);
    const sentiment = memberIds.length ? sentimentTotal / memberIds.length : 0;
    return {
        id: clusterId + '-merge-' + mergeIndex,
        kind: 'merge',
        label: '',
        cluster_id: clusterId,
        keywords: keywords,
        summary: buildClusterSummary({memberIds: memberIds, sentiment: sentiment}, keywords),
        sentiment: sentiment,
        tfidfVector: centroid,
        centroid: centroid,
        memberIds: memberIds,
        children: [left, right]
    };
}

function buildClusterHierarchy(cluster, documents) {
    const members = orderDocumentsBySimilarity(cluster.memberIds.map(function (memberId) {
        return documents.find(function (document) {
            return document.id === memberId;
        });
    }).filter(Boolean), cluster.centroid);
    if (!members.length) {
        return null;
    }
    let mergeIndex = 1;
    let nodes = members.map(function (member) {
        return createCommentLeaf(member, cluster);
    });
    while (nodes.length > 1) {
        let bestPair = null;
        let bestScore = null;
        for (let leftIndex = 0; leftIndex < nodes.length; leftIndex += 1) {
            for (let rightIndex = leftIndex + 1; rightIndex < nodes.length; rightIndex += 1) {
                const score = mergeTreeSimilarityScore(nodes[leftIndex], nodes[rightIndex]);
                if (bestScore === null || score.score > bestScore.score) {
                    bestScore = score;
                    bestPair = [leftIndex, rightIndex];
                }
            }
        }
        if (!bestPair) {
            break;
        }
        const rightNode = nodes.splice(bestPair[1], 1)[0];
        const leftNode = nodes.splice(bestPair[0], 1)[0];
        nodes.push(mergeHierarchyNodes(leftNode, rightNode, cluster.id, mergeIndex));
        mergeIndex += 1;
    }
    return nodes[0];
}

function appendTreeToGraph(node, parentId, graphNodes, graphEdges) {
    if (!node) {
        return;
    }
    graphNodes.push(node);
    if (parentId) {
        graphEdges.push({source: parentId, target: node.id});
    }
    (node.children || []).forEach(function (child) {
        appendTreeToGraph(child, node.id, graphNodes, graphEdges);
    });
}

function buildSubclusters(cluster, documents) {
    const members = cluster.memberIds.map(function (memberId) {
        return documents.find(function (document) {
            return document.id === memberId;
        });
    }).filter(Boolean);
    if (!members.length || cluster.isMisc || cluster.isOutlier) {
        return [];
    }
    const seededMembers = members.slice().sort(function (left, right) {
        const leftScore = cosineSimilarity(left.vector, cluster.centroid);
        const rightScore = cosineSimilarity(right.vector, cluster.centroid);
        if (rightScore !== leftScore) {
            return rightScore - leftScore;
        }
        return left.postId - right.postId;
    });
    let groups = [];

    seededMembers.forEach(function (member) {
        let bestGroup = null;
        let bestMatch = null;
        groups.forEach(function (group) {
            const match = clusterAssignmentScore(member, {
                centroid: group.centroid,
                keywords: group.keywords
            });
            if (bestMatch === null || match.score > bestMatch.score) {
                bestMatch = match;
                bestGroup = group;
            }
        });
        if (bestMatch && (bestMatch.score >= 0.31 || (bestMatch.similarity >= 0.22 && bestMatch.collision >= 0.25))) {
            bestGroup.members.push(member);
            recomputeMemberGroup(bestGroup);
            return;
        }
        groups.push(recomputeMemberGroup({
            label: member.topTerms[0] || cluster.keywords[0] || 'branch',
            members: [member],
            centroid: member.vector,
            keywords: member.topTerms.slice(0, 6),
            sentiment: member.sentiment,
            isMisc: false,
            isOutlier: false
        }));
    });

    let merged = true;
    while (merged && groups.length > 1) {
        merged = false;
        for (let leftIndex = 0; leftIndex < groups.length && !merged; leftIndex += 1) {
            for (let rightIndex = leftIndex + 1; rightIndex < groups.length; rightIndex += 1) {
                const left = groups[leftIndex];
                const right = groups[rightIndex];
                const similarity = cosineSimilarity(left.centroid, right.centroid);
                const overlap = keywordOverlap(left.keywords.slice(0, 4), right.keywords.slice(0, 4));
                if (similarity > 0.48 || overlap >= 2) {
                    groups.splice(rightIndex, 1);
                    groups.splice(leftIndex, 1, recomputeMemberGroup({
                        label: left.label,
                        members: left.members.concat(right.members),
                        centroid: {},
                        keywords: [],
                        sentiment: 0,
                        isMisc: false,
                        isOutlier: false
                    }));
                    merged = true;
                    break;
                }
            }
        }
    }

    const singleMemberGroups = groups.filter(function (group) {
        return group.members.length === 1;
    });
    if (singleMemberGroups.length > 1) {
        groups = groups.filter(function (group) {
            return group.members.length > 1;
        });
        groups.push(recomputeMemberGroup({
            label: 'misc',
            members: singleMemberGroups.reduce(function (accumulator, group) {
                return accumulator.concat(group.members);
            }, []),
            centroid: {},
            keywords: [],
            sentiment: 0,
            isMisc: true,
            isOutlier: false
        }));
    } else if (singleMemberGroups.length === 1) {
        groups = groups.map(function (group) {
            if (group.members.length === 1) {
                group.isOutlier = true;
            }
            return recomputeMemberGroup(group);
        });
    }

    return groups.sort(function (left, right) {
        if (!!left.isMisc !== !!right.isMisc) {
            return left.isMisc ? 1 : -1;
        }
        if (!!left.isOutlier !== !!right.isOutlier) {
            return left.isOutlier ? 1 : -1;
        }
        if (right.members.length !== left.members.length) {
            return right.members.length - left.members.length;
        }
        return left.label.localeCompare(right.label);
    }).map(function (group, index) {
        const orderedMembers = orderDocumentsBySimilarity(group.members, group.centroid);
        const centroid = averageVectors(orderedMembers.map(function (member) {
            return member.vector;
        }));
        const keywords = topTermNames(centroid, 6).length
            ? topTermNames(centroid, 6)
            : [group.label];
        const sentiment = orderedMembers.reduce(function (total, member) {
            return total + member.sentiment;
        }, 0) / orderedMembers.length;
        return {
            id: cluster.id + '-branch-' + (index + 1),
            clusterId: cluster.id,
            memberIds: orderedMembers.map(function (member) {
                return member.id;
            }),
            centroid: centroid,
            keywords: keywords,
            label: group.isMisc ? 'misc' : (group.isOutlier ? ((orderedMembers[0].topTerms[0] || keywords[0] || 'outlier')) : (group.label || keywords[0] || 'branch')),
            sentiment: sentiment,
            isMisc: group.isMisc,
            isOutlier: group.isOutlier,
            summary: buildClusterSummary({memberIds: orderedMembers.map(function (member) {
                return member.id;
            }), sentiment: sentiment, isMisc: group.isMisc, isOutlier: group.isOutlier}, keywords)
        };
    });
}

function compareDocumentOrder(left, right) {
    if (left.postId !== right.postId) {
        return left.postId - right.postId;
    }
    return (left.orderIndex || 0) - (right.orderIndex || 0);
}

function normalizeReferenceIds(referenceIds, documentsById) {
    return uniqueValues(referenceIds || []).filter(function (referenceId) {
        return !!documentsById[referenceId];
    }).sort(function (leftId, rightId) {
        const left = documentsById[leftId];
        const right = documentsById[rightId];
        if (left && right && left.postId !== right.postId) {
            return left.postId - right.postId;
        }
        return String(leftId).localeCompare(String(rightId));
    });
}

function pickPrimaryParentId(document, documentsById, opDocument) {
    const references = normalizeReferenceIds(document.referenceIds, documentsById)
        .map(function (referenceId) {
            return documentsById[referenceId];
        })
        .filter(function (referenceDocument) {
            return referenceDocument && compareDocumentOrder(referenceDocument, document) < 0;
        })
        .sort(function (left, right) {
            return compareDocumentOrder(right, left);
        });
    if (!references.length) {
        return opDocument.id;
    }
    return references[0].id;
}

function formatReferenceLabel(postId) {
    return '#' + postId;
}

function formatReferenceList(postIds, joiner) {
    return (postIds || []).map(function (postId) {
        return formatReferenceLabel(postId);
    }).join(joiner || ', ');
}

function buildReplyGroupLabel(clusterNode, keywords) {
    const referencePostIds = clusterNode.reference_post_ids || [];
    if (!referencePostIds.length) {
        return clusterNode.label || (keywords && keywords[0]) || 'Replies';
    }
    if (referencePostIds.length === 1) {
        return 'Replies to ' + formatReferenceLabel(referencePostIds[0]);
    }
    return 'Refs ' + formatReferenceList(referencePostIds, ' + ');
}

function buildReplyGroupSummary(clusterNode, keywords, sentiment, commentCount) {
    const intro = commentCount === 1 ? '1 comment' : commentCount + ' comments';
    const tone = summarizeSentiment(sentiment);
    const referencePostIds = clusterNode.reference_post_ids || [];
    if (!referencePostIds.length) {
        if (!keywords.length) {
            return intro + ' branch off the OP with a ' + tone + ' tone.';
        }
        return intro + ' branch off the OP around ' + keywords.slice(0, 3).join(', ') + ' with a ' + tone + ' tone.';
    }
    if (referencePostIds.length === 1) {
        if (!keywords.length) {
            return intro + ' reply to ' + formatReferenceLabel(referencePostIds[0]) + ' with a ' + tone + ' tone.';
        }
        return intro + ' reply to ' + formatReferenceLabel(referencePostIds[0]) + ' around ' + keywords.slice(0, 3).join(', ') + ' with a ' + tone + ' tone.';
    }
    if (!keywords.length) {
        return intro + ' connect ' + formatReferenceList(referencePostIds, ', ') + ' with a ' + tone + ' tone.';
    }
    return intro + ' connect ' + formatReferenceList(referencePostIds, ', ') + ' around ' + keywords.slice(0, 3).join(', ') + ' with a ' + tone + ' tone.';
}

function createCommentBranchNode(document, parentClusterId, childrenByParentId, documentsById, isOp) {
    const commentNode = {
        id: 'comment-' + document.id,
        document_id: document.id,
        post_id: document.postId,
        kind: isOp ? 'op' : 'comment',
        label: commentLeafLabel(document),
        cluster_id: parentClusterId || null,
        secondary_cluster_ids: document.secondaryClusterIds || [],
        text: document.text,
        keywords: document.topTerms,
        summary: snippet(document.text, 160),
        sentiment: document.sentiment,
        tfidfVector: document.vector,
        centroid: document.vector,
        color: document.color,
        reference_post_ids: document.referencePostIds || [],
        memberIds: [document.id],
        children: []
    };
    const childDocuments = (childrenByParentId[document.id] || []).slice().sort(compareDocumentOrder);
    commentNode.children = buildChildClusterNodes(
        document,
        childDocuments,
        childrenByParentId,
        documentsById,
        false
    );
    return commentNode;
}

function collectSubtreeDocumentIds(node) {
    const childIds = uniqueValues((node.children || []).reduce(function (accumulator, child) {
        return accumulator.concat(collectSubtreeDocumentIds(child));
    }, []));
    if ((node.kind === 'comment' || node.kind === 'op') && node.document_id) {
        return uniqueValues([node.document_id].concat(childIds));
    }
    return childIds;
}

function hydrateClusterMetrics(clusterNode, documentsById) {
    const memberIds = collectSubtreeDocumentIds(clusterNode);
    const members = memberIds.map(function (memberId) {
        return documentsById[memberId];
    }).filter(Boolean);
    const centroid = averageVectors(members.map(function (member) {
        return member.vector;
    }));
    const keywords = topTermNames(centroid, 8);
    const sentiment = members.length
        ? members.reduce(function (total, member) {
            return total + member.sentiment;
        }, 0) / members.length
        : 0;
    clusterNode.memberIds = memberIds;
    clusterNode.centroid = centroid;
    clusterNode.tfidfVector = centroid;
    clusterNode.keywords = keywords;
    clusterNode.sentiment = sentiment;
    if (clusterNode.cluster_type === 'semantic') {
        clusterNode.label = clusterNode.label || clusterDisplayLabel(clusterNode);
        clusterNode.summary = buildClusterSummary({
            memberIds: memberIds,
            sentiment: sentiment,
            isMisc: !!clusterNode.is_misc,
            isOutlier: !!clusterNode.is_outlier
        }, keywords);
        return clusterNode;
    }
    clusterNode.label = buildReplyGroupLabel(clusterNode, keywords);
    clusterNode.summary = buildReplyGroupSummary(clusterNode, keywords, sentiment, memberIds.length);
    return clusterNode;
}

function buildChildClusterNodes(parentDocument, childDocuments, childrenByParentId, documentsById, topLevel) {
    if (!childDocuments.length) {
        return [];
    }

    const unreferencedChildren = [];
    const referencedGroups = {};

    childDocuments.forEach(function (childDocument) {
        const referenceIds = normalizeReferenceIds(childDocument.referenceIds, documentsById);
        if (!referenceIds.length) {
            unreferencedChildren.push(childDocument);
            return;
        }
        const groupKey = referenceIds.join('|');
        if (!referencedGroups[groupKey]) {
            referencedGroups[groupKey] = {
                key: groupKey,
                referenceIds: referenceIds,
                referencePostIds: referenceIds.map(function (referenceId) {
                    return documentsById[referenceId].postId;
                }),
                documents: []
            };
        }
        referencedGroups[groupKey].documents.push(childDocument);
    });

    const clusterNodes = [];

    if (unreferencedChildren.length) {
        const semanticClusters = orderClustersBySimilarity(buildClusters(unreferencedChildren));
        semanticClusters.forEach(function (cluster, clusterIndex) {
            const clusterNode = {
                id: 'cluster-' + parentDocument.id + '-semantic-' + (clusterIndex + 1),
                kind: 'cluster',
                label: cluster.label || cluster.keywords[0] || cluster.id,
                cluster_id: cluster.id,
                keywords: cluster.keywords || [],
                summary: cluster.summary || '',
                sentiment: cluster.sentiment || 0,
                tfidfVector: cluster.centroid || {},
                centroid: cluster.centroid || {},
                is_misc: !!cluster.isMisc,
                is_outlier: !!cluster.isOutlier,
                cluster_type: 'semantic',
                reference_post_ids: [],
                parent_post_id: parentDocument.postId,
                band: !!topLevel,
                children: []
            };
            const orderedMembers = orderDocumentsBySimilarity(
                cluster.memberIds.map(function (memberId) {
                    return documentsById[memberId];
                }).filter(Boolean).sort(compareDocumentOrder),
                cluster.centroid
            );
            clusterNode.children = orderedMembers.map(function (member) {
                return createCommentBranchNode(member, clusterNode.id, childrenByParentId, documentsById, false);
            });
            hydrateClusterMetrics(clusterNode, documentsById);
            clusterNodes.push(clusterNode);
        });
    }

    Object.keys(referencedGroups).forEach(function (groupKey, groupIndex) {
        const group = referencedGroups[groupKey];
        const directCentroid = averageVectors(group.documents.map(function (document) {
            return document.vector;
        }));
        const clusterNode = {
            id: 'cluster-' + parentDocument.id + '-reply-' + (groupIndex + 1),
            kind: 'cluster',
            label: '',
            cluster_id: null,
            keywords: topTermNames(directCentroid, 8),
            summary: '',
            sentiment: 0,
            tfidfVector: directCentroid,
            centroid: directCentroid,
            is_misc: false,
            is_outlier: false,
            cluster_type: 'reply',
            reference_post_ids: group.referencePostIds,
            parent_post_id: parentDocument.postId,
            band: !!topLevel,
            children: []
        };
        const orderedMembers = orderDocumentsBySimilarity(
            group.documents.slice().sort(compareDocumentOrder),
            directCentroid
        );
        clusterNode.children = orderedMembers.map(function (member) {
            return createCommentBranchNode(member, clusterNode.id, childrenByParentId, documentsById, false);
        });
        hydrateClusterMetrics(clusterNode, documentsById);
        clusterNodes.push(clusterNode);
    });

    return orderClustersBySimilarity(clusterNodes);
}

function buildReferencedConversationTree(documents, globalKeywords, globalVector, conversationSentiment) {
    const root = {
        id: 'conversation-root',
        kind: 'root',
        label: 'Conversation',
        keywords: globalKeywords,
        summary: '',
        sentiment: conversationSentiment,
        tfidfVector: globalVector,
        children: []
    };
    if (!documents.length) {
        return {
            root: root,
            clusters: []
        };
    }

    const sortedDocuments = documents.slice().sort(compareDocumentOrder);
    const opDocument = sortedDocuments[0];
    const documentsById = {};
    sortedDocuments.forEach(function (document) {
        documentsById[document.id] = document;
    });

    const childrenByParentId = {};
    sortedDocuments.slice(1).forEach(function (document) {
        const parentId = pickPrimaryParentId(document, documentsById, opDocument);
        document.primaryParentId = parentId;
        if (!childrenByParentId[parentId]) {
            childrenByParentId[parentId] = [];
        }
        childrenByParentId[parentId].push(document);
    });

    Object.keys(childrenByParentId).forEach(function (parentId) {
        childrenByParentId[parentId].sort(compareDocumentOrder);
    });

    const opNode = createCommentBranchNode(opDocument, null, childrenByParentId, documentsById, true);
    opNode.summary = snippet(opDocument.text, 200);
    root.children.push(opNode);

    const topLevelClusters = opNode.children.filter(function (child) {
        return child.kind === 'cluster';
    });

    return {
        root: root,
        clusters: topLevelClusters
    };
}

function subtreeLeafCount(node, collapsedSet) {
    const collapsed = collapsedSet.has(node.id);
    if (!node.children || !node.children.length || collapsed) {
        return 1;
    }
    return node.children.reduce(function (total, child) {
        return total + subtreeLeafCount(child, collapsedSet);
    }, 0);
}

function computeDescendantMetadata(node) {
    const ownCommentIds = (node.kind === 'comment' || node.kind === 'op') ? [node.id] : [];
    const commentIds = ownCommentIds.slice();
    const keywordCounts = {};
    (node.keywords || []).forEach(function (keyword, index) {
        keywordCounts[keyword] = (keywordCounts[keyword] || 0) + (6 - index);
    });
    let sentimentTotal = (node.sentiment || 0) * ownCommentIds.length;
    let sentimentCount = ownCommentIds.length;
    if (!node.children || !node.children.length) {
        return {
            commentIds: commentIds,
            keywords: (node.keywords || []).slice(0, 8),
            sentiment: sentimentCount ? sentimentTotal / sentimentCount : (node.sentiment || 0)
        };
    }
    node.children.forEach(function (child) {
        const childMetadata = computeDescendantMetadata(child);
        child.__descendantMeta = childMetadata;
        childMetadata.commentIds.forEach(function (commentId) {
            commentIds.push(commentId);
        });
        (childMetadata.keywords || []).forEach(function (keyword, index) {
            keywordCounts[keyword] = (keywordCounts[keyword] || 0) + (6 - index);
        });
        sentimentTotal += childMetadata.sentiment * Math.max(1, childMetadata.commentIds.length);
        sentimentCount += Math.max(1, childMetadata.commentIds.length);
    });
    const keywords = Object.keys(keywordCounts).sort(function (left, right) {
        if (keywordCounts[right] !== keywordCounts[left]) {
            return keywordCounts[right] - keywordCounts[left];
        }
        return left.localeCompare(right);
    }).slice(0, 8);
    return {
        commentIds: commentIds,
        keywords: keywords,
        sentiment: sentimentCount ? sentimentTotal / sentimentCount : (node.sentiment || 0)
    };
}

function layoutTree(root, collapsedSet) {
    computeDescendantMetadata(root);
    const INNER_RADIUS = 44;
    const OUTER_RADIUS = 332;
    const nodes = [];
    const edges = [];
    const nodeMap = {};
    const descendantCommentIds = {};
    const visibleLeafNodes = [];

    function maxTreeDepth(node) {
        if (!node.children || !node.children.length) {
            return 0;
        }
        return 1 + node.children.reduce(function (maximum, child) {
            return Math.max(maximum, maxTreeDepth(child));
        }, 0);
    }

    const treeDepth = Math.max(1, maxTreeDepth(root));

    function nodeRadiusForDepth(node, depth, leaf) {
        if (node.kind === 'root') {
            return 0;
        }
        if ((node.kind === 'comment' || node.kind === 'op') && leaf) {
            return OUTER_RADIUS;
        }
        if (treeDepth <= 1) {
            return OUTER_RADIUS;
        }
        return INNER_RADIUS + (((depth - 1) / Math.max(1, treeDepth - 1)) * (OUTER_RADIUS - INNER_RADIUS));
    }

    function walk(node, depth, startAngle, endAngle, parent, inheritedTopClusterId) {
        const collapsed = collapsedSet.has(node.id);
        const leaf = !node.children || !node.children.length || collapsed;
        const radius = nodeRadiusForDepth(node, depth, leaf);
        let angle = (startAngle + endAngle) / 2;
        const topClusterId = node.band ? node.id : (inheritedTopClusterId || null);

        if (!leaf && node.children.length) {
            let cursor = startAngle;
            node.children.forEach(function (child) {
                const span = endAngle - startAngle;
                const share = subtreeLeafCount(child, collapsedSet) / subtreeLeafCount(node, collapsedSet);
                const childStart = cursor;
                const childEnd = cursor + (span * share);
                walk(child, depth + 1, childStart, childEnd, node, topClusterId);
                cursor = childEnd;
            });
            angle = (startAngle + endAngle) / 2;
        }

        const cartesianX = radius * Math.cos(angle - (Math.PI / 2));
        const cartesianY = radius * Math.sin(angle - (Math.PI / 2));
        const layoutNode = {
            id: node.id,
            kind: node.kind,
            label: node.label,
            radius: radius,
            angle: angle,
            x: cartesianX,
            y: cartesianY,
            depth: depth,
            leaf: leaf,
            collapsed: collapsed,
            startAngle: startAngle,
            endAngle: endAngle,
            band: !!node.band,
            topClusterId: topClusterId,
            keywords: node.__descendantMeta ? node.__descendantMeta.keywords : (node.keywords || []),
            summary: node.summary,
            sentiment: node.__descendantMeta ? node.__descendantMeta.sentiment : node.sentiment,
            color: sentimentColor(node.__descendantMeta ? node.__descendantMeta.sentiment : node.sentiment),
            commentIds: node.__descendantMeta ? node.__descendantMeta.commentIds : []
        };
        nodes.push(layoutNode);
        nodeMap[node.id] = layoutNode;
        descendantCommentIds[node.id] = layoutNode.commentIds;
        if (leaf) {
            visibleLeafNodes.push(layoutNode);
        }
        if (parent && nodeMap[parent.id]) {
            edges.push({
                id: parent.id + '->' + node.id,
                source: parent.id,
                target: node.id,
                topClusterId: topClusterId
            });
        }
    }

    walk(root, 0, 0, Math.PI * 2, null, null);
    return {
        nodes: nodes,
        edges: edges,
        nodeMap: nodeMap,
        descendantCommentIds: descendantCommentIds,
        visibleLeafNodes: visibleLeafNodes
    };
}

function buildSemanticThreadGraph(posts) {
    const documents = buildDocuments(posts);
    const globalVector = averageVectors(documents.map(function (document) {
        return document.vector;
    }));
    const globalKeywords = topTermNames(globalVector, 10);
    const conversationSentiment = documents.length
        ? documents.reduce(function (total, document) {
            return total + document.sentiment;
        }, 0) / documents.length
        : 0;
    const conversationProfile = averageSentimentProfiles(documents.map(function (document) {
        return document.sentimentProfile || emptySentimentProfile();
    }));
    const tree = buildReferencedConversationTree(
        documents,
        globalKeywords,
        globalVector,
        conversationSentiment
    );
    const conversationSummary = buildConversationSummary(
        documents,
        globalKeywords,
        tree.clusters,
        conversationSentiment,
        conversationProfile
    );
    tree.root.summary = conversationSummary;

    const graphNodes = [];
    const graphEdges = [];
    appendTreeToGraph(tree.root, null, graphNodes, graphEdges);

    const layout = layoutTree(tree.root, new Set());
    const clusterExport = tree.clusters.map(function (cluster) {
        return {
            id: cluster.id,
            label: cluster.label,
            keywords: cluster.keywords,
            centroid: cluster.centroid,
            summary: cluster.summary,
            sentiment: cluster.sentiment,
            comment_count: (cluster.memberIds || []).length,
            is_misc: !!cluster.is_misc,
            is_outlier: !!cluster.is_outlier
        };
    });

    const graph = {
        nodes: graphNodes.map(function (node) {
            return {
                id: node.id,
                text: node.text || '',
                cluster_id: node.cluster_id || null,
                subcluster_id: node.subcluster_id || null,
                sentiment: node.sentiment || 0,
                tfidf_vector: node.tfidfVector || {},
                kind: node.kind,
                label: node.label,
                keywords: node.keywords || [],
                summary: node.summary || '',
                secondary_cluster_ids: node.secondary_cluster_ids || [],
                band: !!node.band,
                is_misc: !!node.is_misc,
                is_outlier: !!node.is_outlier
            };
        }),
        edges: graphEdges,
        clusters: clusterExport
    };

    return {
        graph: graph,
        layout: {
            nodes: layout.nodes.map(function (node) {
                return {
                    id: node.id,
                    radius: node.radius,
                    angle: node.angle
                };
            })
        },
        summary: {
            conversation: conversationSummary,
            keywords: globalKeywords,
            sentiment: conversationSentiment,
            sentiment_profile: conversationProfile,
            sentiment_tone: summarizeSentiment(conversationSentiment, conversationProfile),
            clusters: clusterExport.map(function (cluster) {
                return {
                    id: cluster.id,
                    label: cluster.label,
                    summary: cluster.summary,
                    keywords: cluster.keywords,
                    sentiment: cluster.sentiment,
                    comment_count: cluster.comment_count,
                    is_misc: !!cluster.is_misc,
                    is_outlier: !!cluster.is_outlier
                };
            }),
            global_vector: globalVector
        },
        documents: documents,
        tree: tree.root
    };
}

export {
    buildSemanticThreadGraph,
    layoutTree,
    decorateHtmlWithSentiment,
    sentimentColor,
    scoreSelectionText,
    sentimentHighlightPalette,
    highlightableSentimentToken,
    normalizeTokenValue,
    stemToken,
    semanticTextForPost,
    stripHtml,
    snippet
};
