import axios from 'axios';

// Same-origin, no CSRF (matches /api/v1/live). Both are best-effort: callers must
// tolerate rejection, since the client always has an in-bundle LM fallback score.

// Fetch persisted per-word scores for the words in the current selection.
// Resolves to { scores: { word: { score, magnitude, categories, source,
// hit_count, confident } } }.
export async function fetchWordScores(words) {
    const payload = { words: Array.isArray(words) ? words : [] };
    if (!payload.words.length) {
        return { scores: {} };
    }
    const response = await axios.post('/api/v1/sentiment/scores', payload);
    return response && response.data ? response.data : { scores: {} };
}

// Fire-and-forget: persist/learn scores from a chunk of text.
export function learnWords(text) {
    const value = typeof text === 'string' ? text : '';
    if (!value.trim()) {
        return Promise.resolve({ learned: 0 });
    }
    return axios
        .post('/api/v1/sentiment/learn', { text: value })
        .then(function (response) {
            return response && response.data ? response.data : { learned: 0 };
        })
        .catch(function () {
            return { learned: 0 };
        });
}
