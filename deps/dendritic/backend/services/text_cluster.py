import datetime as _datetime
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


ENV_STOPWORDS = {
    "about", "after", "amid", "among", "also", "been", "before", "being", "between", "could",
    "from", "have", "into", "over", "reports", "report", "says", "said", "that", "their",
    "there", "these", "this", "those", "through", "under", "were", "when", "where", "which",
    "while", "with", "would", "your", "more", "than", "what", "such", "still", "some",
}
DOMAIN_STOPWORDS = {
    "anonymous", "hacker", "hackers", "hacktivist", "hacktivists", "group", "collective",
    "cyber", "cyberattack", "attack", "attacks", "breach", "breaches", "leak", "leaks",
    "dark", "web", "crime", "cybercrime", "data", "security", "operation",
}
TOKEN_RE = re.compile(r"[a-z0-9]+")


def normalize_article_url(url):
    if not url:
        return ""
    split_url = urlsplit(url)
    kept_query = []
    for key, value in parse_qsl(split_url.query, keep_blank_values=True):
        if key.lower().startswith("utm_"):
            continue
        if key.lower() in {"fbclid", "gclid", "ocid", "guccounter"}:
            continue
        kept_query.append((key, value))
    return urlunsplit((
        split_url.scheme,
        split_url.netloc,
        split_url.path,
        urlencode(kept_query),
        split_url.fragment,
    ))


def cluster_articles(articles):
    normalized = []
    for article in sorted(
        articles,
        key=lambda item: article_value(item, "published_at") or _datetime.datetime.min,
        reverse=True,
    ):
        published_at = article_value(article, "published_at")
        if published_at is None:
            continue
        title = (article_value(article, "title") or "").strip()
        if not title:
            continue
        tokens = distinctive_tokens(article)
        if not tokens:
            tokens = plain_tokens("%s %s" % (title, article_value(article, "description") or ""))
        normalized.append({
            "article": article,
            "published_at": published_at,
            "tokens": tokens,
            "title_tokens": plain_tokens(title),
        })

    clusters = []
    for item in normalized:
        best_cluster = None
        best_score = 0.0
        for cluster in clusters:
            score = cluster_score(item, cluster)
            if score > best_score:
                best_score = score
                best_cluster = cluster
        if best_cluster is None or best_score < 2.6:
            clusters.append(new_cluster(item))
            continue
        add_to_cluster(best_cluster, item)

    return [cluster["articles"] for cluster in clusters]


def cluster_keywords(cluster):
    token_counts = {}
    for article in cluster:
        for token in distinctive_tokens(article):
            token_counts[token] = token_counts.get(token, 0) + 1
    return [
        token
        for token, _count in sorted(token_counts.items(), key=lambda item: (-item[1], item[0]))
        if token not in DOMAIN_STOPWORDS
    ][:8]


def article_value(article, key):
    if isinstance(article, dict):
        return article.get(key)
    return getattr(article, key)


def distinctive_tokens(article):
    text = " ".join(filter(None, (
        article_value(article, "title"),
        article_value(article, "description"),
        article_value(article, "content"),
        article_value(article, "keyword"),
    )))
    return {
        token
        for token in plain_tokens(text)
        if token not in ENV_STOPWORDS and token not in DOMAIN_STOPWORDS and len(token) >= 3
    }


def plain_tokens(text):
    return set(TOKEN_RE.findall((text or "").lower()))


def count_tokens(tokens):
    counts = {}
    for token in tokens:
        counts[token] = counts.get(token, 0) + 1
    return counts


def increment_counts(counts, tokens):
    for token in tokens:
        counts[token] = counts.get(token, 0) + 1


def new_cluster(item):
    return {
        "articles": [item["article"]],
        "token_counts": count_tokens(item["tokens"]),
        "title_counts": count_tokens(item["title_tokens"]),
        "latest": item["published_at"],
    }


def add_to_cluster(cluster, item):
    cluster["articles"].append(item["article"])
    cluster["latest"] = max(cluster["latest"], item["published_at"])
    increment_counts(cluster["token_counts"], item["tokens"])
    increment_counts(cluster["title_counts"], item["title_tokens"])


def cluster_score(item, cluster):
    if abs((cluster["latest"] - item["published_at"]).total_seconds()) > (96 * 3600):
        return 0.0
    cluster_tokens = set(cluster["token_counts"].keys())
    cluster_title_tokens = set(cluster["title_counts"].keys())
    shared_tokens = item["tokens"] & cluster_tokens
    shared_title_tokens = item["title_tokens"] & cluster_title_tokens
    if not shared_tokens and not shared_title_tokens:
        return 0.0
    union_size = len(item["tokens"] | cluster_tokens) or 1
    title_union_size = len(item["title_tokens"] | cluster_title_tokens) or 1
    jaccard = len(shared_tokens) / union_size
    title_jaccard = len(shared_title_tokens) / title_union_size
    longest_shared = max((len(token) for token in shared_tokens), default=0)
    return (
        (len(shared_tokens) * 1.1)
        + (len(shared_title_tokens) * 0.9)
        + (jaccard * 3.5)
        + (title_jaccard * 4.0)
        + (0.25 if longest_shared >= 7 else 0.0)
    )
