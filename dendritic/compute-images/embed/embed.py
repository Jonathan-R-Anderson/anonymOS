"""Deterministic embedding generation for the compute catalogue.

Reads /work/input.jsonl -- one JSON object per line, each with an "id" and a
"text" -- and writes /work/output.jsonl plus a digest on stdout.

THE STDOUT CONTRACT
-------------------
Exactly one line, and nothing else, ever:

    embed-digest sha256:<hex> count:<n>

backend/services/compute_verify.output_digest hashes stdout plus the exit code
and compares that between replicas. Stdout IS the verification surface, so a
stray print -- a progress bar, a warning, a library banner -- is not noise, it
is a disagreement between two honest nodes. Everything diagnostic goes to
stderr, which output_digest deliberately excludes.

EXIT CODES
----------
    0  success; the digest line is on stdout
    2  no /work/input.jsonl -- PLUMBING. The runner never delivered the file.
    3  a line is not a JSON object (line number on stderr)
    4  a line is missing "id" or "text" (line number on stderr)
    5  this container is not in a state that can produce comparable output

2 is kept for plumbing alone. The language images already exit 2 for "entrypoint
not found", so the site sees 2 as "the work never started"; a caller that cannot
tell that apart from "your data was malformed" retries a bad shard forever, or
blames a node for the runner's mistake. 3 and 4 are the submitter's problem and
say which line caused it.

WHY THE OUTPUT IS HEX AND NOT FLOATS
------------------------------------
The result has to be COMPARED, not read. Two replicas are checked by hashing
their output, so the serialisation has to be exactly reproducible -- and decimal
float formatting is not: repr() of a float32 promoted to float64 varies with
libc, and rounding to N places quietly discards the low bits that would have
revealed a genuine disagreement. Writing the raw little-endian float32 bytes as
hex sidesteps the question entirely: identical vectors produce identical text,
and any difference at all survives to the digest.

WHY THE DIGEST IS OVER THE FILE AND NOT COMPUTED PER-VECTOR
-----------------------------------------------------------
So that ORDER counts. A node that returned the right vectors against the wrong
ids would otherwise pass, and the id-to-vector mapping is the entire product.
Output order is input order, line for line: records are read into a list and
written in that order, never through a set or a dict.
"""

import hashlib
import json
import os
import sys

import numpy as np
import onnxruntime as ort
from tokenizers import Tokenizer

MODEL_DIR = os.environ.get("MODEL_DIR", "/opt/model")
INPUT = "/work/input.jsonl"
OUTPUT = "/work/output.jsonl"

# Exit codes, named so the reasons cannot drift apart from the docstring above.
EXIT_NO_INPUT = 2
EXIT_BAD_LINE = 3
EXIT_BAD_RECORD = 4
EXIT_NOT_DETERMINISTIC = 5

# Long inputs are TRUNCATED, not rejected. The model has a fixed window and a
# job whose corpus happens to contain one long document should produce a
# comparable result rather than failing the whole unit -- but the limit is
# stated here rather than left to the tokenizer's default, so that two nodes
# cannot disagree about where the cut falls.
MAX_TOKENS = 256


def _fail(code, message):
    sys.stderr.write(message + "\n")
    raise SystemExit(code)


def _session():
    # DETERMINISM, stated in code rather than trusted to defaults. Two nodes
    # must produce identical bytes or slice 1 verifies nothing: M5 compares
    # digests, so "nearly the same vector" is a disagreement, and M8 charges
    # that to an honest node's reputation.
    options = ort.SessionOptions()
    # A parallel float reduction sums in whatever order the threads finish, and
    # that order is not stable between machines -- or between two runs on one
    # machine. Single-threaded is slower and verifiable; threaded is faster and
    # worthless here.
    options.intra_op_num_threads = 1
    options.inter_op_num_threads = 1
    options.execution_mode = ort.ExecutionMode.ORT_SEQUENTIAL
    # Pinned explicitly, NOT left to ORT_DISABLE_ALL_OPTIMIZATION in the
    # environment: a level set by env var is a level a host can change under us.
    # BASIC and not ALL because ALL includes layout optimisations chosen from
    # the CPU's feature set, so an AVX-512 node and an AVX2 node would run
    # different graphs and honestly disagree.
    options.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_BASIC
    # Errors only. ORT's warnings name paths and timings; they belong nowhere
    # near stdout, whose entire content is the digest line.
    options.log_severity_level = 3

    session = ort.InferenceSession(
        os.path.join(MODEL_DIR, "onnx", "model.onnx"),
        sess_options=options,
        providers=["CPUExecutionProvider"],
    )

    # Assert the provider actually in use rather than the one requested. If this
    # image were ever rebuilt against onnxruntime-gpu, a CUDA provider would be
    # selected silently and its reductions are not reproducible -- the job would
    # succeed, return different bytes from every other replica, and look like
    # fraud. Refuse instead.
    providers = session.get_providers()
    if providers != ["CPUExecutionProvider"]:
        _fail(
            EXIT_NOT_DETERMINISTIC,
            "refusing to run: providers are %r, only CPUExecutionProvider is reproducible"
            % (providers,),
        )
    return session


def _records():
    """Every record, in file order.

    A list, not a dict keyed by id: duplicate ids are the submitter's business,
    and dict iteration order is one more thing two nodes could disagree about.
    Nothing on the digest path iterates a set or a dict, so the result does not
    depend on PYTHONHASHSEED -- the Dockerfile pins it to 0 as well, but that is
    belt and braces, not the reason this is safe.
    """
    if not os.path.exists(INPUT):
        # PLUMBING, not data. The runner never delivered the shard.
        _fail(EXIT_NO_INPUT, "no %s supplied" % INPUT)
    out = []
    with open(INPUT, "r", encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except ValueError:
                _fail(EXIT_BAD_LINE, "line %d is not JSON" % number)
            if not isinstance(row, dict):
                _fail(
                    EXIT_BAD_LINE,
                    "line %d is JSON but not an object; each line must be {\"id\":...,\"text\":...}"
                    % number,
                )
            if "id" not in row or "text" not in row:
                _fail(EXIT_BAD_RECORD, "line %d needs both 'id' and 'text'" % number)
            out.append((str(row["id"]), str(row["text"])))
    if not out:
        # Not an error: an empty shard hashes to the empty digest, which every
        # honest replica of an empty shard also produces. Said out loud on
        # stderr because it is far more often a mis-sharded job than an intent.
        sys.stderr.write("warning: %s contained no records\n" % INPUT)
    return out


def _embed(session, tokenizer, text):
    encoded = tokenizer.encode(text)
    ids = encoded.ids[:MAX_TOKENS]
    mask = [1] * len(ids)
    if not ids:
        # An empty string is legitimate input. Embedding nothing would divide by
        # a zero-length mask below, so it gets an explicit zero vector rather
        # than a NaN that would propagate into whatever consumes this.
        return np.zeros(_dim(session), dtype=np.float32)

    feed = {
        "input_ids": np.array([ids], dtype=np.int64),
        "attention_mask": np.array([mask], dtype=np.int64),
    }
    # get_inputs() is an ordered list; membership is tested by name, and the
    # feed is passed to ORT by key. No iteration order reaches the output.
    if any(i.name == "token_type_ids" for i in session.get_inputs()):
        feed["token_type_ids"] = np.zeros((1, len(ids)), dtype=np.int64)

    hidden = session.run(None, feed)[0]

    # Mean pooling over real tokens, then L2 normalisation -- what this model
    # family is trained for. Done in float32 throughout: promoting to float64
    # here would change the low bits relative to a node that did not.
    weights = np.array([mask], dtype=np.float32)[..., None]
    pooled = (hidden * weights).sum(axis=1) / weights.sum(axis=1)
    norm = np.linalg.norm(pooled, axis=1, keepdims=True)
    norm[norm == 0] = 1.0
    return (pooled / norm).astype(np.float32)[0]


def _dim(session):
    shape = session.get_outputs()[0].shape
    return int(shape[-1]) if isinstance(shape[-1], int) else 384


def main():
    records = _records()
    session = _session()
    tokenizer = Tokenizer.from_file(os.path.join(MODEL_DIR, "tokenizer.json"))

    digest = hashlib.sha256()
    with open(OUTPUT, "w", encoding="utf-8") as handle:
        # In input order. The digest is over the concatenated lines, so a node
        # that reordered them would produce a different hash even with every
        # vector correct -- which is the point.
        for identifier, text in records:
            vector = _embed(session, tokenizer, text)
            line = json.dumps(
                {
                    "id": identifier,
                    "dim": int(vector.shape[0]),
                    # Little-endian float32, hex-encoded. See the module
                    # docstring: this is for comparison, not for reading.
                    "vec": vector.astype("<f4").tobytes().hex(),
                },
                # sort_keys so the key order is the sorted order and not the
                # dict's; ensure_ascii so no locale or codec choice can change
                # a byte. Both are on the digest path.
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            )
            handle.write(line + "\n")
            digest.update(line.encode("ascii"))
            digest.update(b"\n")

    # The single line M5 compares between replicas. Nothing else may be written
    # to stdout, before or after it.
    sys.stdout.write("embed-digest sha256:%s count:%d\n" % (digest.hexdigest(), len(records)))


if __name__ == "__main__":
    main()
