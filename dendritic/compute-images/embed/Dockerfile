# Embedding-generation catalogue runtime — M10 slice 1.
#
# WHY THIS IS THE FIRST AI WORKLOAD
# ---------------------------------
# Not because it is the most exciting, but because it is the only one on the
# list that M5 can verify by hash equality. Two replicas either produce the same
# bytes or one of them is wrong, with no tolerance window to tune and no
# research problem to solve first. Everything harder waits behind it.
#
# DETERMINISM IS THE ENTIRE DESIGN CONSTRAINT
# -------------------------------------------
# An embedding model that produces *nearly* the same vector on two nodes is
# useless here: M5 compares digests, so "nearly" is a disagreement, which M8
# then charges to an honest node's reputation. Every choice below exists to make
# the output byte-identical rather than merely close:
#
#   * the base image is pinned by digest, not tag,
#   * the model is BAKED IN at build time, so no node fetches weights at run
#     time and no two nodes can end up on different revisions,
#   * ONNX Runtime rather than torch, because its CPU kernels do not reorder
#     reductions between runs the way a threaded BLAS does,
#   * single-threaded, because a parallel float reduction sums in whatever order
#     the threads finish, and that order is not stable between machines.
#
# The last point is the one that looks like a performance bug and is not.
# Multi-threading this image would make it faster and make its output
# unverifiable, which is a strictly worse trade for a paid network.
FROM python:3.12-slim@sha256:2be8daddbb82756f7d1f2c7ece706aadcb284bf6ab6d769ea695cc3ed6016743

# These are the environment's half of the bargain. The half that matters is in
# embed.py, which sets thread counts, execution mode, graph-optimisation level
# and execution provider on the session itself -- an env var is a setting a host
# can change under us, and the digest cannot afford that.
ENV PYTHONHASHSEED=0 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    LC_ALL=C \
    LANG=C \
    TZ=UTC \
    SOURCE_DATE_EPOCH=0 \
    OMP_NUM_THREADS=1 \
    MKL_NUM_THREADS=1 \
    OPENBLAS_NUM_THREADS=1 \
    ORT_DISABLE_ALL_OPTIMIZATION=0 \
    TOKENIZERS_PARALLELISM=false

# Versions pinned exactly. A floating onnxruntime is a floating set of CPU
# kernels, and a kernel change is an output change -- the same class of silent
# drift the base-image digest pin prevents.
RUN pip install --no-cache-dir \
        onnxruntime==1.19.2 \
        tokenizers==0.20.1 \
        numpy==2.1.2 \
        huggingface-hub==0.26.0

# The model, fetched ONCE at build time and pinned by revision. After this layer
# the image needs no network at all, which is what lets the runtime deny egress
# outright rather than allow-listing a model host.
#
# The two `test -f` checks are not paranoia: snapshot_download does NOT fail when
# allow_patterns match nothing, so a revision without the onnx export would build
# a green image whose every job dies at run time on a missing file -- on a
# volunteer's node, minutes into a paid unit. The failure belongs here.
ARG MODEL_REPO=sentence-transformers/all-MiniLM-L6-v2
ARG MODEL_REVISION=8b3219a92973c328a8e22fadcfa821b5dc75636a
ENV MODEL_DIR=/opt/model
RUN python3 -c "\
from huggingface_hub import snapshot_download; \
snapshot_download('${MODEL_REPO}', revision='${MODEL_REVISION}', \
    local_dir='${MODEL_DIR}', \
    allow_patterns=['onnx/model.onnx','tokenizer.json','config.json'])" \
    && test -f ${MODEL_DIR}/onnx/model.onnx \
    && test -f ${MODEL_DIR}/tokenizer.json \
    && find ${MODEL_DIR} -type f -exec chmod 0444 {} +

# Offline AFTER the fetch, never before. Setting these above the download turns
# the one step that legitimately needs the network into an immediate failure --
# which is exactly what happened the first time this image was built. From here
# on they are load-bearing: they guarantee a running job cannot reach out for a
# model, so the runtime can deny egress outright and two nodes cannot silently
# end up on different weights.
ENV HF_HUB_OFFLINE=1 \
    TRANSFORMERS_OFFLINE=1

RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin compute
USER 10001:10001
WORKDIR /work

COPY --chown=10001:10001 embed.py /usr/local/bin/embed.py
COPY --chown=10001:10001 run.sh /usr/local/bin/run
ENTRYPOINT ["/usr/local/bin/run"]
