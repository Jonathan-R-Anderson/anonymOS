#include "SurfaceState.hpp"
#include "helpers/Format.hpp"
#include "protocols/types/Buffer.hpp"
#include "render/Renderer.hpp"
#include "render/Texture.hpp"

Vector2D SSurfaceState::sourceSize() {
    if UNLIKELY (!texture)
        return {};

    if UNLIKELY (viewport.hasSource)
        return viewport.source.size();

    Vector2D trc = transform % 2 == 1 ? Vector2D{bufferSize.y, bufferSize.x} : bufferSize;
    return trc / scale;
}

CRegion SSurfaceState::accumulateBufferDamage() {
    if (damage.empty())
        return bufferDamage;

    CRegion surfaceDamage = damage;
    if (viewport.hasDestination) {
        Vector2D scale = sourceSize() / viewport.destination;
        surfaceDamage.scale(scale);
    }

    if (viewport.hasSource)
        surfaceDamage.translate(viewport.source.pos());

    Vector2D trc = transform % 2 == 1 ? Vector2D{bufferSize.y, bufferSize.x} : bufferSize;

    bufferDamage = surfaceDamage.scale(scale).transform(Math::wlTransformToHyprutils(Math::invertTransform(transform)), trc.x, trc.y).add(bufferDamage);
    damage.clear();
    return bufferDamage;
}

void SSurfaceState::updateSynchronousTexture(SP<Render::ITexture> lastTexture) {
    // EpinAnonymOS HOS path: the CPU-readback compositor (hosComposeShmWindows)
    // samples each client's wl_shm buffer directly via beginDataPtr() every frame,
    // so the GL texture mirror of a synchronous buffer is never read. Re-uploading
    // it on every commit is not just wasted work: Mesa swrast's GL dispatch table
    // is unusable on the compositor's main thread once worker threads have spawned,
    // so glTexSubImage2D inside CGLTexture::update() segfaults the event loop and
    // kills all input. Keep the texture object (mapping logic wants it non-null)
    // but skip the upload. HOS_SCENE_RENDER opts back into the real GL path.
    static const bool HOS_CPU_PATH = std::getenv("HOS_SCENE_RENDER") == nullptr;

    auto [dataPtr, fmt, size] = buffer->beginDataPtr(0);
    if (dataPtr) {
        auto drmFmt = NFormatUtils::shmToDRM(fmt);
        auto stride = bufferSize.y ? size / bufferSize.y : 0;
        if (lastTexture && lastTexture->m_isSynchronous && lastTexture->m_size == bufferSize) {
            texture = lastTexture;
            if (!HOS_CPU_PATH)
                texture->update(drmFmt, dataPtr, stride, accumulateBufferDamage());
        } else if (!HOS_CPU_PATH)
            texture = g_pHyprRenderer->createTexture(drmFmt, dataPtr, stride, bufferSize);
        else if (!texture)
            // First synchronous commit on the HOS path: we still need a non-null,
            // correctly-sized texture handle for map/geometry bookkeeping. The very
            // first createTexture runs before any worker thread exists, so its GL is
            // safe; later size changes simply re-bind the same handle (CPU compose
            // re-reads the resized buffer directly).
            texture = g_pHyprRenderer->createTexture(drmFmt, dataPtr, stride, bufferSize);
        else
            texture->m_size = bufferSize;
    }
    buffer->endDataPtr();
}

void SSurfaceState::reset() {
    updated.all = false;

    // After commit, there is no pending buffer until the next attach.
    buffer = {};

    // applies only to the buffer that is attached to the surface
    acquire = {};

    // wl_surface.commit assigns pending ... and clears pending damage.
    damage.clear();
    bufferDamage.clear();

    callbacks.clear();
    lockMask = LOCK_REASON_NONE;

    barrierSet    = false;
    surfaceLocked = false;
    fifoScheduled = false;

    pendingTimeout.reset();
    timer.reset(); // CEventLoopManager::nudgeTimers should handle it eventually
}

void SSurfaceState::updateFrom(SSurfaceState& ref) {
    updated = ref.updated;

    if (ref.updated.bits.buffer) {
        buffer     = ref.buffer;
        texture    = ref.texture;
        size       = ref.size;
        bufferSize = ref.bufferSize;
    }

    if (ref.updated.bits.damage) {
        damage       = ref.damage;
        bufferDamage = ref.bufferDamage;
    } else {
        // damage is always relative to the current commit
        damage.clear();
        bufferDamage.clear();
    }

    if (ref.updated.bits.input)
        input = ref.input;

    if (ref.updated.bits.opaque)
        opaque = ref.opaque;

    if (ref.updated.bits.offset)
        offset = ref.offset;

    if (ref.updated.bits.scale)
        scale = ref.scale;

    if (ref.updated.bits.transform)
        transform = ref.transform;

    if (ref.updated.bits.viewport)
        viewport = ref.viewport;

    if (ref.updated.bits.acquire)
        acquire = ref.acquire;

    if (ref.updated.bits.acked)
        ackedSize = ref.ackedSize;

    if (ref.updated.bits.frame) {
        callbacks.insert(callbacks.end(), std::make_move_iterator(ref.callbacks.begin()), std::make_move_iterator(ref.callbacks.end()));
        ref.callbacks.clear();
    }

    if (ref.barrierSet)
        barrierSet = ref.barrierSet;
}
