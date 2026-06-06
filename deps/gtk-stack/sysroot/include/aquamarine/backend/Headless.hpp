#pragma once

#include "./Backend.hpp"
#include "../allocator/Swapchain.hpp"
#include "../output/Output.hpp"
#include "../input/Input.hpp"
#include <hyprutils/memory/WeakPtr.hpp>
#include <hyprutils/os/FileDescriptor.hpp>

namespace Aquamarine {
    class CBackend;
    class CHeadlessBackend;
    class IAllocator;

    // EpinAnonymOS GUI roadmap G3: the headless/sessionless backend has no
    // libinput/libseat path (no udev, no DRM session), so it bridges the kernel's
    // evdev-compatible PS/2 mouse device (/dev/input/event1) straight into an
    // aquamarine pointer.  Hyprland's input manager consumes it exactly like a
    // libinput pointer.
    class CHeadlessPointer : public IPointer {
      public:
        CHeadlessPointer(const std::string& name_) : name(name_) {}
        virtual ~CHeadlessPointer() {}
        virtual const std::string& getName() {
            return name;
        }

      private:
        std::string name;
    };

    // GUI roadmap G4: kernel evdev keyboard (/dev/input/event0) bridged into an
    // aquamarine keyboard, the same way CHeadlessPointer bridges the mouse.
    // Only key events are emitted; Hyprland derives modifiers via its own xkb
    // state, exactly as it does for a libinput keyboard.
    class CHeadlessKeyboard : public IKeyboard {
      public:
        CHeadlessKeyboard(const std::string& name_) : name(name_) {}
        virtual ~CHeadlessKeyboard() {}
        virtual const std::string& getName() {
            return name;
        }

      private:
        std::string name;
    };

    class CHeadlessOutput : public IOutput {
      public:
        virtual ~CHeadlessOutput();
        virtual bool                                                      commit();
        virtual bool                                                      test();
        virtual Hyprutils::Memory::CSharedPointer<IBackendImplementation> getBackend();
        virtual void                                                      scheduleFrame(const scheduleFrameReason reason = AQ_SCHEDULE_UNKNOWN);
        virtual bool                                                      destroy();
        virtual std::vector<SDRMFormat>                                   getRenderFormats();
        virtual bool                                                      pendingPageFlip();

        Hyprutils::Memory::CWeakPointer<CHeadlessOutput>                  self;

      private:
        CHeadlessOutput(const std::string& name_, Hyprutils::Memory::CWeakPointer<CHeadlessBackend> backend_);

        Hyprutils::Memory::CWeakPointer<CHeadlessBackend>        backend;

        Hyprutils::Memory::CSharedPointer<std::function<void()>> framecb;
        bool                                                     frameScheduled = false;
        bool                                                     watchdogScheduled = false;
        uint32_t                                                 activeRepaintTicks = 0;
        uint64_t                                                 frameSequence = 0;
        uint64_t                                                 presentSequence = 0;
        std::chrono::steady_clock::time_point                    lastFrame;
        std::chrono::steady_clock::time_point                    lastFrameRequest;
        std::chrono::steady_clock::time_point                    lastPresent;

        std::chrono::nanoseconds frameInterval();
        void                     emitFrame(const char* source);
        void                     armRepaintWatchdog();

        friend class CHeadlessBackend;
    };

    class CHeadlessBackend : public IBackendImplementation {
      public:
        virtual ~CHeadlessBackend();
        virtual eBackendType                                               type();
        virtual bool                                                       start();
        virtual std::vector<Hyprutils::Memory::CSharedPointer<SPollFD>>    pollFDs();
        virtual int                                                        drmFD();
        virtual bool                                                       dispatchEvents();
        virtual uint32_t                                                   capabilities();
        virtual bool                                                       setCursor(Hyprutils::Memory::CSharedPointer<IBuffer> buffer, const Hyprutils::Math::Vector2D& hotspot);
        virtual void                                                       onReady();
        virtual std::vector<SDRMFormat>                                    getRenderFormats();
        virtual std::vector<SDRMFormat>                                    getCursorFormats();
        virtual bool                                                       createOutput(const std::string& name = "");
        virtual Hyprutils::Memory::CSharedPointer<IAllocator>              preferredAllocator();
        virtual std::vector<Hyprutils::Memory::CSharedPointer<IAllocator>> getAllocators();
        virtual Hyprutils::Memory::CWeakPointer<IBackendImplementation>    getPrimary();

        Hyprutils::Memory::CWeakPointer<CHeadlessBackend>                  self;
        virtual int                                                        drmRenderNodeFD();

      private:
        CHeadlessBackend(Hyprutils::Memory::CSharedPointer<CBackend> backend_);

        Hyprutils::Memory::CWeakPointer<CBackend>                       backend;
        std::vector<Hyprutils::Memory::CSharedPointer<CHeadlessOutput>> outputs;

        size_t                                                          outputIDCounter = 0;

        class CTimer {
          public:
            std::chrono::steady_clock::time_point when;
            std::function<void(void)>             what;
            bool                                  expired();
        };

        struct {
            Hyprutils::OS::CFileDescriptor timerfd;
            std::vector<CTimer>            timers;
        } timers;

        void dispatchTimers();
        void updateTimerFD();
        void addTimer(std::chrono::steady_clock::time_point when, std::function<void(void)> what);
        void scheduleOutputs(IOutput::scheduleFrameReason reason);

        // EpinAnonymOS G3: kernel evdev mouse → aquamarine pointer bridge.
        Hyprutils::OS::CFileDescriptor                    mouseFD;
        Hyprutils::Memory::CSharedPointer<CHeadlessPointer> pointer;
        int32_t                                           accumDX = 0, accumDY = 0;
        void                                              initInput();
        void                                              dispatchInput();

        Hyprutils::OS::CFileDescriptor                     kbdFD;
        Hyprutils::Memory::CSharedPointer<CHeadlessKeyboard> keyboard;
        void                                               dispatchKeyboard();

        friend class CBackend;
        friend class CHeadlessOutput;
    };
};
