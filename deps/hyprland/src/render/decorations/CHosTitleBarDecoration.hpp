#pragma once

#include "IHyprWindowDecoration.hpp"
#include "../../devices/IPointer.hpp"
#include "../Texture.hpp"
#include <string>

// EpinAnonymOS: every window's titlebar -- the strip you drag a window by, with its minimize,
// maximize and close controls -- drawn by the compositor in the colour of the DOMAIN that owns
// the window.  The colour is the kernel's answer for the client's pid (/proc/<pid>/status
// "DomainColor", the identity colour the kernel used to paint as a border around each window),
// and the domain's name is written beside the title.
//
// It replaces the kernel-drawn identity border.  The guarantee is the same one the border gave:
// the bar lies outside the client's surface, so a program cannot paint over it or choose its
// colour -- a window can only ever show the colour of the domain it really runs in.
class CHosTitleBarDecoration : public IHyprWindowDecoration {
  public:
    CHosTitleBarDecoration(PHLWINDOW);
    virtual ~CHosTitleBarDecoration() = default;

    virtual SDecorationPositioningInfo getPositioningInfo();
    virtual void                       onPositioningReply(const SDecorationPositioningReply& reply);
    virtual void                       draw(PHLMONITOR, float const& a);
    virtual eDecorationType            getDecorationType();
    virtual void                       updateWindow(PHLWINDOW);
    virtual void                       damageEntire();
    virtual bool                       onInputOnDeco(const eInputType, const Vector2D&, std::any = {});
    virtual eDecorationLayer           getDecorationLayer();
    virtual uint64_t                   getDecorationFlags();
    virtual std::string                getDisplayName();

  private:
    CBox                 m_assignedBox = {0};
    PHLWINDOWREF         m_window;
    bool                 m_lastVisible = true;

    // The rendered title, rebuilt only when its text, colour or room changes.
    SP<Render::ITexture> m_titleTex;
    std::string          m_titleFor;
    uint32_t             m_titleColor = 0;
    int                  m_titleRoom  = 0;

    uint64_t             m_lastPressMs = 0;   // double-click on the bar = maximize

    bool                 visible();
    CBox                 assignedBoxGlobal();
    bool                 onButton(const Vector2D& pos, const IPointer::SButtonEvent& e);
    void                 minimize();
    void                 restore();
    void                 toggleMaximize();
};
