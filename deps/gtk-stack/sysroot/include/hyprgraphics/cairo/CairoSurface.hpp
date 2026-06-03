#pragma once

#include <cstdint>
#include <cairo/cairo.h>
#include <hyprutils/math/Vector2D.hpp>

namespace Hyprgraphics {

    // A simple cairo surface wrapper. Will destroy the surface in the ~dtor.
    class CCairoSurface {
      public:
        CCairoSurface(cairo_surface_t* surf);
        ~CCairoSurface();

        CCairoSurface(CCairoSurface&&)                            = delete;
        CCairoSurface(const CCairoSurface&)                       = delete;
        CCairoSurface&            operator=(const CCairoSurface&) = delete;
        CCairoSurface&            operator=(CCairoSurface&&)      = delete;

        cairo_surface_t*          cairo();
        Hyprutils::Math::Vector2D size();
        int                       status();
        uint8_t*                  data();
        int                       stride();

      private:
        cairo_surface_t* pSurface = nullptr;
    };
};
