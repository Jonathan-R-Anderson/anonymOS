# Build the Identity Manager view module (roadmap/INSTALLER.md Phase 6 / §D3).
# Built as part of the cross-compiled Calamares against deps/qt-stack (static Qt6, musl).
calamares_add_plugin( identitymanager
    TYPE viewmodule
    EXPORT_MACRO PLUGINDLLEXPORT_PRO
    SOURCES
        IdentityManagerViewStep.cpp
    LINK_PRIVATE_LIBRARIES
        calamaresui
    SHARED_LIB
)
