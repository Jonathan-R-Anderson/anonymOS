-- Overlay-plane window rules (2026-09-27).
--
-- The Domain Manager's layout is fixed-pixel and does NOT reflow, so Hyprland correctly floats it
-- (min==max) — and a floating fixed-size window on the tiled workspace is exactly the "the Domain
-- Manager covers everything" problem.  Routing it to the special:overlay workspace (the SUPER+SPACE
-- overlay plane) keeps it OFF the tiled desktop.  The DM runs only in System and is never launched
-- into another domain, so its app_id is the plain "epin-domain-manager" (no @domain qualifier).
hl.window_rule({ match = { class = "^(epin-domain-manager)$" }, float     = true })
hl.window_rule({ match = { class = "^(epin-domain-manager)$" }, workspace = "special:overlay" })

-- PER-DOMAIN overlay for ordinary apps (terminal, monitor, calculator, …) is USER-CONFIGURABLE and
-- lives in the DM-generated custom/overlay.lua (sourced from hyprland.lua), NOT here.  Those apps set
-- a domain-qualified app_id "<base>@<domain>" (src/util/epin-appid.h), so a rule like
-- class:^(epin-calc@Work)$ can float them onto special:overlay in Work only.  Toggle it per app on
-- each domain's Applications tab in the Domain Manager.  Keeping the toggle's rules in the separate
-- generated file (not this blob-shipped file) means a DM write is never clobbered by the boot unpack.
