module drivers;

/// AnonymOS Drivers - Hardware device drivers
/// 
/// This module provides device drivers for:
/// - Block devices (AHCI, SATA)
/// - Network devices
/// - Input devices (keyboard, mouse, USB HID)
/// - Graphics devices (DRM, VirtIO GPU)
/// - PCI bus
/// - USB bus
/// - VirtIO devices

// Block device drivers
public import drivers.block.ahci;

// Network drivers
public import drivers.network.network;

// Input drivers
public import drivers.input.hid_keyboard;
public import drivers.input.hid_mouse;
public import drivers.input.usb_hid;

// Graphics drivers
public import drivers.graphics.drm;
public import drivers.graphics.virtio_gpu;

// Bus and infrastructure drivers
public import drivers.pci;
public import drivers.virtio;
public import drivers.io;
