/*
 * Copyright © 2011, 2012 Intel Corporation
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice (including the
 * next paragraph) shall be included in all copies or substantial
 * portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef _LIBINPUT_DEVICE_H_
#define _LIBINPUT_DEVICE_H_

#include "config.h"

#include <linux/input.h>
#include <wayland-util.h>
#include <libinput.h>
#include <stdbool.h>

#include <libweston/libweston.h>

enum evdev_device_seat_capability {
	EVDEV_SEAT_POINTER = (1 << 0),
	EVDEV_SEAT_KEYBOARD = (1 << 1),
	EVDEV_SEAT_TOUCH = (1 << 2),
	EVDEV_SEAT_TABLET = (1 << 3)
};

struct evdev_device {
	struct weston_seat *seat;
	enum evdev_device_seat_capability seat_caps;
	struct libinput_device *device;
	struct weston_touch_device *touch_device;
	struct wl_list link;
	struct weston_output *output;
	struct wl_listener output_destroy_listener;
	struct weston_tablet *tablet;
	char *output_name;
	int fd;
	bool override_wl_calibration;
	struct weston_log_pacer unknown_scroll_pacer;
};

void
evdev_led_update(struct evdev_device *device, enum weston_led leds);

/* anonymOS: RENAMED from evdev_device_create / evdev_device_destroy.
 *
 * libinput defines its OWN global evdev_device_create() and evdev_device_destroy()
 * (src/evdev.c), with different signatures and a different `struct evdev_device`.
 * Upstream that is harmless because libinput is a shared library and its copies stay
 * inside libinput.so -- but deps/weston/Makefile:198 patches libinput to build as a
 * static_library, so both definitions land in the same link unit (drm-backend.so).
 *
 * Static-archive resolution order then silently breaks libinput: weston's
 * libinput-device.c.o is linked before libinput.a, so by the time the linker reaches
 * libinput's path-seat.c.o the name is already defined and evdev.c.o is never pulled in
 * to satisfy it.  libinput's internal call lands in WESTON's function, which takes
 * (libinput_device *, weston_seat *) -- so it never opens /dev/input/event*, never runs
 * libevdev, and never queues LIBINPUT_EVENT_DEVICE_ADDED, yet returns non-NULL.  Verified
 * by disassembling the shipped drm-backend.so: path_device_enable+0x14a calls 0x30680,
 * which calls weston_seat_init_keyboard/weston_seat_add_tablet.  The visible symptom was
 * a compositor with no keyboard and no pointer ("no input devices found") on every boot,
 * via BOTH the udev and the path backend.
 *
 * Keep these names weston-prefixed so the collision cannot come back.
 */
struct evdev_device *
weston_evdev_device_create(struct libinput_device *libinput_device,
			   struct weston_seat *seat);

int
evdev_device_process_event(struct libinput_event *event);

void
evdev_device_set_output(struct evdev_device *device,
			struct weston_output *output);
void
weston_evdev_device_destroy(struct evdev_device *device);

void
evdev_notify_keyboard_focus(struct weston_seat *seat,
			    struct wl_list *evdev_devices);
void
evdev_device_set_calibration(struct evdev_device *device);

int
dispatch_libinput(struct libinput *libinput);

#endif /* _LIBINPUT_DEVICE_H_ */
