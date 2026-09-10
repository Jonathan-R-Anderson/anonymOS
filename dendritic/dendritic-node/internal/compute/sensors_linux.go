//go:build linux

package compute

// The machine-state sensors the governor reads, from procfs and sysfs.
//
// Every one returns a "do not know" value rather than a guess, because the
// governor treats not-knowing as a reason to stop. That is the right split of
// responsibility: sensors report, the policy decides what ignorance means.

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// LinuxSensors reads live machine state.
type LinuxSensors struct{}

// LoadAverage1 returns the 1-minute run-queue depth, or -1 if unreadable.
//
// Load average rather than instantaneous CPU percentage on purpose: it counts
// runnable AND uninterruptible tasks, so a machine thrashing on I/O reads as
// busy. A user waiting on a slow disk is using their machine just as much as
// one waiting on the CPU, and instantaneous idle-percentage would call that
// moment free.
func (LinuxSensors) LoadAverage1() float64 {
	text, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return -1
	}
	fields := strings.Fields(string(text))
	if len(fields) == 0 {
		return -1
	}
	value, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return -1
	}
	return value
}

// OnBattery reports whether the machine is running on battery.
//
// False when there is no battery at all, which is the desktop and server case
// and must not read as "discharging". The distinction matters: a policy that
// pauses on battery would otherwise pause forever on every machine without
// one — the machines most able to do this work.
func (LinuxSensors) OnBattery() bool {
	// The AC adapter is the authority when present: it says whether power is
	// coming in, which is the actual question, and does not depend on a
	// battery's own reporting quirks.
	adapters, _ := filepath.Glob("/sys/class/power_supply/*/type")
	for _, typePath := range adapters {
		kind, err := os.ReadFile(typePath)
		if err != nil || strings.TrimSpace(string(kind)) != "Mains" {
			continue
		}
		online, err := os.ReadFile(filepath.Join(filepath.Dir(typePath), "online"))
		if err != nil {
			continue
		}
		return strings.TrimSpace(string(online)) == "0"
	}

	// No mains adapter listed. Fall back to any battery's own status.
	batteries, _ := filepath.Glob("/sys/class/power_supply/*/status")
	for _, statusPath := range batteries {
		status, err := os.ReadFile(statusPath)
		if err != nil {
			continue
		}
		if strings.TrimSpace(string(status)) == "Discharging" {
			return true
		}
	}
	return false
}

// HottestC returns the highest thermal-zone reading in Celsius, or -1.
//
// The hottest zone rather than an average or the CPU package: whichever
// component is closest to its limit is the one that will throttle, and it is
// not always the one being asked to work.
func (LinuxSensors) HottestC() int {
	zones, _ := filepath.Glob("/sys/class/thermal/thermal_zone*/temp")
	hottest := -1
	for _, zone := range zones {
		raw, err := os.ReadFile(zone)
		if err != nil {
			continue
		}
		milli, err := strconv.Atoi(strings.TrimSpace(string(raw)))
		if err != nil {
			continue
		}
		celsius := milli / 1000
		// Sensors that are unplugged or unsupported report absurd values —
		// 0, negatives, or tens of thousands. Believing one either stops all
		// work forever or silently disables the ceiling.
		if celsius <= 0 || celsius > 150 {
			continue
		}
		if celsius > hottest {
			hottest = celsius
		}
	}
	return hottest
}

// GPUBusyPercent returns 0-100, or -1 when nothing reports it.
//
// This catches what input-idleness cannot: somebody four hours into a
// fullscreen game has touched no key for minutes and is using their machine as
// hard as it gets.
//
// Only sysfs is read — no vendor tool is invoked. This runs on a short timer,
// and spawning nvidia-smi every interval is its own small tax on the machine
// we are trying not to disturb. amdgpu and i915 expose the counter directly;
// NVIDIA does not, so a machine with only an NVIDIA card falls back to the load
// check, which does catch a game's CPU thread.
func (LinuxSensors) GPUBusyPercent() int {
	candidates, _ := filepath.Glob("/sys/class/drm/card[0-9]*/device/gpu_busy_percent")
	busiest := -1
	for _, path := range candidates {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		percent, err := strconv.Atoi(strings.TrimSpace(string(raw)))
		if err != nil || percent < 0 || percent > 100 {
			continue
		}
		if percent > busiest {
			busiest = percent
		}
	}
	return busiest
}
