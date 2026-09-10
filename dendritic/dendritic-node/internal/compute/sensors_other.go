//go:build !linux

package compute

// Sensors on everything that is not Linux.
//
// Reports "do not know" for every reading, which the governor treats as a
// reason not to run. That is correct behaviour rather than a stub: the node
// targets Linux, and a developer running this on macOS should see work refused
// with an honest reason rather than have the governor guess their laptop is
// idle and cook it.

type LinuxSensors struct{}

func (LinuxSensors) LoadAverage1() float64 { return -1 }
func (LinuxSensors) OnBattery() bool       { return false }
func (LinuxSensors) HottestC() int         { return -1 }
func (LinuxSensors) GPUBusyPercent() int   { return -1 }
