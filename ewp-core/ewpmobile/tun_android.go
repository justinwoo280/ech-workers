//go:build android

package ewpmobile

import (
	"os"
	"sync"

	wgtun "golang.zx2c4.com/wireguard/tun"
)

// androidTunDevice implements wgtun.Device by reading/writing raw IP packets
// directly from the fd that Android VpnService hands us. It intentionally
// avoids any ioctl/netlink calls (no setMTU, no TUNGETIFF) because Android
// SELinux denies netlink_route_socket operations for untrusted apps.
// The interface is already fully configured (IP, MTU, routes) by VpnService.Builder.
type androidTunDevice struct {
	file      *os.File
	mtu       int
	events    chan wgtun.Event
	closeOnce sync.Once
}

func newAndroidTunDevice(file *os.File, mtu int) *androidTunDevice {
	dev := &androidTunDevice{
		file:   file,
		mtu:    mtu,
		events: make(chan wgtun.Event, 4),
	}
	dev.events <- wgtun.EventUp
	return dev
}

func (d *androidTunDevice) File() *os.File { return d.file }

// Read reads one IP packet per call (Android TUN fd is always single-packet).
func (d *androidTunDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	n, err := d.file.Read(bufs[0][offset:])
	if err != nil {
		return 0, err
	}
	sizes[0] = n
	return 1, nil
}

// Write writes each packet in the slice to the TUN fd sequentially.
func (d *androidTunDevice) Write(bufs [][]byte, offset int) (int, error) {
	for i, buf := range bufs {
		if _, err := d.file.Write(buf[offset:]); err != nil {
			return i, err
		}
	}
	return len(bufs), nil
}

func (d *androidTunDevice) MTU() (int, error) { return d.mtu, nil }

func (d *androidTunDevice) Name() (string, error) { return "vpn", nil }

func (d *androidTunDevice) Events() <-chan wgtun.Event { return d.events }

func (d *androidTunDevice) BatchSize() int { return 1 }

func (d *androidTunDevice) Close() error {
	var err error
	d.closeOnce.Do(func() {
		close(d.events)
		err = d.file.Close()
	})
	return err
}
