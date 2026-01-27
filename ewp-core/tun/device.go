package tun

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"ewp-core/log"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type Device struct {
	adapter  *wintun.Adapter
	session  wintun.Session
	endpoint *Endpoint
	mtu      int
}

func NewDevice(mtu int) (*Device, error) {
	adapter, err := wintun.CreateAdapter("ECH-TUN", "WireGuard", nil)
	if err != nil {
		return nil, fmt.Errorf("create TUN adapter failed: %w", err)
	}
	log.Printf("[TUN] Adapter created")

	session, err := adapter.StartSession(0x800000)
	if err != nil {
		adapter.Close()
		return nil, fmt.Errorf("start session failed: %w", err)
	}
	log.Printf("[TUN] Session started")

	if mtu <= 0 {
		mtu = 1500
	}

	return &Device{
		adapter: adapter,
		session: session,
		mtu:     mtu,
	}, nil
}

func (d *Device) Configure(ip, gateway, mask, dns string) error {
	interfaceName := "ECH-TUN"

	cmd := exec.Command("netsh", "interface", "ip", "set", "address",
		fmt.Sprintf("name=%s", interfaceName),
		"source=static",
		fmt.Sprintf("addr=%s", ip),
		fmt.Sprintf("mask=%s", mask),
		fmt.Sprintf("gateway=%s", gateway))

	if output, err := cmd.CombinedOutput(); err != nil {
		log.Printf("[TUN] netsh config failed: %s (admin required)", output)
		return fmt.Errorf("configure network interface failed, run as admin: %w", err)
	}

	log.Printf("[TUN] Interface config: IP=%s, Gateway=%s, Mask=%s", ip, gateway, mask)

	cmd = exec.Command("netsh", "interface", "ip", "set", "dns",
		fmt.Sprintf("name=%s", interfaceName),
		"source=static",
		fmt.Sprintf("addr=%s", dns))
	cmd.Run()

	log.Printf("[TUN] DNS set: %s", dns)

	if d.mtu > 0 {
		cmd = exec.Command("netsh", "interface", "ipv4", "set", "subinterface",
			interfaceName,
			fmt.Sprintf("mtu=%d", d.mtu),
			"store=persistent")
		if output, err := cmd.CombinedOutput(); err != nil {
			log.Printf("[TUN] Set IPv4 MTU failed: %v (%s)", err, output)
		} else {
			log.Printf("[TUN] MTU set: %d", d.mtu)
		}
		cmd = exec.Command("netsh", "interface", "ipv6", "set", "subinterface",
			interfaceName,
			fmt.Sprintf("mtu=%d", d.mtu),
			"store=persistent")
		_, _ = cmd.CombinedOutput()
	}

	return nil
}

func (d *Device) AttachEndpoint(ep *Endpoint) {
	d.endpoint = ep
}

func (d *Device) Start() {
	go d.readLoop()
	go d.writeLoop()
}

func (d *Device) readLoop() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[TUN] Read goroutine crashed: %v", r)
		}
	}()

	packetBuf := make([]byte, d.mtu)

	for {
		packet, err := d.session.ReceivePacket()
		if err != nil {
			errStr := err.Error()
			if err == windows.ERROR_NO_MORE_ITEMS ||
				strings.Contains(errStr, "No more data is available") ||
				strings.Contains(errStr, "ERROR_NO_MORE_ITEMS") {
				time.Sleep(1 * time.Millisecond)
				continue
			}
			log.Printf("[TUN] Receive packet failed: %v", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}

		n := copy(packetBuf, packet)

		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(packetBuf[:n]),
		})

		d.endpoint.InjectInbound(header.IPv4ProtocolNumber, pkt)
		pkt.DecRef()
	}
}

func (d *Device) writeLoop() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[TUN] Write goroutine crashed: %v", r)
		}
	}()

	for {
		pkt := d.endpoint.ReadContext(context.Background())
		if pkt == nil {
			continue
		}

		data := pkt.ToView().AsSlice()

		packet, err := d.session.AllocateSendPacket(len(data))
		if err != nil {
			log.Printf("[TUN] Allocate send buffer failed: %v", err)
			pkt.DecRef()
			continue
		}

		copy(packet, data)
		d.session.SendPacket(packet)
		pkt.DecRef()
	}
}

func (d *Device) Close() error {
	log.Printf("[TUN] Cleaning up TUN resources...")

	if d.session != (wintun.Session{}) {
		d.session.End()
		log.Printf("[TUN] Session closed")
	}

	if d.adapter != nil {
		d.adapter.Close()
		log.Printf("[TUN] Adapter closed")
	}

	log.Printf("[TUN] TUN resource cleanup complete")
	return nil
}
