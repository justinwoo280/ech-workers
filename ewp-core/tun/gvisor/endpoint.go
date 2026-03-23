package gvisor

import (
	tun "golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type endpoint struct {
	tunDev     tun.Device
	mtu        uint32
	dispatcher stack.NetworkDispatcher
}

// newEndpoint wraps a wireguard-go tun.Device as a gvisor LinkEndpoint.
func newEndpoint(dev tun.Device, mtu uint32) (stack.LinkEndpoint, error) {
	return &endpoint{
		tunDev: dev,
		mtu:    mtu,
	}, nil
}

func (e *endpoint) MTU() uint32 {
	return e.mtu
}

func (e *endpoint) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityNone
}

func (e *endpoint) MaxHeaderLength() uint16 {
	return 0
}

func (e *endpoint) LinkAddress() tcpip.LinkAddress {
	return ""
}

func (e *endpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	pktsSlice := pkts.AsSlice()
	if len(pktsSlice) == 0 {
		return 0, nil
	}

	bufs := make([][]byte, len(pktsSlice))
	for i, pkt := range pktsSlice {
		view := pkt.ToView()
		data := view.AsSlice()
		buf := make([]byte, len(data))
		copy(buf, data)
		view.Release()
		bufs[i] = buf
	}

	if _, err := e.tunDev.Write(bufs, 0); err != nil {
		return 0, &tcpip.ErrAborted{}
	}
	return len(pktsSlice), nil
}

func (e *endpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.dispatcher = dispatcher
	if dispatcher == nil {
		return
	}

	go e.dispatchLoop()
}

func (e *endpoint) dispatchLoop() {
	// BatchSize reports the preferred number of packets to read per call.
	// For most platforms without GRO this is 1; Linux with vnetHdr can be 128.
	batchSize := e.tunDev.BatchSize()
	if batchSize <= 0 {
		batchSize = 1
	}

	// Pre-allocate buffer slices for the full batch.
	bufs := make([][]byte, batchSize)
	for i := range bufs {
		bufs[i] = make([]byte, e.mtu+4) // +4 for any platform headroom
	}
	sizes := make([]int, batchSize)

	for {
		// Read up to batchSize packets in one syscall.
		n, err := e.tunDev.Read(bufs, sizes, 0)
		if err != nil {
			return
		}

		for i := range n {
			if sizes[i] == 0 {
				continue
			}

			// sizes[i] is the actual byte count for packet i.
			payload := bufs[i][:sizes[i]]

			var protocol tcpip.NetworkProtocolNumber
			switch header.IPVersion(payload) {
			case header.IPv4Version:
				protocol = header.IPv4ProtocolNumber
			case header.IPv6Version:
				protocol = header.IPv6ProtocolNumber
			default:
				continue
			}

			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(payload),
			})
			e.dispatcher.DeliverNetworkPacket(protocol, pkt)
			pkt.DecRef()
			// MakeWithData -> NewViewWithData -> v.Write() 内部复制数据到新 chunk，
			// 原 bufs[i] 不被 gVisor 持有，可直接复用，无需重新 make。
		}
	}
}

func (e *endpoint) IsAttached() bool {
	return e.dispatcher != nil
}

func (e *endpoint) Wait() {}

func (e *endpoint) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareNone
}

func (e *endpoint) AddHeader(pkt *stack.PacketBuffer) {}

func (e *endpoint) ParseHeader(pkt *stack.PacketBuffer) bool { return true }

func (e *endpoint) Close() {}

func (e *endpoint) SetOnCloseAction(func()) {}

func (e *endpoint) SetLinkAddress(addr tcpip.LinkAddress) {}

func (e *endpoint) SetMTU(mtu uint32) { e.mtu = mtu }
