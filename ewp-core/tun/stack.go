package tun

import (
	"fmt"

	"ewp-core/log"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

type Endpoint = channel.Endpoint

type Stack struct {
	stack    *stack.Stack
	endpoint *Endpoint
}

func NewStack(mtu int, gateway string) (*Stack, error) {
	if mtu <= 0 {
		mtu = 1500
	}

	endpoint := channel.New(512, uint32(mtu), "")

	st := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
			ipv6.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
		},
	})

	if err := st.CreateNIC(1, endpoint); err != nil {
		return nil, fmt.Errorf("create NIC failed: %v", err)
	}

	gatewayIP := parseIPv4(gateway)
	st.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFrom4([4]byte{gatewayIP[0], gatewayIP[1], gatewayIP[2], gatewayIP[3]}),
			PrefixLen: 24,
		},
	}, stack.AddressProperties{})

	subnet, _ := tcpip.NewSubnet(tcpip.AddrFrom4([4]byte{0, 0, 0, 0}), tcpip.MaskFromBytes([]byte{0, 0, 0, 0}))
	st.SetRouteTable([]tcpip.Route{
		{
			Destination: subnet,
			NIC:         1,
		},
	})

	st.SetPromiscuousMode(1, true)
	st.SetSpoofing(1, true)

	log.Printf("[TUN] Network stack initialized")

	return &Stack{
		stack:    st,
		endpoint: endpoint,
	}, nil
}

func (s *Stack) Endpoint() *Endpoint {
	return s.endpoint
}

func (s *Stack) Stack() *stack.Stack {
	return s.stack
}
