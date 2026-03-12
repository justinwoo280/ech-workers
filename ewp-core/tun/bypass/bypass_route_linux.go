//go:build linux && !android

package bypass

import (
	"encoding/binary"
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	bypassRouteTable = 252 // custom routing table (avoids main=254, local=255, default=253)
	bypassRulePrio   = 100 // ip rule priority

	// FRA_* routing rule attributes (linux/fib_rules.h)
	fraFwmark   = 10
	fraFwmask   = 16
	fraTable    = 15
	fraPriority = 6
	frActToTbl  = 1 // FR_ACT_TO_TBL
)

// nlAttr builds a netlink attribute (header + data) padded to 4-byte alignment.
func nlAttr(attrType uint16, data []byte) []byte {
	hdrLen := 4 // sizeof(struct rtattr)
	total := hdrLen + len(data)
	padded := (total + 3) &^ 3
	b := make([]byte, padded)
	binary.NativeEndian.PutUint16(b[0:2], uint16(total))
	binary.NativeEndian.PutUint16(b[2:4], attrType)
	copy(b[4:], data)
	return b
}

func nlAttrU32(t uint16, v uint32) []byte {
	d := make([]byte, 4)
	binary.NativeEndian.PutUint32(d, v)
	return nlAttr(t, d)
}

// netlinkDo opens a NETLINK_ROUTE socket, sends one message, and waits for ACK.
// body is the fixed-size header (struct rtmsg / fib_rule_hdr).
// attrs are the variable-length attribute blobs to append.
func netlinkDo(msgType uint16, flags uint16, body []byte, attrs ...[]byte) error {
	sock, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return fmt.Errorf("netlink socket: %w", err)
	}
	defer unix.Close(sock)

	attrTotal := 0
	for _, a := range attrs {
		attrTotal += len(a)
	}
	msgLen := unix.SizeofNlMsghdr + len(body) + attrTotal
	buf := make([]byte, (msgLen+3)&^3)

	binary.NativeEndian.PutUint32(buf[0:4], uint32(msgLen))
	binary.NativeEndian.PutUint16(buf[4:6], msgType)
	binary.NativeEndian.PutUint16(buf[6:8], flags)
	binary.NativeEndian.PutUint32(buf[8:12], 1) // seq
	binary.NativeEndian.PutUint32(buf[12:16], 0) // pid

	off := unix.SizeofNlMsghdr
	copy(buf[off:], body)
	off += len(body)
	for _, a := range attrs {
		copy(buf[off:], a)
		off += len(a)
	}

	sa := &unix.SockaddrNetlink{Family: unix.AF_NETLINK}
	if err := unix.Sendto(sock, buf[:msgLen], 0, sa); err != nil {
		return fmt.Errorf("netlink send: %w", err)
	}

	resp := make([]byte, 4096)
	n, _, err := unix.Recvfrom(sock, resp, 0)
	if err != nil {
		return fmt.Errorf("netlink recv: %w", err)
	}
	msgs, err := syscall.ParseNetlinkMessage(resp[:n])
	if err != nil {
		return fmt.Errorf("netlink parse: %w", err)
	}
	for _, m := range msgs {
		if m.Header.Type == unix.NLMSG_ERROR {
			errno := int32(binary.NativeEndian.Uint32(m.Data[:4]))
			if errno != 0 {
				return syscall.Errno(-errno)
			}
		}
	}
	return nil
}

// rtmsgBody builds the 12-byte struct rtmsg / fib_rule_hdr body.
// Fields: [family, dst_len, src_len, tos, table, proto/res1, scope/res2, type/action, flags(4)]
func rtmsgBody(family, table, proto, scope, typ uint8) []byte {
	b := make([]byte, unix.SizeofRtMsg) // 12 bytes
	b[0] = family
	b[4] = table
	b[5] = proto
	b[6] = scope
	b[7] = typ
	return b
}

// netlinkAddRule: ip rule add fwmark <mark> lookup <table> prio <prio> (IPv4 or IPv6)
func netlinkAddRule(family uint8, mark, table, prio uint32) error {
	body := rtmsgBody(family, unix.RT_TABLE_UNSPEC, 0, 0, frActToTbl)
	attrs := [][]byte{
		nlAttrU32(fraPriority, prio),
		nlAttrU32(fraFwmark, mark),
		nlAttrU32(fraFwmask, 0xFFFFFFFF),
		nlAttrU32(fraTable, table),
	}
	flags := uint16(unix.NLM_F_REQUEST | unix.NLM_F_ACK | unix.NLM_F_CREATE)
	err := netlinkDo(unix.RTM_NEWRULE, flags, body, attrs...)
	if err == syscall.EEXIST {
		return nil
	}
	return err
}

// netlinkDelRule: ip rule del fwmark <mark> lookup <table>
func netlinkDelRule(family uint8, mark, table, prio uint32) error {
	body := rtmsgBody(family, unix.RT_TABLE_UNSPEC, 0, 0, frActToTbl)
	attrs := [][]byte{
		nlAttrU32(fraPriority, prio),
		nlAttrU32(fraFwmark, mark),
		nlAttrU32(fraFwmask, 0xFFFFFFFF),
		nlAttrU32(fraTable, table),
	}
	err := netlinkDo(unix.RTM_DELRULE,
		uint16(unix.NLM_F_REQUEST|unix.NLM_F_ACK), body, attrs...)
	if err == syscall.ENOENT {
		return nil
	}
	return err
}

// netlinkAddRoute: ip route add default dev <iface> table <table> (IPv4 or IPv6)
func netlinkAddRoute(family uint8, ifIndex, table uint32) error {
	body := rtmsgBody(family, unix.RT_TABLE_UNSPEC, unix.RTPROT_BOOT, unix.RT_SCOPE_UNIVERSE, unix.RTN_UNICAST)
	attrs := [][]byte{
		nlAttrU32(unix.RTA_TABLE, table),
		nlAttrU32(unix.RTA_OIF, ifIndex),
	}
	flags := uint16(unix.NLM_F_REQUEST | unix.NLM_F_ACK | unix.NLM_F_CREATE)
	err := netlinkDo(unix.RTM_NEWROUTE, flags, body, attrs...)
	if err == syscall.EEXIST {
		return nil
	}
	return err
}

// netlinkDelRoute: ip route del default table <table>
func netlinkDelRoute(family uint8, ifIndex, table uint32) error {
	body := rtmsgBody(family, unix.RT_TABLE_UNSPEC, unix.RTPROT_BOOT, unix.RT_SCOPE_UNIVERSE, unix.RTN_UNICAST)
	attrs := [][]byte{
		nlAttrU32(unix.RTA_TABLE, table),
		nlAttrU32(unix.RTA_OIF, ifIndex),
	}
	err := netlinkDo(unix.RTM_DELROUTE,
		uint16(unix.NLM_F_REQUEST|unix.NLM_F_ACK), body, attrs...)
	if err == syscall.ENOENT {
		return nil
	}
	return err
}

// platformSetup adds policy routing so that sockets marked with bypassFWMark
// are routed through the physical NIC, bypassing the TUN default route.
//
// Equivalent to:
//
//	ip route add default dev <iface> table 252
//	ip rule  add fwmark 0xEC011 lookup 252 prio 100   (IPv4 + IPv6)
func (b *BypassDialer) platformSetup() error {
	iface := b.iface
	idx := uint32(iface.Index)

	if err := netlinkAddRoute(unix.AF_INET, idx, bypassRouteTable); err != nil {
		return fmt.Errorf("add bypass IPv4 route: %w", err)
	}
	if err := netlinkAddRule(unix.AF_INET, bypassFWMark, bypassRouteTable, bypassRulePrio); err != nil {
		_ = netlinkDelRoute(unix.AF_INET, idx, bypassRouteTable)
		return fmt.Errorf("add bypass IPv4 rule: %w", err)
	}
	// IPv6 is best-effort; some environments may lack IPv6.
	_ = netlinkAddRoute(unix.AF_INET6, idx, bypassRouteTable)
	_ = netlinkAddRule(unix.AF_INET6, bypassFWMark, bypassRouteTable, bypassRulePrio)
	return nil
}

// platformCleanup removes the routing rule and route added by platformSetup.
func (b *BypassDialer) platformCleanup() {
	idx := uint32(b.iface.Index)
	_ = netlinkDelRule(unix.AF_INET, bypassFWMark, bypassRouteTable, bypassRulePrio)
	_ = netlinkDelRule(unix.AF_INET6, bypassFWMark, bypassRouteTable, bypassRulePrio)
	_ = netlinkDelRoute(unix.AF_INET, idx, bypassRouteTable)
	_ = netlinkDelRoute(unix.AF_INET6, idx, bypassRouteTable)
}
