//go:build android

package tun

import (
	"context"
	"fmt"
	"time"
	"unsafe"

	"ewp-core/log"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// Android TUN 设备实现
// 这个版本专门为 Android VPNService 设计
type Device struct {
	fd       int
	endpoint *Endpoint
	mtu      int
	name     string
	running  bool
}

// ifReq 结构体（与 device_linux.go 保持一致）
type ifReq struct {
	Name  [16]byte
	Flags uint16
	_     [16]byte
}

// NewDeviceFromFD 从 Android VPNService 的 ParcelFileDescriptor 创建设备
func NewDeviceFromFD(fd int, mtu int) (*Device, error) {
	if mtu <= 0 {
		mtu = 1500
	}

	if fd < 0 {
		return nil, fmt.Errorf("invalid file descriptor: %d", fd)
	}

	// 获取接口名称
	var ifr ifReq
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.TUNGETIFF), uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		return nil, fmt.Errorf("TUNGETIFF failed: %v", errno)
	}

	name := unix.ByteSliceToString(ifr.Name[:])
	log.Printf("[TUN-Android] TUN device from FD: %s (fd: %d, mtu: %d)", name, fd, mtu)

	return &Device{
		fd:      fd,
		mtu:     mtu,
		name:    name,
		running: false,
	}, nil
}

// Configure 配置网络接口（Android 版本）
// 在 Android 上，网络配置由 VPNService Builder 处理
func (d *Device) Configure(ip, gateway, mask, dns string) error {
	// Android VPNService 已经通过 Builder 配置了网络
	// 这里只需要记录配置信息
	log.Printf("[TUN-Android] Network configured by VPNService: IP=%s, Gateway=%s, Mask=%s, DNS=%s", 
		ip, gateway, mask, dns)
	return nil
}

// AttachEndpoint 附加端点
func (d *Device) AttachEndpoint(ep *Endpoint) {
	d.endpoint = ep
}

// Start 启动设备读写循环
func (d *Device) Start() {
	d.running = true
	log.Printf("[TUN-Android] Starting device loops for %s", d.name)
	
	go d.readLoop()
	go d.writeLoop()
}

// readLoop 读取循环（Android 版本）
func (d *Device) readLoop() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[TUN-Android] Read goroutine crashed: %v", r)
		}
	}()

	packetBuf := make([]byte, d.mtu)

	for d.running {
		// 从 TUN 设备读取数据包
		n, err := unix.Read(d.fd, packetBuf)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
				// 非阻塞模式，没有数据可读
				time.Sleep(1 * time.Millisecond)
				continue
			}
			
			if d.running {
				log.Printf("[TUN-Android] Read packet failed: %v", err)
				time.Sleep(100 * time.Millisecond)
			}
			continue
		}

		if n == 0 {
			continue
		}

		// 记录接收到的数据包
		if n >= 20 {
			version := packetBuf[0] >> 4
			protocol := packetBuf[9]
			srcIP := fmt.Sprintf("%d.%d.%d.%d", packetBuf[12], packetBuf[13], packetBuf[14], packetBuf[15])
			dstIP := fmt.Sprintf("%d.%d.%d.%d", packetBuf[16], packetBuf[17], packetBuf[18], packetBuf[19])
			
			if version == 4 {
				var srcPort, dstPort uint16
				if protocol == 6 && n >= 20+4 { // TCP
					srcPort = uint16(packetBuf[20])<<8 | uint16(packetBuf[21])
					dstPort = uint16(packetBuf[22])<<8 | uint16(packetBuf[23])
				} else if protocol == 17 && n >= 20+4 { // UDP
					srcPort = uint16(packetBuf[20])<<8 | uint16(packetBuf[21])
					dstPort = uint16(packetBuf[22])<<8 | uint16(packetBuf[23])
				}
				
				log.V("[TUN-Android] Packet: %s:%d -> %s:%d (proto: %d, size: %d)", 
					srcIP, srcPort, dstIP, dstPort, protocol, n)
			}
		}

		// 创建数据包缓冲区
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(packetBuf[:n]),
		})

		// 注入到网络栈
		if d.endpoint != nil {
			d.endpoint.InjectInbound(header.IPv4ProtocolNumber, pkt)
		}
		pkt.DecRef()
	}
}

// writeLoop 写入循环（Android 版本）
func (d *Device) writeLoop() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[TUN-Android] Write goroutine crashed: %v", r)
		}
	}()

	for d.running {
		// 从端点读取数据包
		if d.endpoint == nil {
			time.Sleep(10 * time.Millisecond)
			continue
		}

		pkt := d.endpoint.ReadContext(context.Background())
		if pkt == nil {
			continue
		}

		data := pkt.ToView().AsSlice()

		// 记录发送的数据包
		if len(data) >= 20 {
			version := data[0] >> 4
			protocol := data[9]
			srcIP := fmt.Sprintf("%d.%d.%d.%d", data[12], data[13], data[14], data[15])
			dstIP := fmt.Sprintf("%d.%d.%d.%d", data[16], data[17], data[18], data[19])
			
			if version == 4 {
				var srcPort, dstPort uint16
				if protocol == 6 && len(data) >= 20+4 { // TCP
					srcPort = uint16(data[20])<<8 | uint16(data[21])
					dstPort = uint16(data[22])<<8 | uint16(data[23])
				} else if protocol == 17 && len(data) >= 20+4 { // UDP
					srcPort = uint16(data[20])<<8 | uint16(data[21])
					dstPort = uint16(data[22])<<8 | uint16(data[23])
				}
				
				log.V("[TUN-Android] Send: %s:%d -> %s:%d (proto: %d, size: %d)", 
					srcIP, srcPort, dstIP, dstPort, protocol, len(data))
			}
		}

		// 写入到 TUN 设备
		_, err := unix.Write(d.fd, data)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
				// 非阻塞模式，缓冲区满
				time.Sleep(1 * time.Millisecond)
				pkt.DecRef()
				continue
			}
			
			if d.running {
				log.Printf("[TUN-Android] Write packet failed: %v", err)
			}
			pkt.DecRef()
			continue
		}

		pkt.DecRef()
	}
}

// Close 关闭设备（Android 版本）
func (d *Device) Close() error {
	log.Printf("[TUN-Android] Closing TUN device: %s", d.name)
	
	d.running = false

	// 注意：不要关闭 fd，因为它由 Android VPNService 管理
	// VPNService 会负责关闭 ParcelFileDescriptor
	d.fd = -1

	log.Printf("[TUN-Android] TUN device cleanup complete")
	return nil
}

// GetFD 获取文件描述符
func (d *Device) GetFD() int {
	return d.fd
}

// GetName 获取接口名称
func (d *Device) GetName() string {
	return d.name
}

// IsAdmin 检查权限（Android 版本）
func IsAdmin() bool {
	// Android VPN 权限通过 VPNService API 管理
	return true
}

// CleanupRouting 清理路由（Android 版本）
func CleanupRouting(gateway string) error {
	// Android 路由由 VPNService 管理
	log.Printf("[TUN-Android] Routing cleanup (handled by VPNService)")
	return nil
}

// ConfigureRouting 配置路由（Android 版本）
func ConfigureRouting(gateway string) error {
	// Android 路由由 VPNService 管理
	log.Printf("[TUN-Android] Routing configuration (handled by VPNService)")
	return nil
}

// NewDevice 创建设备（Android 版本，不推荐使用）
// 在 Android 上应该使用 NewDeviceFromFD
func NewDevice(mtu int) (*Device, error) {
	return nil, fmt.Errorf("use NewDeviceFromFD on Android")
}
