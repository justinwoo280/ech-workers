//go:build linux && !android

package tun

import (
	"context"
	"fmt"
	"os"
	"time"
	"unsafe"

	"ewp-core/log"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// Linux/Android TUN 设备实现
type Device struct {
	fd       int
	endpoint *Endpoint
	mtu      int
	name     string
	running  bool
}

const (
	TUNSETIFF     = 0x400454ca
	IFF_TUN       = 0x0001
	IFF_NO_PI     = 0x1000
	IFF_MULTI_QUEUE = 0x0100
)

type ifReq struct {
	Name  [16]byte
	Flags uint16
	_     [16]byte
}

// NewDevice 创建 Linux/Android TUN 设备
func NewDevice(mtu int) (*Device, error) {
	if mtu <= 0 {
		mtu = 1500
	}

	// 打开 /dev/net/tun 设备
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun failed: %w", err)
	}

	// 创建 TUN 接口
	var ifr ifReq
	copy(ifr.Name[:], "ewp-tun%d")
	ifr.Flags = IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE

	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(TUNSETIFF), uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		unix.Close(fd)
		return nil, fmt.Errorf("TUNSETIFF failed: %v", errno)
	}

	// 获取接口名称
	name := unix.ByteSliceToString(ifr.Name[:])
	log.Printf("[TUN] TUN device created: %s (fd: %d)", name, fd)

	return &Device{
		fd:      fd,
		mtu:     mtu,
		name:    name,
		running: false,
	}, nil
}

// Configure 配置网络接口
func (d *Device) Configure(ip, gateway, mask, dns string) error {
	// 设置 IP 地址
	if err := d.setAddress(ip, mask); err != nil {
		return fmt.Errorf("set address failed: %w", err)
	}

	// 设置网关
	if err := d.setGateway(gateway); err != nil {
		return fmt.Errorf("set gateway failed: %w", err)
	}

	// 设置 MTU
	if err := d.setMTU(d.mtu); err != nil {
		log.Printf("[TUN] Set MTU failed: %v", err)
	}

	// 启用接口
	if err := d.setUp(true); err != nil {
		return fmt.Errorf("set interface up failed: %w", err)
	}

	log.Printf("[TUN] Interface configured: IP=%s, Gateway=%s, Mask=%s", ip, gateway, mask)
	return nil
}

// setAddress 设置 IP 地址
func (d *Device) setAddress(ip, mask string) error {
	cmd := fmt.Sprintf("ip addr add %s/%s dev %s", ip, mask, d.name)
	if err := runCommand(cmd); err != nil {
		return fmt.Errorf("run command failed: %w", err)
	}
	log.Printf("[TUN] Address set: %s/%s", ip, mask)
	return nil
}

// setGateway 设置网关
func (d *Device) setGateway(gateway string) error {
	cmd := fmt.Sprintf("ip route add default via %s dev %s", gateway, d.name)
	if err := runCommand(cmd); err != nil {
		return fmt.Errorf("run command failed: %w", err)
	}
	log.Printf("[TUN] Gateway set: %s", gateway)
	return nil
}

// setMTU 设置 MTU
func (d *Device) setMTU(mtu int) error {
	cmd := fmt.Sprintf("ip link set dev %s mtu %d", d.name, mtu)
	if err := runCommand(cmd); err != nil {
		return fmt.Errorf("run command failed: %w", err)
	}
	log.Printf("[TUN] MTU set: %d", mtu)
	return nil
}

// setUp 设置接口状态
func (d *Device) setUp(up bool) error {
	state := "down"
	if up {
		state = "up"
	}
	cmd := fmt.Sprintf("ip link set dev %s %s", d.name, state)
	if err := runCommand(cmd); err != nil {
		return fmt.Errorf("run command failed: %w", err)
	}
	log.Printf("[TUN] Interface set %s", state)
	return nil
}

// AttachEndpoint 附加端点
func (d *Device) AttachEndpoint(ep *Endpoint) {
	d.endpoint = ep
}

// Start 启动设备读写循环
func (d *Device) Start() {
	d.running = true
	log.Printf("[TUN] Starting device loops for %s", d.name)
	
	go d.readLoop()
	go d.writeLoop()
}

// readLoop 读取循环
func (d *Device) readLoop() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[TUN] Read goroutine crashed: %v", r)
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
				log.Printf("[TUN] Read packet failed: %v", err)
				time.Sleep(100 * time.Millisecond)
			}
			continue
		}

		if n == 0 {
			continue
		}

		// 创建数据包缓冲区
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(packetBuf[:n]),
		})

		// 注入到网络栈
		d.endpoint.InjectInbound(header.IPv4ProtocolNumber, pkt)
		pkt.DecRef()
	}
}

// writeLoop 写入循环
func (d *Device) writeLoop() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[TUN] Write goroutine crashed: %v", r)
		}
	}()

	for d.running {
		// 从端点读取数据包
		pkt := d.endpoint.ReadContext(context.Background())
		if pkt == nil {
			continue
		}

		data := pkt.ToView().AsSlice()

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
				log.Printf("[TUN] Write packet failed: %v", err)
			}
			pkt.DecRef()
			continue
		}

		pkt.DecRef()
	}
}

// Close 关闭设备
func (d *Device) Close() error {
	log.Printf("[TUN] Closing TUN device: %s", d.name)
	
	d.running = false

	if d.fd >= 0 {
		unix.Close(d.fd)
		d.fd = -1
		log.Printf("[TUN] TUN device closed")
	}

	log.Printf("[TUN] TUN device cleanup complete")
	return nil
}

// GetFD 获取文件描述符（用于 Android）
func (d *Device) GetFD() int {
	return d.fd
}

// GetName 获取接口名称
func (d *Device) GetName() string {
	return d.name
}

// runCommand 执行系统命令（Linux 版本）
func runCommand(cmd string) error {
	log.Printf("[TUN] Executing: %s", cmd)
	
	// 使用 sh -c 执行命令
	parts := []string{"/bin/sh", "-c", cmd}
	process, err := os.StartProcess(parts[0], parts, &os.ProcAttr{
		Files: []*os.File{os.Stdin, os.Stdout, os.Stderr},
	})
	
	if err != nil {
		return fmt.Errorf("start process failed: %w", err)
	}
	
	// 等待进程完成
	state, err := process.Wait()
	if err != nil {
		return fmt.Errorf("wait process failed: %w", err)
	}
	
	if !state.Success() {
		return fmt.Errorf("command failed with exit code: %d", state.ExitCode())
	}
	
	return nil
}

// IsAdmin 检查是否有管理员权限（Linux/Android 版本）
func IsAdmin() bool {
	// 在 Android 上，VPN 权限通过 VPNService API 管理
	// 不需要传统的管理员权限
	return true
}

// CleanupRouting 清理路由（Linux/Android 版本）
func CleanupRouting(gateway string) error {
	// 在 Android 上，路由由 VPNService 管理
	// 不需要手动清理
	log.Printf("[TUN] Routing cleanup (handled by VPNService)")
	return nil
}

// ConfigureRouting 配置路由（Linux/Android 版本）
func ConfigureRouting(gateway string) error {
	// 在 Android 上，路由由 VPNService 管理
	// 不需要手动配置
	log.Printf("[TUN] Routing configuration (handled by VPNService)")
	return nil
}


