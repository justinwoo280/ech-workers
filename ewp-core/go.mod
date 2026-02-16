module ewp-core

go 1.24.0

require (
	github.com/google/uuid v1.6.0
	github.com/gorilla/websocket v1.5.1
	github.com/quic-go/quic-go v0.59.0
	github.com/sagernet/sing v0.7.18
	github.com/sagernet/sing-tun v0.7.11
	github.com/xtaci/smux v1.5.53
	golang.org/x/crypto v0.47.0
	golang.org/x/net v0.49.0
	golang.org/x/sys v0.40.0
	google.golang.org/grpc v1.69.0-dev
	google.golang.org/protobuf v1.36.0
)

require (
	github.com/fsnotify/fsnotify v1.7.0 // indirect
	github.com/go-ole/go-ole v1.3.0 // indirect
	github.com/google/btree v1.1.3 // indirect
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/josharian/native v1.1.0 // indirect
	github.com/mdlayher/netlink v1.7.2 // indirect
	github.com/mdlayher/socket v0.4.1 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/sagernet/fswatch v0.1.1 // indirect
	github.com/sagernet/gvisor v0.0.0-20241123041152-536d05261cff // indirect
	github.com/sagernet/netlink v0.0.0-20240612041022-b9a21c07ac6a // indirect
	github.com/sagernet/nftables v0.3.0-beta.4 // indirect
	github.com/vishvananda/netns v0.0.4 // indirect
	go4.org/netipx v0.0.0-20231129151722-fdeea329fbba // indirect
	golang.org/x/exp v0.0.0-20240613232115-7f521ea00fb8 // indirect
	golang.org/x/sync v0.19.0 // indirect
	golang.org/x/text v0.33.0 // indirect
	golang.org/x/time v0.7.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240903143218-8af14fe29dc1 // indirect
)

// 排除旧版本的 genproto（防止依赖冲突）
exclude google.golang.org/genproto v0.0.0-20230110181048-76db0878b65f
