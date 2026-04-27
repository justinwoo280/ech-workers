// Package main is the unified ech-workers binary.
//
// It compiles to one executable that, depending on configuration,
// runs as: client (TUN/SOCKS5/HTTP inbound + ewpclient outbound),
// server (ewpserver inbound + direct outbound), or relay (both
// kinds of inbounds + ewpclient outbound for chaining).
//
// Configuration is YAML or JSON; see doc/EWP_V2.md §"engine config".
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"ewp-core/cmd/ewp/cfg"
	"ewp-core/common/stun"
	"ewp-core/engine"
	"ewp-core/inbound/ewpserver"
	"ewp-core/log"
	"ewp-core/outbound/direct"
)

// hasAnyEWPServerInbound reports whether any inbound is an ewpserver
// (only those care about STUN reflexive).
func hasAnyEWPServerInbound(c *cfg.File) bool {
	for _, in := range c.Inbounds {
		if in.Type == "ewpserver" {
			return true
		}
	}
	return false
}

func main() {
	configPath := flag.String("config", "engine.yaml", "engine config file (yaml or json)")
	logLevel := flag.String("log", "info", "log level: debug | info")
	probeNAT := flag.String("probe-nat", "", "diagnostic: send a UDP_PROBE_REQ via the default ewpclient outbound to the given STUN server (host:port) and print the reflexive address the server saw, then exit")
	flag.Parse()

	if *logLevel == "debug" {
		log.SetVerbose(true)
	}

	conf, err := cfg.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		os.Exit(2)
	}

	router, err := cfg.BuildRouter(conf.Router)
	if err != nil {
		fmt.Fprintf(os.Stderr, "router: %v\n", err)
		os.Exit(2)
	}

	eng := engine.New(router)

	// Build the shared server-side AsyncResolver, if dns.server.upstream
	// is configured. It will be attached to every direct outbound — those
	// are the only ones that need it; ewpclient outbounds do their own
	// resolution via the remote server's resolver.
	serverResolver := cfg.BuildAsyncResolver(conf.DNS.Server.Upstream)
	if serverResolver != nil {
		log.Printf("[ewp] DNS server resolver: %d DoH upstream(s), pool=%d",
			len(conf.DNS.Server.Upstream.Servers), conf.DNS.Server.Upstream.WorkerPool)
	}

	// Client DNS: privacy-preserving resolver used by ewpclient
	// outbounds to translate the upstream EWP server's domain name
	// into an IP at Dial time. Independent of serverResolver and
	// echBootstrap. Returns nil if user did not configure
	// `client_dns:`, in which case the OS resolver is used.
	clientResolver, err := cfg.BuildServerNameResolver(conf.ServerNameDNS)
	if err != nil {
		fmt.Fprintf(os.Stderr, "server_name_dns: %v\n", err)
		os.Exit(2)
	}
	if clientResolver != nil {
		log.Printf("[ewp] server-name DNS resolver: %d DoH upstream(s) for upstream-server lookup",
			len(conf.ServerNameDNS.DoH.Servers))
	}

	for _, oc := range conf.Outbounds {
		out, err := cfg.BuildOutbound(oc, conf.ECH.BootstrapDoH.Servers, clientResolver)
		if err != nil {
			fmt.Fprintf(os.Stderr, "outbound %q: %v\n", oc.Tag, err)
			os.Exit(2)
		}
		// If the outbound is a *direct.Outbound and we have a server
		// resolver, attach it. ewpclient outbounds resolve at the
		// remote end so they do not need it.
		if serverResolver != nil {
			if d, ok := out.(*direct.Outbound); ok {
				d.SetResolver(serverResolver)
				log.Printf("[ewp] outbound %q: AsyncResolver attached", oc.Tag)
			}
		}
		if err := eng.AddOutbound(out); err != nil {
			fmt.Fprintf(os.Stderr, "AddOutbound %q: %v\n", oc.Tag, err)
			os.Exit(2)
		}
	}

	// Optional reflexive address discovery: ask a few public STUN
	// servers what the world sees us as. The result is shared by all
	// ewpserver inbounds so PROBE_RESP can carry an honest answer.
	var reflexiveIP [16]byte
	var reflexivePort uint16
	var reflexiveSet, reflexiveIPv6 bool
	if len(conf.STUN.Servers) > 0 || hasAnyEWPServerInbound(conf) {
		stunCtx, stunCancel := context.WithTimeout(context.Background(), 3*time.Second)
		ref, err := stun.Discover(stunCtx, conf.STUN.Servers, "")
		stunCancel()
		if err == nil && ref.IP.IsValid() {
			if ref.IP.Is6() {
				reflexiveIP = ref.IP.As16()
				reflexiveIPv6 = true
			} else {
				v := ref.IP.As4()
				copy(reflexiveIP[12:16], v[:])
			}
			reflexivePort = ref.Port
			reflexiveSet = true
			log.Printf("[ewp] STUN reflexive: %s:%d (via %s)", ref.IP, ref.Port, ref.From)
		} else if err != nil {
			log.Printf("[ewp] STUN discover failed: %v (PROBE_RESP will fall back to per-sub default)", err)
		}
	}

	for _, ic := range conf.Inbounds {
		in, err := cfg.BuildInbound(ic)
		if err != nil {
			fmt.Fprintf(os.Stderr, "inbound %q: %v\n", ic.Tag, err)
			os.Exit(2)
		}
		// Plumb reflexive address into ewpserver inbounds.
		if reflexiveSet {
			if rs, ok := in.(*ewpserver.Inbound); ok {
				rs.SetReflexive(reflexiveIP, reflexivePort, reflexiveIPv6)
				log.Printf("[ewp] inbound %q: STUN reflexive attached", ic.Tag)
			}
		}
		if err := eng.AddInbound(in); err != nil {
			fmt.Fprintf(os.Stderr, "AddInbound %q: %v\n", ic.Tag, err)
			os.Exit(2)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		s := <-sigCh
		log.Printf("[ewp] caught %s, shutting down", s)
		cancel()
	}()

	if *probeNAT != "" {
		// Find the default ewpclient outbound (the one selected by
		// the static router), trigger one PROBE_REQ via it, print
		// the result and exit. Useful for "what NAT am I behind"
		// diagnostics on a freshly-deployed config.
		runProbeAndExit(ctx, eng, conf, *probeNAT)
		return
	}

	log.Printf("[ewp] starting engine with %d inbound(s) %d outbound(s)",
		len(conf.Inbounds), len(conf.Outbounds))

	if err := eng.Start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "engine: %v\n", err)
		os.Exit(1)
	}

	if err := eng.Close(); err != nil {
		log.Printf("[ewp] close: %v", err)
	}
}
