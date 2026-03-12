//go:build !linux || android

package bypass

// platformSetup is a no-op on platforms that manage bypass at the socket level
// (Windows: bind to physical IP; Darwin: IP_BOUND_IF; Android: VpnService.protect).
func (b *BypassDialer) platformSetup() error { return nil }

// platformCleanup is a no-op on non-Linux platforms.
func (b *BypassDialer) platformCleanup() {}
