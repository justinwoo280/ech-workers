package tls

import "crypto/tls"

type ClientOptions struct {
	ServerName   string
	UseMozillaCA bool
	EnableECH    bool
	ECHList      []byte
	EnablePQC    bool
	ECHManager   *ECHManager
}

func NewClient(options ClientOptions) (Config, error) {
	if !options.EnableECH {
		return NewSTDConfig(options.ServerName, options.UseMozillaCA, options.EnablePQC), nil
	}

	if len(options.ECHList) > 0 {
		return NewSTDECHConfig(options.ServerName, options.UseMozillaCA, options.ECHList, options.EnablePQC), nil
	}

	if options.ECHManager != nil {
		echList, err := options.ECHManager.Get()
		if err != nil {
			return nil, err
		}
		cfg := NewSTDECHConfig(options.ServerName, options.UseMozillaCA, echList, options.EnablePQC)
		return &ManagedECHConfig{
			STDECHConfig: cfg,
			manager:      options.ECHManager,
		}, nil
	}

	return NewSTDConfig(options.ServerName, options.UseMozillaCA, options.EnablePQC), nil
}

type ManagedECHConfig struct {
	*STDECHConfig
	manager *ECHManager
}

func (c *ManagedECHConfig) Clone() Config {
	cloned := c.STDECHConfig.Clone().(*STDECHConfig)
	return &ManagedECHConfig{
		STDECHConfig: cloned,
		manager:      c.manager,
	}
}

// TLSConfig returns a fresh clone with the latest ECH config list from the
// manager. Every Dial() gets its own *tls.Config so concurrent connections
// never share a mutable struct (P0-8).
func (c *ManagedECHConfig) TLSConfig() (*tls.Config, error) {
	echList, err := c.manager.Get()
	if err != nil {
		// Fall back to the list that was embedded at creation time.
		return c.STDECHConfig.TLSConfig()
	}
	cfg := c.config.Clone()
	cfg.EncryptedClientHelloConfigList = echList
	return cfg, nil
}
