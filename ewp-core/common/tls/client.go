package tls

type ClientOptions struct {
	ServerName string
	EnableECH  bool
	ECHList    []byte
	EnablePQC  bool
	ECHManager *ECHManager
}

func NewClient(options ClientOptions) (Config, error) {
	if !options.EnableECH {
		return NewSTDConfig(options.ServerName, options.EnablePQC), nil
	}

	if len(options.ECHList) > 0 {
		return NewSTDECHConfig(options.ServerName, options.ECHList, options.EnablePQC), nil
	}

	if options.ECHManager != nil {
		echList, err := options.ECHManager.Get()
		if err != nil {
			return nil, err
		}
		cfg := NewSTDECHConfig(options.ServerName, echList, options.EnablePQC)
		return &ManagedECHConfig{
			STDECHConfig: cfg,
			manager:      options.ECHManager,
		}, nil
	}

	return NewSTDConfig(options.ServerName, options.EnablePQC), nil
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
