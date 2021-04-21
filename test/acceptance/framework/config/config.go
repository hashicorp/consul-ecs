package config

// TestConfig holds configuration for the test suite
type TestConfig struct {
	Vars               map[string]string
	NoCleanupOnFailure bool
}

func (t TestConfig) TFVars() map[string]interface{} {
	varsAsInterface := make(map[string]interface{})
	for k, v := range t.Vars {
		varsAsInterface[k] = v
	}
	return varsAsInterface
}
