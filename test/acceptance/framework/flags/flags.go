package flags

import (
	"flag"
	"sync"

	"github.com/hashicorp/consul-ecs/test/acceptance/framework/config"
)

const (
	flagVar = "var"
)

type TestFlags struct {
	flagVars map[string]string

	flagNoCleanupOnFailure bool

	once sync.Once
}

func NewTestFlags() *TestFlags {
	t := &TestFlags{}
	t.once.Do(t.init)

	return t
}

func (t *TestFlags) init() {
	flag.Var((*FlagMapValue)(&t.flagVars), flagVar, "Set a variable in the Terraform configuration, e.g. -var foo=bar. This flag can be set multiple times.")

	flag.BoolVar(&t.flagNoCleanupOnFailure, "no-cleanup-on-failure", false,
		"If true, the tests will not clean up resources they create when they finish running."+
			"Note this flag must be run with -failfast flag, otherwise subsequent tests will fail.")
}

func (t *TestFlags) Validate() error {
	// todo: require certain vars
	return nil
}

func (t *TestFlags) TestConfigFromFlags() *config.TestConfig {
	return &config.TestConfig{
		Vars:               t.flagVars,
		NoCleanupOnFailure: t.flagNoCleanupOnFailure,
	}
}
