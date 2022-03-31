package logging

import (
	"flag"

	"github.com/hashicorp/go-hclog"
)

type LogOpts struct {
	LogLevel string
}

func (l *LogOpts) Flags() *flag.FlagSet {
	fs := flag.NewFlagSet("", flag.ContinueOnError)
	fs.StringVar(&l.LogLevel, "log-level", "INFO", "Log level for this command")
	return fs
}

func (l *LogOpts) Logger() hclog.Logger {
	return hclog.New(
		&hclog.LoggerOptions{
			Level: hclog.LevelFromString(l.LogLevel),
		},
	)
}

// https://github.com/hashicorp/consul/blob/64e35777e044a9c6122093067eacc871f440b7db/command/flags/merge.go
func Merge(dst, src *flag.FlagSet) {
	if dst == nil {
		panic("dst cannot be nil")
	}
	if src == nil {
		return
	}
	src.VisitAll(func(f *flag.Flag) {
		dst.Var(f.Value, f.Name, f.Usage)
	})
}
