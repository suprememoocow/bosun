package main

import (
	"flag"
	"log/slog"
	"os"
	"strings"
)

// globalFlags holds flags common to every subcommand (design doc §8).
type globalFlags struct {
	config    string
	logLevel  string
	logFormat string
	noColor   bool
	allowCmd  bool
}

func registerGlobal(fs *flag.FlagSet) *globalFlags {
	g := &globalFlags{}
	fs.StringVar(&g.config, "config", "bosun.yaml", "path to the config file")
	fs.StringVar(&g.logLevel, "log-level", "info", "log level: debug, info, warn, error")
	fs.StringVar(&g.logFormat, "log-format", "text", "log format: text or json")
	fs.BoolVar(&g.noColor, "no-color", false, "disable coloured output")
	fs.BoolVar(&g.allowCmd, "allow-cmd", false, "enable ${cmd:...} secret expansion")
	return g
}

// logger builds the structured logger. Logs go to stderr so stdout carries only
// command output (plan diffs, JSON).
func (g *globalFlags) logger() *slog.Logger {
	var level slog.Level
	switch strings.ToLower(g.logLevel) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: level}
	var h slog.Handler
	if strings.ToLower(g.logFormat) == "json" {
		h = slog.NewJSONHandler(os.Stderr, opts)
	} else {
		h = slog.NewTextHandler(os.Stderr, opts)
	}
	return slog.New(h)
}
