// Copyright 2021 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

// LoggerInterface is where a Logger writes debug output. Its methods match
// Print and Printf of the standard library's *log.Logger.
type LoggerInterface interface {
	Print(v ...any)
	Printf(format string, v ...any)
}

// Logger writes debug output to a LoggerInterface. The zero Logger discards
// everything. For verbose logging to stdout:
//
//	x.Logger = NewLogger(log.New(os.Stdout, "", 0))
type Logger struct {
	logger LoggerInterface
}

// NewLogger returns a Logger writing to logger; a nil logger disables logging.
func NewLogger(logger LoggerInterface) Logger {
	return Logger{
		logger: logger,
	}
}

// Print writes to the logger, if one is set.
func (l *Logger) Print(v ...any) {
	if l.logger != nil {
		l.logger.Print(v...)
	}
}

// Printf writes to the logger, if one is set.
func (l *Logger) Printf(format string, v ...any) {
	if l.logger != nil {
		l.logger.Printf(format, v...)
	}
}

// enabled reports whether a logger is set. Print and Printf arguments are
// evaluated and boxed even when it is not, so per-request call sites check
// enabled first.
func (l *Logger) enabled() bool {
	return l.logger != nil
}
