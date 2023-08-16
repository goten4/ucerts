package logger

import (
	"fmt"
	"io"
	"os"
)

type LogOption struct {
	apply func()
}

var (
	Shutdown func()
)

func Init(opts ...LogOption) {
	for _, opt := range opts {
		opt.apply()
	}
}

func ShutdownFunc(f func()) LogOption {
	return LogOption{func() { Shutdown = f }}
}

func Print(message string) {
	printMessage(os.Stdout, message)
}

func Printf(format string, args ...any) {
	printMessagef(os.Stdout, format, args...)
}

func Error(message string) {
	printMessage(os.Stderr, message)
}

func Errorf(format string, args ...any) {
	printMessagef(os.Stderr, format, args...)
}

func Fail(message string) {
	Error(message)
	Shutdown()
}

func Failf(format string, args ...any) {
	Errorf(format, args...)
	Shutdown()
}

func printMessage(out io.Writer, message string) {
	_, _ = fmt.Fprintf(out, "%s\n", message)
}

func printMessagef(out io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(out, fmt.Sprintf("%s\n", format), args...)
}
