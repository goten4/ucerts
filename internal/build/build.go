package build

import (
	"fmt"
	"runtime"
)

var (
	Name      = "ucerts"
	GoVersion = runtime.Version()
	Version   = "snapshot"
	BuiltAt   = ""
)

var Info = func() string {
	info := Version + " built"
	if BuiltAt != "" {
		info += fmt.Sprintf(" at %s", BuiltAt)
	}
	return fmt.Sprintf("%s using %s", info, GoVersion)
}
