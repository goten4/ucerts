package watcher

import (
	"github.com/fsnotify/fsnotify"

	"github.com/goten4/ucerts/internal/config"
	"github.com/goten4/ucerts/internal/funcs"
	"github.com/goten4/ucerts/internal/logger"
	"github.com/goten4/ucerts/pkg/tls"
)

var (
	watcher *fsnotify.Watcher
)

func Start() funcs.Stop {
	var err error
	if watcher, err = fsnotify.NewWatcher(); err != nil {
		logger.Failf("Failed to start TLS configs watcher: %v", err)
		return funcs.NoOp
	}
	stop := func() {
		if err := watcher.Close(); err != nil {
			logger.Errorf("Failed to close TLS configs watcher: %v", err)
		}
	}

	go listenEvents()

	// Add TLS configs paths
	for _, path := range config.TLSConfigPaths {
		logger.Printf("Watching for path %s", path)
		if err = watcher.Add(path); err != nil {
			logger.Failf("Failed to add TLS config dir %s: %v", path, err)
		}
	}

	return stop
}

func listenEvents() {
	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if event.Has(fsnotify.Write) {
				tls.Load(event.Name)
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			logger.Errorf("Error while watching TLS configs:", err)
		}
	}
}
