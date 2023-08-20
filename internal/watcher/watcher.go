package watcher

import (
	"github.com/fsnotify/fsnotify"
	"github.com/sirupsen/logrus"

	"github.com/goten4/ucerts/internal/config"
	"github.com/goten4/ucerts/internal/funcs"
	"github.com/goten4/ucerts/pkg/tls"
)

var (
	watcher *fsnotify.Watcher
)

func Start() funcs.Stop {
	var err error
	if watcher, err = fsnotify.NewWatcher(); err != nil {
		logrus.Fatalf("Failed to start TLS configs watcher: %v", err)
		return funcs.NoOp
	}
	stop := func() {
		if err := watcher.Close(); err != nil {
			logrus.Errorf("Failed to close TLS configs watcher: %v", err)
		}
	}

	go listenEvents()

	// Add TLS configs paths
	for _, path := range config.CertificateRequestsPaths {
		logrus.Infof("Watching for path %s", path)
		if err = watcher.Add(path); err != nil {
			logrus.Fatalf("Failed to add TLS config dir %s: %v", path, err)
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
				// Handle only files with compatible extension
				if _, err := config.GetExtension(event.Name); err == nil {
					tls.HandleCertificateRequestFile(event.Name)
				}
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			logrus.Errorf("Error while watching TLS configs: %v", err)
		}
	}
}
