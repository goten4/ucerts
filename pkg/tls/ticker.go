package tls

import (
	"time"

	"github.com/goten4/ucerts/internal/config"
	"github.com/goten4/ucerts/internal/funcs"
)

func Start() funcs.Stop {
	ticker := time.NewTicker(config.Interval)
	stop := make(chan struct{}, 1)

	go func() {
		for {
			for _, dir := range config.CertificateRequestsPaths {
				LoadCertificateRequests(dir)
			}

			select {
			case <-ticker.C:
				continue
			case <-stop:
				return
			}
		}
	}()

	return func() {
		ticker.Stop()
		stop <- struct{}{}
	}
}
