package manager

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
			LoadCertificateRequests()

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
