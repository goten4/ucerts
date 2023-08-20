package daemon

import (
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/goten4/ucerts/internal/build"
	"github.com/goten4/ucerts/internal/config"
)

var signals = make(chan os.Signal, 1)

var WaitForStop = func() {
	logrus.Infof("%s %s started", build.Name, build.Version)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(signals)
	for s := range signals {
		logrus.Infof("Signal %s received", s)
		go func() {
			<-time.After(config.ShutdownTimeout)
			os.Exit(1)
		}()
		return
	}
}

var GracefulStop = func() {
	callGracefulStops()
	logrus.Infof("%s stopped", build.Name)
}

func callGracefulStops() {
	if len(gracefulStops) == 0 {
		return
	}
	stop := PopGracefulStop()
	stop()
	callGracefulStops()
}

var gracefulStops []func()

func PopGracefulStop() func() {
	n := len(gracefulStops) - 1
	stop := gracefulStops[n]
	gracefulStops = gracefulStops[:n]
	return stop
}

func PushGracefulStop(f func()) {
	gracefulStops = append(gracefulStops, f)
}
