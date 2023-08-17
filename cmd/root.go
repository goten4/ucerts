package cmd

import (
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/goten4/ucerts/internal/build"
	"github.com/goten4/ucerts/internal/config"
	"github.com/goten4/ucerts/internal/daemon"
	"github.com/goten4/ucerts/internal/logger"
	"github.com/goten4/ucerts/internal/watcher"
	"github.com/goten4/ucerts/pkg/tls"
)

func Execute() {
	cobra.OnInitialize(func() {
		logger.Init(logger.ShutdownFunc(daemon.Stop))
		config.Init()
	})

	rootCmd := &cobra.Command{
		Use: build.Name,
		Run: run,
	}

	rootCmd.PersistentFlags().StringP("config", "c", "", "provides the configuration file")
	_ = viper.BindPFlag("config", rootCmd.PersistentFlags().Lookup("config"))

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "print version and exit",
		Run:   printVersion,
	}

	rootCmd.AddCommand(versionCmd)

	if err := rootCmd.Execute(); err != nil {
		logger.Fail(err.Error())
	}
}

func printVersion(_ *cobra.Command, _ []string) {
	logger.Print(build.Info())
	os.Exit(0)
}

func run(_ *cobra.Command, _ []string) {
	defer daemon.Shutdown()

	daemon.PushGracefulStop(tls.Start())
	daemon.PushGracefulStop(watcher.Start())

	daemon.WaitForStop()
}
