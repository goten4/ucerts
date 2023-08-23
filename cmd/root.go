package cmd

import (
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/goten4/ucerts/internal/build"
	"github.com/goten4/ucerts/internal/config"
	"github.com/goten4/ucerts/internal/daemon"
	"github.com/goten4/ucerts/internal/watcher"
	"github.com/goten4/ucerts/pkg/agent"
	"github.com/goten4/ucerts/pkg/manager"
)

func Execute() {
	cobra.OnInitialize(func() {
		logrus.RegisterExitHandler(daemon.GracefulStop)
		logrus.SetOutput(os.Stdout)
		config.Init()
	})

	rootCmd := &cobra.Command{
		Use: build.Name,
		Run: runManager,
	}

	rootCmd.PersistentFlags().StringP("config", "c", "", "provides the configuration file")
	_ = viper.BindPFlag("config", rootCmd.PersistentFlags().Lookup("config"))

	agentCmd := &cobra.Command{
		Use: "agent",
		Run: runAgent,
	}
	rootCmd.AddCommand(agentCmd)

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "print version and exit",
		Run:   version,
	}
	rootCmd.AddCommand(versionCmd)

	if err := rootCmd.Execute(); err != nil {
		logrus.Fatal(err.Error())
	}
}

func version(_ *cobra.Command, _ []string) {
	_, _ = fmt.Fprintf(os.Stdout, "Version: %s\n", build.Version)
	_, _ = fmt.Fprintf(os.Stdout, "Date: %s\n", build.BuiltAt)
	os.Exit(0)
}

func runManager(_ *cobra.Command, _ []string) {
	defer daemon.GracefulStop()

	daemon.PushGracefulStop(manager.Start())
	daemon.PushGracefulStop(watcher.Start())

	daemon.WaitForStop()
}

func runAgent(_ *cobra.Command, _ []string) {
	defer daemon.GracefulStop()

	daemon.PushGracefulStop(agent.Start(config.AgentGRPC))

	daemon.WaitForStop()
}
