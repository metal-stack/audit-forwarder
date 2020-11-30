package main

import (
	"time"

	"go.uber.org/zap"
	apiv1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	k8s "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"context"
	"os"
	"os/exec"
	"strings"

	"github.com/metal-stack/v"

	"github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	moduleName   = "audit-forwarder-controller"
	systemctlBin = "/bin/systemctl"
	namespace    = "kube-system"
	podname      = "kubernetes-audit-tailer"
	podport      = "24224"
	commandName  = "sleep"
	commandArgs  = "3600"
)

var rootCmd = &cobra.Command{
	Use:     moduleName,
	Short:   "a service that watches for an audit-tailer pod in the cluster and then starts the audit-forwarder with the right destination IP",
	Version: v.V.String(),
	Run: func(cmd *cobra.Command, args []string) {
		run()
	},
}

var logger *zap.SugaredLogger

func main() {
	zap, _ := zap.NewProduction()
	defer func() {
		_ = zap.Sync()
	}()
	logger = zap.Sugar()
	if err := rootCmd.Execute(); err != nil {
		logger.Error("Failed executing root command", "Error", err)
	}
}

func init() {
	viper.SetEnvPrefix("audit")
	homedir, err := homedir.Dir()
	if err != nil {
		logger.Fatal(err)
	}
	rootCmd.PersistentFlags().StringP("kubecfg", "k", homedir+"/.kube/config", "kubecfg path to the cluster to account")
	rootCmd.PersistentFlags().Duration("fetch-interval", 10*time.Second, "interval for checking availability of target")
	viper.AutomaticEnv()
	err = viper.BindPFlags(rootCmd.PersistentFlags())
	if err != nil {
		logger.Fatal(err)
	}
}

func run() {
	client, err := loadClient(viper.GetString("kubecfg"))
	if err != nil {
		logger.Errorw("Unable to connect to k8s", "Error", err)
		os.Exit(1)
	}

	fetchInterval := viper.GetDuration("fetch-interval")

	// initialising variables used in pod loop
	oldPodIP := ""
	var oldPodDate time.Time
	ctx, cancel := context.WithCancel(context.Background())
	forwarderKilled := make(chan struct{})

	logger.Infow("Initial old values", "oldPodIP", oldPodIP, "oldPodDate", oldPodDate)

	labelMap := map[string]string{"app": podname}
	opts := metav1.ListOptions{
		LabelSelector: labels.SelectorFromSet(labelMap).String(),
	}
	for {
		watcher, err := client.CoreV1().Pods(namespace).Watch(opts)
		if err != nil {
			logger.Errorw("Could not watch for pods", "Error", err)
			time.Sleep(fetchInterval)
			continue
		}
		for event := range watcher.ResultChan() {
			p, ok := event.Object.(*apiv1.Pod)
			if !ok {
				logger.Error("Unexpected type")
			}
			podIP := p.Status.PodIP
			logger.Infow("Pod change detected", "old IP", oldPodIP, "new IP", podIP)
			if podIP != "" && oldPodIP != podIP {
				podDate := p.Status.StartTime.Time
				logger.Infow("Pod dates", "old", oldPodDate, "new", podDate)
				if podDate.After(oldPodDate) {
					logger.Infow("Newer pod detected, (re-)starting forwarder")
					if oldPodIP != "" {
						logger.Infow("Killing old forwarder")
						cancel()
						// Wait for the old forwarder to exit
						<-forwarderKilled
						// Create new context
						ctx, cancel = context.WithCancel(context.Background())
					}

					go func() {
						for {

							logger.Info("Building forwarder command")

							cmd := exec.CommandContext(ctx, commandName, commandArgs)
							cmd.Stdout = os.Stdout // Lets us see stdout and stderr of cmd
							cmd.Stderr = os.Stderr
							cmd.Env = append(os.Environ(),
								"AUDIT_TAILER_HOST="+podIP,
								"AUDIT_TAILER_PORT="+podport,
							)
							logger.Infow("Executing:", "Command", strings.Join(cmd.Args, " "), ", Environment:", strings.Join(cmd.Env, ", "))

							err := cmd.Run()
							if err != nil {
								logger.Errorw("Forwarder exited", "Error", err)
							}
							// command is finished, now we check if it died or if it got canceled.
							select {
							case <-ctx.Done():
								logger.Infow("Old forwarder is killed, returning", "Error", ctx.Err())
								forwarderKilled <- struct{}{}
								return
							default:
								logger.Infow("Forwarder was not killed by this controller, restarting")
							}
						}
					}()

					oldPodIP = podIP
					oldPodDate = podDate
				}
			}
			logger.Info("Pod change handled")
		}
	}
}

func loadClient(kubeconfigPath string) (*k8s.Clientset, error) {
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	if err != nil {
		return nil, err
	}
	return k8s.NewForConfig(config)
}
