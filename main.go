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
	moduleName   = "audit-tailer-controller"
	systemctlBin = "/bin/systemctl"
	namespace    = "kube-system"
	podname      = "kubernetes-audit-tailer"
	podport      = "24224"
)

var rootCmd = &cobra.Command{
	Use:     moduleName,
	Short:   "a service that watches for an audit-tailer server pod in the cluster and then starts the audit-tailer client pod with the correct destination IP",
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
		logger.Error("failed executing root command", "error", err)
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
		logger.Errorw("unable to connect to k8s", "error", err)
		os.Exit(1)
	}

	fetchInterval := viper.GetDuration("fetch-interval")
	oldPodIP := "0.0.0.0"
	var oldPodDate time.Time
	logger.Infow("Initial old values", "oldPodIP", oldPodIP, "oldPodDate", oldPodDate)
	// forwarder, _ := os.FindProcess(os.Getpid()) // This is just to initialize forwarder

	ctx, cancel := context.WithCancel(context.Background())

	labelMap := map[string]string{"app": podname}
	opts := metav1.ListOptions{
		LabelSelector: labels.SelectorFromSet(labelMap).String(),
	}
	for {
		watcher, err := client.CoreV1().Pods(namespace).Watch(opts)
		if err != nil {
			logger.Errorw("could not watch for pods", "error", err)
			time.Sleep(fetchInterval)
			continue
		}
		for event := range watcher.ResultChan() {
			p, ok := event.Object.(*apiv1.Pod)
			if !ok {
				logger.Error("unexpected type")
			}
			podIP := p.Status.PodIP
			logger.Infow("Pod IPs", "old", oldPodIP, "new", podIP)
			if podIP != "" && oldPodIP != podIP {
				podDate := p.Status.StartTime.Time
				logger.Infow("Pod dates", "old", oldPodDate, "new", podDate)
				if podDate.After(oldPodDate) {
					logger.Infow("podIP changed, (re-)start forwarder", "old", oldPodIP, "new", podIP, "old date", oldPodDate, "new date", podDate)

					// kill the old process
					// if forwarder.Pid != os.Getpid() {
					// logger.Infow("Killing old process", "PID", forwarder.Pid)
					// err := forwarder.Kill()
					// err := forwarder.Signal(syscall.SIGTERM)
					// if err != nil {
					// 	logger.Errorw("Could not kill old process", "PID", forwarder.Pid, "error", err)
					// }
					// err = forwarder.Release()
					// if err != nil {
					// 	logger.Errorw("Could not release old process", "PID", forwarder.Pid, "error", err)
					// }
					// cancel()

					//}

					cancel()
					// Wait for the old forwarder to exit
					time.Sleep(fetchInterval)

					ctx, cancel = context.WithCancel(context.Background())

					go func() {
						for {

							logger.Info("Building command")

							cmd := exec.CommandContext(ctx, "sleep", "3600")
							cmd.Stdout = os.Stdout // Lets us see stdout and stderr of cmd
							cmd.Stderr = os.Stderr
							cmd.Env = append(os.Environ(),
								"AUDIT_TAILER_HOST="+podIP,
								"AUDIT_TAILER_PORT="+podport,
							)
							logger.Infow("Executing:", "Command", strings.Join(cmd.Args, " "), ", Environment:", strings.Join(cmd.Env, ", "))

							err := cmd.Run()
							if err != nil {
								logger.Errorw("cmd.Run() exited", "error", err)
							}
							// command is finished, now we check if it died or if it got canceled.
							select {
							case <-ctx.Done():
								logger.Infow("Command got canceled", "Error", ctx.Err())
								return
							default:
							}
						}
					}()

					// forwarder = cmd.Process
					// logger.Infow("Process started", "PID", forwarder.Pid)

					oldPodIP = podIP
					oldPodDate = podDate
				}
			}
			logger.Info("After for loop")
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
