package main

import (
	"time"

	"log"

	"go.uber.org/zap"
	apiv1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	k8s "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"context"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/metal-stack/v"

	"github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/go-playground/validator.v9"
)

const (
	cfgFileType = "yaml"
	moduleName  = "audit-forwarder"
	commandName = "/fluent-bit/bin/fluent-bit"
	commandArgs = "--config=/fluent-bit/etc/fluent-bit.conf"
)

var (
	cfgFile string
	logger  *zap.SugaredLogger
)

// Opts is required in order to have proper validation for args from cobra and viper.
// this is because MarkFlagRequired from cobra does not work well with viper, see:
// https://github.com/spf13/viper/issues/397
type Opts struct {
	KubeCfg       string
	FetchInterval time.Duration
	NameSpace     string
	ServiceName   string
	ServicePort   int
	LogLevel      string
}

var cmd = &cobra.Command{
	Use:     moduleName,
	Short:   "a webhook that accepts audit events and writes them to stdout so they can be picked up by another log processing system.",
	Version: v.V.String(),
	Run: func(cmd *cobra.Command, args []string) {
		initConfig()
		opts, err := initOpts()
		if err != nil {
			log.Fatalf("unable to init options, error: %v", err)
		}
		initLogging()
		run(opts)
	},
}

func init() {
	log.Print("Function init() called.")
	homedir, err := homedir.Dir()
	if err != nil {
		logger.Fatal(err)
	}
	log.Printf("Homedir variable homedir: %s", homedir)

	cmd.Flags().StringP("log-level", "", "info", "sets the application log level")
	cmd.Flags().StringVarP(&cfgFile, "config", "c", "", "alternative path to config file")

	cmd.Flags().StringP("kubecfg", "k", homedir+"/.kube/config", "kubecfg path to the cluster to account")
	cmd.Flags().Duration("fetch-interval", 10*time.Second, "interval for checking availability of target")

	cmd.Flags().StringP("namespace", "", "kube-system", "the namespace of the audit-tailer service")
	cmd.Flags().StringP("service-name", "", "kubernetes-audit-tailer", "the service name of the audit-tailer service")
	cmd.Flags().IntP("service-port", "", 24224, "the service port of the audit-tailer service")

	err = viper.BindPFlags(cmd.Flags())
	if err != nil {
		logger.Fatalw("unable to construct root command", "error", err)
	}
}

func initOpts() (*Opts, error) {
	opts := &Opts{
		KubeCfg:       viper.GetString("kubecfg"),
		FetchInterval: viper.GetDuration("fetch-interval"),
		NameSpace:     viper.GetString("namespace"),
		ServiceName:   viper.GetString("service-name"),
		ServicePort:   viper.GetInt("service-port"),
		LogLevel:      viper.GetString("log-level"),
	}

	validate := validator.New()
	err := validate.Struct(opts)
	if err != nil {
		return nil, err
	}

	return opts, nil
}

func main() {
	zap, _ := zap.NewProduction()
	defer func() {
		_ = zap.Sync()
	}()
	logger = zap.Sugar()
	if err := cmd.Execute(); err != nil {
		logger.Error("Failed executing root command", "Error", err)
	}
}

func initConfig() {
	viper.SetEnvPrefix("audit")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.AutomaticEnv()

	viper.SetConfigType(cfgFileType)

	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
		if err := viper.ReadInConfig(); err != nil {
			logger.Errorw("Config file path set explicitly, but unreadable", "error", err)
			os.Exit(1)
		}
	} else {
		viper.SetConfigName("config")
		viper.AddConfigPath("/etc/" + moduleName)
		viper.AddConfigPath("$HOME/." + moduleName)
		viper.AddConfigPath(".")
		if err := viper.ReadInConfig(); err != nil {
			usedCfg := viper.ConfigFileUsed()
			if usedCfg != "" {
				logger.Errorw("Config file unreadable", "config-file", usedCfg, "error", err)
				os.Exit(1)
			}
		}
	}

	usedCfg := viper.ConfigFileUsed()
	if usedCfg != "" {
		logger.Infow("Read config file", "config-file", usedCfg)
	}
}

func initLogging() {
	level := zap.InfoLevel

	if viper.IsSet("log-level") {
		err := level.UnmarshalText([]byte(viper.GetString("log-level")))
		if err != nil {
			log.Fatalf("can't initialize zap logger: %v", err)
		}
	}

	cfg := zap.NewProductionConfig()
	cfg.Level = zap.NewAtomicLevelAt(level)

	log.Printf("Log level: %s", cfg.Level)

	l, err := cfg.Build()
	if err != nil {
		log.Fatalf("can't initialize zap logger: %v", err)
	}

	logger = l.Sugar()
}

func run(opts *Opts) {
	logger.Infow("Options", "opts", opts)
	client, err := loadClient(opts.KubeCfg)
	if err != nil {
		logger.Fatalw("Unable to connect to k8s", "Error", err)
	}

	// Apparently we now need to pass a context co k8s client API
	kubectx, kubecancel := context.WithCancel(context.Background())
	defer kubecancel()

	// initialising variables used in pod loop
	oldPodIP := ""
	var oldPodDate time.Time
	ctx, cancel := context.WithCancel(context.Background())
	forwarderKilled := make(chan struct{})

	logger.Infow("Initial old values", "oldPodIP", oldPodIP, "oldPodDate", oldPodDate)

	labelMap := map[string]string{"app": opts.ServiceName}
	options := metav1.ListOptions{
		LabelSelector: labels.SelectorFromSet(labelMap).String(),
	}
	for {
		watcher, err := client.CoreV1().Pods(opts.NameSpace).Watch(kubectx, options)
		if err != nil {
			logger.Fatalw("Could not watch for pods", "Error", err)
		}
		for event := range watcher.ResultChan() {
			p, ok := event.Object.(*apiv1.Pod)
			if !ok {
				logger.Error("Unexpected type")
				continue
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
								"AUDIT_TAILER_PORT="+strconv.Itoa(opts.ServicePort),
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
								time.Sleep(opts.FetchInterval)
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
