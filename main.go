package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"path"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	apiv1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	k8s "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/manager/signals"

	"context"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/metal-stack/v"

	"github.com/mitchellh/go-homedir"
	"github.com/pkg/errors"
	"github.com/robfig/cron/v3"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/go-playground/validator.v9"
)

const (
	cfgFileType = "yaml"
	moduleName  = "audit-forwarder"
	commandName = "/fluent-bit/bin/fluent-bit"
	commandArgs = "--config=/fluent-bit/etc/fluent-bit.conf"
	// commandName  = "sleep"
	// commandArgs  = "3600"
)

var (
	cfgFile             string
	logger              *zap.SugaredLogger
	logLevel            zapcore.Level
	stop                <-chan struct{}
	targetService       *apiv1.Service
	certSecret          *apiv1.Secret
	forwarderKilledChan chan struct{}
	killForwarderChan   chan struct{}
	forwarderProcess    *os.Process
	secretCronId        cron.EntryID
	serviceCronId       cron.EntryID
)

// CronLogger is used for logging within the cron function.
type CronLogger struct {
	l *zap.SugaredLogger
}

// Info logs info messages from the cron function.
func (c *CronLogger) Info(msg string, keysAndValues ...interface{}) {
	c.l.Infow(msg, keysAndValues)
}

func (c *CronLogger) Error(err error, msg string, keysAndValues ...interface{}) {
	c.l.Errorw(msg, keysAndValues)
}

// Opts is required in order to have proper validation for args from cobra and viper.
// this is because MarkFlagRequired from cobra does not work well with viper, see:
// https://github.com/spf13/viper/issues/397
type Opts struct {
	KubeCfg       string
	NameSpace     string
	ServiceName   string
	SecretName    string
	AuditLogPath  string
	TLSBaseDir    string
	TLSCaFile     string
	TLSCrtFile    string
	TLSKeyFile    string
	TLSVhost      string
	CheckSchedule string
	BackoffTimer  time.Duration
	LogLevel      string
}

var cmd = &cobra.Command{
	Use:     moduleName,
	Short:   "A program to forward audit logs to a service in the cluster. It looks for a matching service, then starts a forwarder program (eg fluent-bit) to pick up the log events and do the actual forwarding.",
	Version: v.V.String(),
	Run: func(cmd *cobra.Command, args []string) {
		initConfig()
		opts, err := initOpts()
		if err != nil {
			log.Fatalf("unable to init options, error: %v", err)
		}
		initLogging(opts)
		initSignalHandlers()
		err = run(opts)
		if err != nil {
			log.Printf("run() function run returned with error: %v", err)
		}
	},
}

func init() {
	homedir, err := homedir.Dir()
	if err != nil {
		log.Fatal(err)
	}

	cmd.Flags().StringVarP(&cfgFile, "config", "c", "", "alternative path to config file")

	cmd.Flags().StringP("kubecfg", "k", homedir+"/.kube/config", "kubecfg path to the cluster to account")
	cmd.Flags().StringP("namespace", "n", "kube-system", "the namespace of the audit-tailer service")
	cmd.Flags().StringP("service-name", "s", "kubernetes-audit-tailer", "the service name of the audit-tailer service")
	cmd.Flags().StringP("secret-name", "e", "audittailer-client", "the name of the secret containing the CA file, client certificate and key")
	cmd.Flags().StringP("audit-log-path", "l", "/auditlog", "the path to the directory containing the audit-log files")
	cmd.Flags().StringP("tls-basedir", "B", "/fluent-bit/etc/ssl", "the path to the directory where the cert and key files should be written")
	cmd.Flags().StringP("tls-ca-file", "C", "ca.crt", "the filename of the CA file for checking the server (audit-tailer) certificate")
	cmd.Flags().StringP("tls-crt-file", "R", "audittailer-client.crt", "the filename of the client certificate used to authenticate to the audit-tailer")
	cmd.Flags().StringP("tls-key-file", "K", "audittailer-client.key", "the filename of the private key file belonging to the client certificate")
	cmd.Flags().StringP("tls-vhost", "H", "kubernetes-audit-tailer", "the name of the audit-tailer, as presented in its server certificate. This is needed so that the certificate is accepted by fluent-bit")
	cmd.Flags().StringP("check-schedule", "S", "*/1 * * * *", "cron schedule when to check for service changes")
	cmd.Flags().DurationP("backoff-timer", "b", time.Duration(10*time.Second), "Backoff time for restarting the forwarder process when it has been killed by external influences")
	cmd.Flags().StringP("log-level", "L", "info", "sets the application log level")

	err = viper.BindPFlags(cmd.Flags())
	if err != nil {
		log.Fatalf("unable to construct root command, error: %v", err)
	}
}

func initOpts() (*Opts, error) {
	opts := &Opts{
		KubeCfg:       viper.GetString("kubecfg"),
		NameSpace:     viper.GetString("namespace"),
		ServiceName:   viper.GetString("service-name"),
		SecretName:    viper.GetString("secret-name"),
		AuditLogPath:  viper.GetString("audit-log-path"),
		TLSBaseDir:    viper.GetString("tls-basedir"),
		TLSCaFile:     viper.GetString("tls-ca-file"),
		TLSCrtFile:    viper.GetString("tls-crt-file"),
		TLSKeyFile:    viper.GetString("tls-key-file"),
		TLSVhost:      viper.GetString("tls-vhost"),
		CheckSchedule: viper.GetString("check-schedule"),
		BackoffTimer:  viper.GetDuration("backoff-timer"),
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

func initLogging(opts *Opts) {
	err := logLevel.UnmarshalText([]byte(opts.LogLevel))
	if err != nil {
		log.Fatalf("can't initialize zap logger: %v", err)
	}

	cfg := zap.NewProductionConfig()
	cfg.Level = zap.NewAtomicLevelAt(logLevel)

	log.Printf("Log level: %s", cfg.Level)

	l, err := cfg.Build()
	if err != nil {
		log.Fatalf("can't initialize zap logger: %v", err)
	}

	logger = l.Sugar()
}

func initSignalHandlers() {
	stop = signals.SetupSignalHandler()
}

func run(opts *Opts) error {
	logger.Debugw("Options", "opts", opts)
	// initialise our synchronisation channels
	forwarderKilledChan = make(chan struct{})
	killForwarderChan = make(chan struct{}, 1)

	// set up certificates directory
	err := os.MkdirAll(opts.TLSBaseDir, 0750)
	if err != nil {
		logger.Errorw("Unable to create certificate directory", opts.TLSBaseDir, err)
		return err
	}

	// Prepare K8s
	client, err := loadClient(opts.KubeCfg)
	if err != nil {
		logger.Errorw("Unable to connect to k8s", "Error", err)
		return err
	}

	// Set up (and run) service checker cron job
	cronjob := cron.New(cron.WithChain(
		cron.SkipIfStillRunning(&CronLogger{l: logger.Named("cron")}),
	))

	secretCronId, err = cronjob.AddFunc(opts.CheckSchedule, func() {
		err := checkSecret(opts, client)
		if err != nil {
			logger.Errorw("error during secret check", "error", err)
		}

		logger.Debugw("scheduling next secret check", "at", cronjob.Entry(secretCronId))
	})
	if err != nil {
		return errors.Wrap(err, "could not initialize cron schedule")
	}
	serviceCronId, err = cronjob.AddFunc(opts.CheckSchedule, func() {
		err := checkService(opts, client)
		if err != nil {
			logger.Errorw("error during service check", "error", err)
		}

		logger.Debugw("scheduling next secret check", "at", cronjob.Entry(serviceCronId))
	})
	if err != nil {
		return errors.Wrap(err, "could not initialize cron schedule")
	}

	logger.Infow("start initial checks", "version", v.V.String())

	err = checkSecret(opts, client)
	if err != nil {
		logger.Errorw("error during initial secret check", "error", err)
	}
	err = checkService(opts, client)
	if err != nil {
		logger.Errorw("error during initial service check", "error", err)
	}
	cronjob.Start()
	logger.Infow("cronjob interval", "check-schedule", opts.CheckSchedule)
	logger.Debugw("Cron entries", cronjob.Entries())

	<-stop
	logger.Info("received stop signal, shutting down...")

	cronjob.Stop()
	return nil

}

func loadClient(kubeconfigPath string) (*k8s.Clientset, error) {
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	if err != nil {
		return nil, err
	}
	return k8s.NewForConfig(config)
}

func checkService(opts *Opts, client *k8s.Clientset) error {
	logger.Debugw("Checking service")
	// logger.Debugw("Current service", "targetService", targetService)

	kubectx, kubecancel := context.WithTimeout(context.Background(), time.Duration(10*time.Second))
	defer kubecancel()
	service, err := client.CoreV1().Services(opts.NameSpace).Get(kubectx, opts.ServiceName, metav1.GetOptions{})
	if err != nil { // That means no matching service found
		if targetService != nil { // This means a service was previously seen, and a forwarder should already be running.
			logger.Infow("Service went away, killing forwarder")
			killForwarder()
			targetService = nil
		}
		return err
	}

	// logger.Debugw("Service gotten", "service", service)
	serviceIP := service.Spec.ClusterIP
	if len(service.Spec.Ports) != 1 {
		logger.Errorw("Service must have exactly one port", "Ports", service.Spec.Ports)
		return errors.Errorf("Service must have exactly one port")
	}
	servicePort := service.Spec.Ports[0].Port

	if targetService != nil { // This means a service was previously seen, and a forwarder should already be running.
		if targetService.Spec.ClusterIP == service.Spec.ClusterIP && targetService.Spec.Ports[0].Port == service.Spec.Ports[0].Port {
			logger.Debugw("Service stayed the same, nothing to do.")
			return nil
		}
		// We need to kill the old forwarder
		killForwarder()
	}

	// Check whether the certificates have already been written!
	if certSecret == nil {
		logger.Debugw("No certificates in place, waiting.")
		return nil
	}

	logger.Infow("Target identified", "IP", serviceIP, "Port", servicePort)
	go runForwarder(serviceIP, int(servicePort), opts)
	targetService = service
	return nil
}

func runForwarder(serviceIP string, servicePort int, opts *Opts) {
	for {
		logger.Info("Starting forwarder")

		cmd := exec.Command(commandName, commandArgs)
		cmd.Stdout = os.Stdout // Lets us see stdout and stderr of cmd
		cmd.Stderr = os.Stderr

		cmd.Env = append(os.Environ(),
			"AUDIT_TAILER_HOST="+serviceIP,
			"AUDIT_TAILER_PORT="+strconv.Itoa(servicePort),
			"AUDIT_LOG_PATH="+opts.AuditLogPath,
			"TLS_CA_FILE="+path.Join(opts.TLSBaseDir, opts.TLSCaFile),
			"TLS_CRT_FILE="+path.Join(opts.TLSBaseDir, opts.TLSCrtFile),
			"TLS_KEY_FILE="+path.Join(opts.TLSBaseDir, opts.TLSKeyFile),
			"TLS_VHOST="+opts.TLSVhost,
			"LOG_LEVEL="+logLevel.String(),
		)
		logger.Debugw("Executing:", "Command", strings.Join(cmd.Args, " "), ", Environment:", strings.Join(cmd.Env, ", "))

		err := cmd.Start()
		if err != nil {
			logger.Errorw("Could not start forwarder", "Error", err)
		}
		logger.Infow("Forwarder process", "PID", cmd.Process)
		forwarderProcess = cmd.Process
		err = cmd.Wait()

		if err != nil {
			logger.Infow("Forwarder exited", "Error", err)
		}
		// command is finished, now we check if it died or if we killed it intentionally.
		select {
		case <-killForwarderChan:
			logger.Infow("Forwarder was killed on purpose")
			forwarderKilledChan <- struct{}{}
			logger.Debugw("Written to confirmation channel, returning")
			return
		default:
			logger.Infow("Forwarder was not killed by this controller, restarting", "Backoff time", opts.BackoffTimer)
			time.Sleep(opts.BackoffTimer)
		}
	}
}

func killForwarder() {
	logger.Infow("Killing process", "PID", forwarderProcess)
	logger.Debugw("Writing to kill channel")
	killForwarderChan <- struct{}{}
	err := forwarderProcess.Kill()
	if err != nil {
		logger.Errorw("Could not kill process", "Error", err)
	}
	// Wait for the old forwarder to exit
	<-forwarderKilledChan
	logger.Infow("Forwarder successfully killed")
}

func checkSecret(opts *Opts, client *k8s.Clientset) error {
	logger.Debugw("Checking secret")
	keys := []string{opts.TLSCaFile, opts.TLSCrtFile, opts.TLSKeyFile}

	kubectx, kubecancel := context.WithTimeout(context.Background(), time.Duration(10*time.Second))
	defer kubecancel()
	secret, err := client.CoreV1().Secrets(opts.NameSpace).Get(kubectx, opts.SecretName, metav1.GetOptions{})
	if err != nil { // That means no matching secret found. No need to do anything - we write a new secret when one becomes available.
		return err
	}
	logger.Debugw("Got secret", opts.SecretName, secret)

	if certSecret != nil { // A secret has already been seen
		if secret.ResourceVersion == certSecret.ResourceVersion { // Secret stayed the same, nothing to do
			logger.Debugw("Secret stayed the same", "ResourceVersion", secret.ResourceVersion)
			return nil
		}
	}

	// Now we attempt to write the certificates to file
	for _, k := range keys {
		v, ok := secret.Data[k]
		if !ok {
			return fmt.Errorf("could not find key in secret key:%s", k)
		}
		f := path.Join(opts.TLSBaseDir, k)
		logger.Debugw("Writing certificate to file", k, f)
		err := ioutil.WriteFile(f, v, 0640)
		if err != nil {
			return fmt.Errorf("could not write secret to certificate base folder:%v", err)
		}
	}

	// Certificates successfully written; if there is a forwarder already running we must restart it now.
	if forwarderProcess != nil {
		logger.Debugw("Forwarder running, killing it so it can restart.", "Process:", forwarderProcess)
		err := forwarderProcess.Kill()
		if err != nil {
			logger.Errorw("Could not kill process", "Error", err)
		}
	}

	certSecret = secret

	return nil
}
