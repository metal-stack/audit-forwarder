package main

import (
	"time"

	"go.uber.org/zap"
	k8s "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"os"

	"github.com/metal-stack/v"
	"github.com/mreiger/audit-tailer-controller/pkg/audittailer"

	"github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	moduleName   = "audit-tailer-controller"
	systemctlBin = "/bin/systemctl"
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
	rootCmd.PersistentFlags().Duration("fetch-interval", 10*time.Second, "interval for reassembling firewall rules")
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
	auditTailer, err := audittailer.NewAuditTailer(logger, client)
	if err != nil {
		logger.Errorw("unable to create audittailer client", "error", err)
		os.Exit(1)
	}

	// watch for server IP
	c := make(chan bool)
	go auditTailer.WatchServerIP()
	// go dropTailer.WatchClientSecret()	// We'll start without SSL - no need for secrets just yet

	time.Sleep(time.Hour) // Sleep for an hour so we can see what's happening.

	// regularly trigger fetch of k8s resources
	go func() {
		t := time.NewTicker(viper.GetDuration("fetch-interval"))
		for {
			<-t.C
			c <- true
		}
	}()

	// debounce events and handle fetch
	// 	d := time.Second * 3
	// 	t := time.NewTimer(d)
	// 	for {
	// 		select {
	// 		case <-c:
	// 			t.Reset(d)
	// 		case <-t.C:
	// 			new, err = ctr.FetchAndAssemble()
	// 			if err != nil {
	// 				logger.Errorw("could not fetch k8s entities to build firewall rules", "error", err)
	// 			}
	// 			if !new.HasChanged(old) {
	// 				old = new
	// 				continue
	// 			}
	// 			old = new
	// 			logger.Infow("new fw rules to enforce", "ingress", len(new.IngressRules), "egress", len(new.EgressRules))
	// 			for k, i := range new.IngressRules {
	// 				fmt.Printf("%d ingress: %s\n", k+1, i)
	// 			}
	// 			for k, e := range new.EgressRules {
	// 				fmt.Printf("%d egress: %s\n", k+1, e)
	// 			}
	// 			if !viper.GetBool("dry-run") {
	// 				rs, err := new.Render()
	// 				if err != nil {
	// 					logger.Errorw("error rendering nftables rules", "error", err)
	// 					continue
	// 				}
	// 				err = ioutil.WriteFile(nftFile, []byte(rs), 0644)
	// 				if err != nil {
	// 					logger.Errorw("error writing nftables file", "file", nftFile, "error", err)
	// 					continue
	// 				}
	// 				c := exec.Command(nftBin, "-c", "-f", nftFile)
	// 				out, err := c.Output()
	// 				if err != nil {
	// 					logger.Errorw("nftables file is invalid", "file", nftFile, "error", fmt.Sprint(out))
	// 					continue
	// 				}
	// 				c = exec.Command(systemctlBin, "reload", nftablesService)
	// 				err = c.Run()
	// 				if err != nil {
	// 					logger.Errorw("nftables.service file could not be reloaded")
	// 					continue
	// 				}
	// 				logger.Info("applied new set of nftable rules")
	// 			}
	// 		}
	// 	}
}

func loadClient(kubeconfigPath string) (*k8s.Clientset, error) {
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	if err != nil {
		return nil, err
	}
	return k8s.NewForConfig(config)
}
