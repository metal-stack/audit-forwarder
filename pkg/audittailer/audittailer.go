package audittailer

import (
	"fmt"
	"os"
	"time"

	"github.com/txn2/txeh"
	"go.uber.org/zap"
	apiv1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	k8s "k8s.io/client-go/kubernetes"
)

const (
	namespace = "kube-system"
	// secretName              = "audittailer-client"
	// secretKeyCertificate    = "audittailer-client.crt"
	// secretKeyCertificateKey = "audittailer-client.key"
	// secretKeyCaCertificate  = "ca.crt"
	defaultCertificateBase = "/etc/audittailer-client"
)

// AuditTailer is responsible to deploy and watch the audittailer service
type AuditTailer struct {
	client          k8s.Interface
	logger          *zap.SugaredLogger
	podname         string
	namespace       string
	hosts           *txeh.Hosts
	oldPodIP        string
	certificateBase string
}

// NewAuditTailer creates a new AuditTailer
func NewAuditTailer(logger *zap.SugaredLogger, client k8s.Interface) (*AuditTailer, error) {
	hosts, err := txeh.NewHostsDefault()
	if err != nil {
		return nil, fmt.Errorf("unable to create hosts editor:%w", err)
	}
	certificateBase := os.Getenv("DROPTAILER_CLIENT_CERTIFICATE_BASE")
	if certificateBase == "" {
		certificateBase = defaultCertificateBase
	}
	return &AuditTailer{
		client:          client,
		logger:          logger,
		podname:         "kubernetes-audit-tailer",
		namespace:       namespace,
		hosts:           hosts,
		certificateBase: certificateBase,
	}, nil
}

// WatchServerIP watches the audittailer-server pod ip and updates /etc/hosts
func (d *AuditTailer) WatchServerIP() {
	labelMap := map[string]string{"app": d.podname}
	opts := metav1.ListOptions{
		LabelSelector: labels.SelectorFromSet(labelMap).String(),
	}
	for {
		watcher, err := d.client.CoreV1().Pods(d.namespace).Watch(opts)
		if err != nil {
			d.logger.Errorw("could not watch for pods", "error", err)
			time.Sleep(10 * time.Second)
			continue
		}
		for event := range watcher.ResultChan() {
			p, ok := event.Object.(*apiv1.Pod)
			if !ok {
				d.logger.Error("unexpected type")
			}
			podIP := p.Status.PodIP
			if podIP != "" && d.oldPodIP != podIP {
				d.logger.Infow("podIP changed, update /etc/hosts", "old", d.oldPodIP, "new", podIP)
				d.hosts.RemoveHost("audittailer")
				d.hosts.AddHost(p.Status.PodIP, "audittailer")
				err := d.hosts.Save()
				if err != nil {
					d.logger.Errorw("could not write audittailer hosts entry", "error", err)
				}
				d.oldPodIP = podIP
			}
		}
	}
}

/* // WatchClientSecret watches the audittailer-client secret and saves it to disk for the audittailer-client.
func (d *AuditTailer) WatchClientSecret() {
	keys := []string{secretKeyCaCertificate, secretKeyCertificate, secretKeyCertificateKey}
	for {
		s, err := d.client.CoreV1().Secrets(namespace).Watch(metav1.ListOptions{})
		if err != nil {
			d.logger.Errorw("could not watch for pods audittailer-client secret", "error", err)
			time.Sleep(10 * time.Second)
			continue
		}
		for event := range s.ResultChan() {
			secret, ok := event.Object.(*apiv1.Secret)
			if !ok {
				d.logger.Error("unexpected type")
			}
			if secret.GetName() != secretName {
				continue
			}
			for _, k := range keys {
				v, ok := secret.Data[k]
				if !ok {
					d.logger.Errorw("could not find key in secret", "key", k)
					continue
				}
				f := path.Join(d.certificateBase, k)
				err = ioutil.WriteFile(f, v, 0640)
				if err != nil {
					d.logger.Errorw("could not write secret to certificate base folder", "error", err)
					time.Sleep(10 * time.Second)
					continue
				}
			}
		}

	}
}
*/
