module github.com/metal-stack/audit-forwarder

go 1.16

require (
	github.com/go-playground/validator/v10 v10.9.0
	github.com/imdario/mergo v0.3.11 // indirect
	github.com/metal-stack/v v1.0.3
	github.com/robfig/cron/v3 v3.0.1
	github.com/spf13/cobra v1.2.1
	github.com/spf13/viper v1.8.1
	go.uber.org/zap v1.19.0
	k8s.io/api v0.20.4
	k8s.io/apimachinery v0.20.4
	k8s.io/client-go v0.20.4
	sigs.k8s.io/controller-runtime v0.6.5
)
