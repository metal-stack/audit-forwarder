# Audit-forwarder

This is a small piece of software that is intended to run as sidecar in an out-of-cluster kube-apiserver (for example: https://github.com/gardener/gardener clusters) and forward the audit log data back into the cluster where it can be picked up by cluster monitoring / logging software.

## Current scope for the implementation

- The audit-forwarder has to run as sidecar container of the kube-apiserver
- The audit data needs to be logged to file in a shared volume
- There has to be a corresponding `kubernetes-audit-tailer` pod in the cluster that receives the audit data and makes it available to a cluster logging solution, e.g. by writing it to its stdout so that it appears as container log
- We use fluent-bit with the `forward` out plugin as forwarding agent because it is built for the task of reliably forwarding log data. There needs to be a corresponding fluent-bit or fluentd in the `kubernetes-audit-tailer` pod to receive the data


## Testing locally

TBD
