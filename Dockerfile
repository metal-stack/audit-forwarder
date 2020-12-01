FROM golang:1.15 AS builder

WORKDIR /go/src/github.com/mreiger/audit-forwarder/

COPY .git Makefile go.* *.go /go/src/github.com/mreiger/audit-forwarder/
RUN make bin/audit-forwarder

FROM fluent/fluent-bit:1.6-debug

COPY --from=builder /go/src/github.com/mreiger/audit-forwarder/bin/audit-forwarder /fluent-bit/bin/
COPY *.conf /fluent-bit/etc/

CMD ["/fluent-bit/bin/audit-forwarder"]