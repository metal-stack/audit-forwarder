FROM golang:1.15 AS builder

WORKDIR /work

COPY .git Makefile go.* *.go /work
RUN make bin/audit-forwarder

FROM fluent/fluent-bit:1.7-debug

COPY --from=builder /work/bin/audit-forwarder /fluent-bit/bin/
COPY *.conf /fluent-bit/etc/

CMD ["/fluent-bit/bin/audit-forwarder"]