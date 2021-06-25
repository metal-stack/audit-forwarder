FROM golang:1.15 AS builder

WORKDIR /work

COPY .git Makefile go.* *.go /work/
COPY pkg/ /work/pkg/
RUN make bin/audit-forwarder

FROM fluent/fluent-bit:1.7.3-debug

COPY --from=builder /work/bin/audit-forwarder /fluent-bit/bin/
COPY fluent-bit.conf /fluent-bit/etc/
COPY parsers.conf /fluent-bit/etc/
COPY null.conf /fluent-bit/etc/add/

CMD ["/fluent-bit/bin/audit-forwarder"]