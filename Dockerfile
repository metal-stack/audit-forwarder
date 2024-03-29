FROM golang:1.20 AS builder

WORKDIR /work

COPY .git Makefile go.* *.go /work/
COPY pkg/ /work/pkg/
RUN make bin/audit-forwarder

FROM fluent/fluent-bit:1.9.10

COPY --from=builder /work/bin/audit-forwarder /fluent-bit/bin/
COPY fluent-bit.conf /fluent-bit/etc/
COPY parsers.conf /fluent-bit/etc/
COPY null.conf /fluent-bit/etc/add/

ENTRYPOINT ["/fluent-bit/bin/audit-forwarder"]
CMD ["/fluent-bit/bin/audit-forwarder"]
