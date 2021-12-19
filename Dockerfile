# BUILDER
FROM golang:1.17.2-bullseye as builder
WORKDIR /workspace

ENV TINI_VERSION v0.19.0
ADD https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini-static /tini
RUN chmod +x /tini

# hadolint ignore=DL3008
RUN apt-get update && \
    apt-get -y --no-install-recommends install ca-certificates && \
    update-ca-certificates

COPY go.mod go.mod
COPY go.sum go.sum
RUN go mod download

COPY Makefile Makefile
COPY src/ src/

RUN make test
RUN make build

# RUNTIME
FROM gcr.io/distroless/static-debian11:nonroot

WORKDIR /
COPY --from=builder /workspace/bin/aad-oidc-identity /aad-oidc-identity
COPY --from=builder /tini /tini
COPY --from=builder /etc/ssl/certs /etc/ssl/certs

ENTRYPOINT [ "/tini", "--", "/aad-oidc-identity"]