FROM golang:alpine as builder

ENV GO111MODULE=on

RUN apk update && \
    apk upgrade && \
    apk add --no-cache make git alpine-sdk
RUN mkdir -p /go/src/github.com/mayuresh82/auto_remediation

COPY . /go/src/github.com/mayuresh82/auto_remediation

WORKDIR /go/src/github.com/mayuresh82/auto_remediation

RUN go mod download
RUN make

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /go/src/github.com/mayuresh82/auto_remediation .

EXPOSE 8080/tcp

ENTRYPOINT ["./auto_remediation"]
