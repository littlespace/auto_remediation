FROM golang:latest as builder

ENV GO111MODULE=on

RUN mkdir -p /go/src/github.com/mayuresh82/auto_remediation

COPY . /go/src/github.com/mayuresh82/auto_remediation

WORKDIR /go/src/github.com/mayuresh82/auto_remediation

RUN go mod download
RUN make

FROM python:3.7

WORKDIR /root/

COPY scripts/requirements.txt .

RUN pip install -r requirements.txt

COPY --from=builder /go/src/github.com/mayuresh82/auto_remediation .

EXPOSE 8080/tcp

ENTRYPOINT ["./auto_remediation"]
