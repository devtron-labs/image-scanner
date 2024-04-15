FROM golang:1.20-alpine3.17  AS build-env
RUN apk add --no-cache git gcc musl-dev
RUN apk add --update make
RUN go install github.com/google/wire/cmd/wire@latest
WORKDIR /go/src/github.com/devtron-labs/image-scanner
ADD . /go/src/github.com/devtron-labs/image-scanner
RUN GOOS=linux make

FROM alpine:3.17
RUN apk update && apk add --no-cache --virtual .build-deps && apk add bash && apk add make && apk add curl && apk add git && apk add zip && apk add jq
COPY --from=aquasec/trivy:0.46.1 /usr/local/bin/trivy /usr/local/bin/trivy
RUN apk add --no-cache ca-certificates
RUN mkdir -p /security
RUN adduser -D devtron

COPY ./git-ask-pass.sh /git-ask-pass.sh
RUN chmod +x /git-ask-pass.sh

COPY --from=build-env  /go/src/github.com/devtron-labs/image-scanner/image-scanner .
COPY ./ssh-config /root/.ssh/config
RUN chmod 644 /root/.ssh/config

RUN chown -R devtron:devtron ./image-scanner
RUN chmod +x ./image-scanner
RUN chown -R devtron:devtron ./security
RUN chmod +x ./securityRUN apk update && apk add --no-cache --virtual .build-deps && apk add bash && apk add make && apk add curl && apk add git && apk add zip && apk add jq

USER devtron
CMD ["./image-scanner"]
