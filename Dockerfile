FROM golang:1.21-alpine3.18  AS build-env
RUN apk add --no-cache git gcc musl-dev
RUN apk add --update make
RUN go install github.com/google/wire/cmd/wire@latest
WORKDIR /go/src/github.com/devtron-labs/image-scanner
ADD . /go/src/github.com/devtron-labs/image-scanner
RUN GOOS=linux make

FROM alpine:3.17
COPY --from=aquasec/trivy:0.46.1 /usr/local/bin/trivy /usr/local/bin/trivy
RUN apk add --no-cache ca-certificates
RUN mkdir -p /security
RUN adduser -D devtron
COPY --from=build-env  /go/src/github.com/devtron-labs/image-scanner/image-scanner .
RUN chown -R devtron:devtron ./image-scanner
RUN chmod +x ./image-scanner
RUN chown -R devtron:devtron ./security
RUN chmod +x ./security
USER devtron
CMD ["./image-scanner"]
