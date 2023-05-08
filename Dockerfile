FROM golang:1.18  AS build-env
RUN apt update
RUN apt install git gcc musl-dev make -y
RUN go install github.com/google/wire/cmd/wire@latest
WORKDIR /go/src/github.com/devtron-labs/image-scanner
ADD . /go/src/github.com/devtron-labs/image-scanner
RUN GOOS=linux make

FROM alpine:3.9
RUN apk add --no-cache ca-certificates
RUN adduser -D devtron
COPY --from=build-env  /go/src/github.com/devtron-labs/image-scanner/image-scanner .
RUN chown -R devtron:devtron ./image-scanner
RUN chmod +x ./image-scanner
RUN apk add curl
RUN curl curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin v0.18.3
USER devtron
CMD ["./image-scanner"]
