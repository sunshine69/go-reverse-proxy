FROM golang:1.26.1-alpine3.23 AS BUILD_BASE
RUN mkdir /app && mkdir /imagetmp && chmod 1777 /imagetmp
ADD . /app/
WORKDIR /app
ENV CGO_ENABLED=0 PATH=/usr/local/go/bin:/opt/go/bin:/usr/bin:/usr/sbin:/bin:/sbin

ARG APP_VERSION="v0.1"
ARG BINARY_NAME="reverse-proxy-go"
ARG PORT="8080"
ARG BUILD_TIME="unknown"

RUN apk add zip 

RUN go generate && go build -trimpath -ldflags="-X main.version=${APP_VERSION} -X main.buildTime=$(date +%Y%m%d%H%M) -extldflags=-static -w -s" --tags "osusergo,netgo" -o ${BINARY_NAME}
CMD ["/app/${BINARY_NAME}"]

FROM scratch
ARG BINARY_NAME="reverse-proxy-go"
ARG PORT="8080"
# the ca files is from my current ubuntu 20 /etc/ssl/certs/ca-certificates.crt - it should provide all current root certs
ADD ca-certificates.crt /etc/ssl/certs/
COPY --from=BUILD_BASE /app/${BINARY_NAME} /${BINARY_NAME}
COPY --from=BUILD_BASE /imagetmp /tmp
ENV TZ=Australia/Brisbane
EXPOSE $PORT
ENTRYPOINT [ "/reverse-proxy-go" ]
