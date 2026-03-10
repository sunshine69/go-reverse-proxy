FROM golang:1.26.1-alpine3.23 AS BUILD_BASE
RUN mkdir /app && mkdir /imagetmp && chmod 1777 /imagetmp
ADD . /app/
WORKDIR /app
ENV CGO_ENABLED=0 PATH=/usr/local/go/bin:/opt/go/bin:/usr/bin:/usr/sbin:/bin:/sbin

ARG APP_VERSION="v0.1"
ARG BINARY_NAME="reverse-proxy-go"
ARG PORT="8080"
ARG BUILD_TIME="unknown"

ARG runas_user_id=10001
ARG runas_user_name=appuser
RUN addgroup ${runas_user_name}; adduser -D --ingroup ${runas_user_name} --uid ${runas_user_id} --shell /bin/false ${runas_user_name};  \
    if [ "$?" != "0" ]; then useradd -g ${runas_user_name} --uid ${runas_user_id} --shell /bin/false ${runas_user_name}; fi; \
    cat /etc/passwd | grep ${runas_user_name} > /etc/passwd_gouser && \
    cat /etc/group | grep ${runas_user_name} > /etc/group_gouser

RUN apk add zip

ENV GOEXPERIMENT=greenteagc,jsonv2

RUN go generate && go build -trimpath -ldflags="-X main.version=${APP_VERSION} -X main.buildTime=$(date +%Y%m%d%H%M) -extldflags=-static -w -s" --tags "osusergo,netgo" -o ${BINARY_NAME}
CMD ["/app/${BINARY_NAME}"]

FROM scratch
ARG BINARY_NAME="reverse-proxy-go"
ARG PORT="8080"

ARG runas_user_id=10001
ARG runas_user_name=appuser
ARG expose_port=8080
COPY --from=build /etc/passwd_gouser /etc/passwd_gouser
COPY --from=build /etc/group_gouser /etc/group_gouser

# the ca files is from my current ubuntu 20 /etc/ssl/certs/ca-certificates.crt - it should provide all current root certs
ADD ca-certificates.crt /etc/ssl/certs/
COPY --from=BUILD_BASE /app/${BINARY_NAME} /app/${BINARY_NAME}
COPY --from=BUILD_BASE /imagetmp /tmp
ENV TZ=Australia/Brisbane
EXPOSE $PORT

USER ${runas_user_name}

WORKDIR /app
ENTRYPOINT [ "/app/reverse-proxy-go" ]
