FROM	golang:1.9
LABEL	maintainer="@discordianfish"

RUN go get -u github.com/golang/dep/cmd/dep

WORKDIR	/go/src/github.com/openshift/oauth-proxy
COPY Gopkg.* ./
RUN	dep ensure --vendor-only

COPY . .
RUN CGO_ENABLED=0 go install

FROM	alpine:3.7
RUN   apk add --update ca-certificates
COPY	--from=0 /go/bin/oauth-proxy /bin/
ENTRYPOINT [ "/bin/oauth-proxy" ]
