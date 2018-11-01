FROM openshift/origin-release:golang-1.10 AS build
COPY . /go/src/github.com/openshift/oauth-proxy
RUN cd /go/src/github.com/openshift/oauth-proxy && go build .
FROM centos:7
COPY --from=build /go/src/github.com/openshift/oauth-proxy/oauth-proxy /bin/oauth-proxy
ENTRYPOINT ["/bin/oauth-proxy"]
