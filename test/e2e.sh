#!/bin/bash -x
set -e
DOCKER_REPO=localhost:5000
KUBECONFIG=~/admin.kubeconfig
TEST_NAMESPACE=myproject

TESTDIR=test
REV=$(git rev-parse --short HEAD)
TEST_IMAGE=${DOCKER_REPO}/oauth-proxy-${REV}:latest

go build -o ${TESTDIR}/oauth-proxy
docker build -t ${TEST_IMAGE} ${TESTDIR}/
docker push ${TEST_IMAGE}
export TEST_IMAGE TEST_NAMESPACE
go test -v github.com/openshift/oauth-proxy/test/e2e
