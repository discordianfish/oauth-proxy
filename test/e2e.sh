#!/bin/bash -x
set -e

PROJECT_REPO=github.com/openshift/oauth-proxy
DOCKER_REPO=localhost:5000
KUBECONFIG=~/admin.kubeconfig
TEST_NAMESPACE=myproject
TESTDIR=test
REV=$(git rev-parse --short HEAD)
TEST_IMAGE=${DOCKER_REPO}/oauth-proxy-${REV}:latest
HELLO_PATH=${TESTDIR}/e2e/hello
HELLO_IMAGE=${DOCKER_REPO}/hello-proxy-${REV}:latest

# build backend site
go build -o ${HELLO_PATH}/hello_openshift ${PROJECT_REPO}/${HELLO_PATH}
docker build -t ${HELLO_IMAGE} ${HELLO_PATH}
docker push ${HELLO_IMAGE}

# build oauth-proxy
go build -o ${TESTDIR}/oauth-proxy
docker build -t ${TEST_IMAGE} ${TESTDIR}/
docker push ${TEST_IMAGE}

# run test
export TEST_IMAGE TEST_NAMESPACE HELLO_IMAGE KUBECONFIG
go test -v ${PROJECT_REPO}/${TESTDIR}/e2e
