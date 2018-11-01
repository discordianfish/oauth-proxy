GOFLAGS :=
IMAGE_REPOSITORY_NAME ?= openshift

build:
	go build $(GOFLAGS) .
.PHONY: build

images:
	imagebuilder -f Dockerfile -t $(IMAGE_REPOSITORY_NAME)/oauth-proxy .
.PHONY: images

clean:
	$(RM) ./oauth-proxy
.PHONY: clean
