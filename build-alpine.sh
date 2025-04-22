#!/bin/sh

mkdir -p build
podman run \
	--rm \
	-v ./main.go:/app/main.go:ro \
	-v ./go.mod:/app/go.mod:ro \
	-v ./build:/app/build:rw \
	docker.io/library/alpine \
	/bin/sh -c 'cd /app && apk update && apk add go && go build && cp mf-script-launcher /app/build/mf-script-launcher.alpine'

