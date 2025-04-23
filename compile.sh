#!/bin/sh

echo "Inspect if image exists" 
if ! podman image inspect localhost/mf-script-launcher-builder >/dev/null 2>&1
then
	echo "Build new image"
	podman build -t localhost/mf-script-launcher-builder .
fi

echo "Build program"
set -x
mkdir -p build
podman run \
	--rm \
	-v ./main.go:/app/main.go:ro \
	-v ./go.mod:/app/go.mod:ro \
	-v ./build:/app/build:rw \
	localhost/mf-script-launcher-builder \
	/bin/sh -c 'cd /app && go build && cp mf-script-launcher /app/build/mf-script-launcher.alpine'

