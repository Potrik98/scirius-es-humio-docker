BUILD_REMOTE=false
tag="$1"
dockerfile="Dockerfile_${1}"
if "$BUILD_REMOTE"; then
    echo "=> Building docker image for $tag at remote"
    IMAGE_TAG="scirius:$tag" REMOTE_PATH="/home/debbie/_docker_build" REMOTE="srv.cyg.no" docker-build-remote . || exit "$?"
else
    echo "=> Building docker image for $tag"
    docker build -f "Dockerfile_${tag}" -t "scirius:$tag"  .|| exit "$?"
fi
