# WTF version is this?
# go look at, https://quay.io/repository/goswagger/swagger?tab=tags
docker pull quay.io/goswagger/swagger:0.15.0

DOCKER_WORKDIR=/go/src/github.com/notasecret/peacemakr-go-sdk

swagger() {
	echo "running swagger command with args: $@"
	ID=`id -u`
	GID=`id -g`
	docker run --rm -it -e GOPATH="/go" -u="$ID:$GID" -v $(pwd):${DOCKER_WORKDIR} -w ${DOCKER_WORKDIR} quay.io/goswagger/swagger:0.15.0 "$@"
}

swagger "$@"
