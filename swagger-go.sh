# WTF version is this?
# go look at, https://quay.io/repository/goswagger/swagger?tab=tags
docker pull quay.io/goswagger/swagger:0.15.0

swagger() {
	echo "running swagger command with args: $@"
	ID=`id -u`
	GID=`id -g`
	docker run --rm -it -e GOPATH="$(pwd):/go" -u="$ID:$GID" -v $HOME:$HOME -w $(pwd) quay.io/goswagger/swagger:0.15.0 "$@"
}

swagger "$@"
