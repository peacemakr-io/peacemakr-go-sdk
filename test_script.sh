set -ex

rm -rf /tmp/.peacemakr && sleep 1
time echo "hello secure world" | go run example.go persister.go --action=encrypt | go run example.go persister.go --action=decrypt
rm -rf /tmp/.peacemakr && sleep 1
time echo "hello secure world" | go run example.go persister.go --action=encrypt | go run example.go persister.go --action=decrypt
time echo "hello secure world" | go run example.go persister.go --action=encrypt | go run example.go persister.go --action=decrypt
