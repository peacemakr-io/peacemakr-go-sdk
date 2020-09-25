FROM golang:alpine

RUN apk add build-base
RUN mkdir /peacemakr
WORKDIR /peacemakr

ADD example.go .
ADD go.mod .


RUN go mod verify
RUN go install ./example.go

CMD /go/bin/example

