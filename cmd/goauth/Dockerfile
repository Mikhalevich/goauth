FROM golang:latest

WORKDIR /go/src/github.com/Mikhalevich/goauth/cmd/goauth
COPY . .

RUN go get -d -v ./...
RUN go build

CMD ./goauth
