FROM golang:latest as builder
WORKDIR /go/src/github.com/Mikhalevich/goauth/cmd/goauth
COPY . .
RUN go get -d -v ./...
RUN go CGO_ENABLED=0 GOOS=linux GOARCH=amd64 build -a -installsuffix cgo -ldflags="-w -s" -o /go/bin/goauth

FROM scratch
COPY --from=builder /go/bin/goauth /go/bin/goauth
EXPOSE 8080
ENTRYPOINT ["/go/bin/goauth"]
