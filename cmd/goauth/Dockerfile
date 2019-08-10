FROM golang:latest as builder

RUN go get -u github.com/Mikhalevich/argparser
RUN go get -u github.com/Mikhalevich/goauth
RUN go get -u github.com/lib/pq
RUN go get -u gopkg.in/gomail.v2

WORKDIR /go/src/github.com/Mikhalevich/goauth/cmd/goauth
COPY . .
#RUN go get -d -v ./...
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -installsuffix cgo -ldflags="-w -s" -o /go/bin/goauth

FROM scratch
COPY --from=builder /go/bin/goauth /go/bin/goauth
COPY --from=builder /go/src/github.com/Mikhalevich/goauth/cmd/goauth/config.json /go/bin/config.json
COPY --from=builder /go/src/github.com/Mikhalevich/goauth/cmd/goauth/html /go/bin/html
EXPOSE 8080
ENTRYPOINT ["/go/bin/goauth", "-config=/go/bin/config.json"]
