FROM golang:alpine as builder
RUN mkdir /build
ADD . /build/
WORKDIR /build
RUN go build -o jwt-middleware-test .
FROM alpine
RUN apk add curl
RUN adduser -S -D -H -h /app appuser
USER root
COPY --from=builder /build/jwt-middleware-test /app/
# COPY /env/config.json /app/
WORKDIR /app
ENTRYPOINT ["./jwt-middleware-test"]