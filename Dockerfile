FROM alpine
WORKDIR /app
RUN apk update && apk add go

