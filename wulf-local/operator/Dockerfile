FROM golang:1.26-bookworm AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/wulf-local-operator ./cmd/wulf-local-operator

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/wulf-local-operator /wulf-local-operator
USER 65532:65532
ENTRYPOINT ["/wulf-local-operator"]
