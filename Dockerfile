FROM golang:1.27.4-bookworm AS build
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY scripts/build ./scripts/build
ARG SOLOID_VERSION=""
ARG SOLOID_COMMIT="unknown"
RUN go run ./scripts/build -o /out/soloid

FROM gcr.io/distroless/static-debian12:nonroot
ENV PORT=3000
COPY --from=build /out/soloid /soloid
USER 65532:65532
EXPOSE 3000
ENTRYPOINT ["/soloid"]
CMD ["serve"]
