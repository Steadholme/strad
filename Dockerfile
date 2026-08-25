# syntax=docker/dockerfile:1.7
ARG STRAD_RUST_BUILDER_IMAGE
ARG STRAD_RUNTIME_IMAGE

FROM ${STRAD_RUST_BUILDER_IMAGE} AS builder
ARG STRAD_RUST_BUILDER_IMAGE
ARG STRAD_RUNTIME_IMAGE
ARG STRAD_REVISION
RUN case "${STRAD_RUST_BUILDER_IMAGE}" in *@sha256:*) ;; *) exit 64 ;; esac \
 && case "${STRAD_RUNTIME_IMAGE}" in *@sha256:*) ;; *) exit 64 ;; esac \
 && builder_digest="${STRAD_RUST_BUILDER_IMAGE##*@sha256:}" \
 && runtime_digest="${STRAD_RUNTIME_IMAGE##*@sha256:}" \
 && test "${#builder_digest}" -eq 64 \
 && test "${#runtime_digest}" -eq 64 \
 && ! printf '%s' "${builder_digest}" | grep -q '[^0-9a-f]' \
 && ! printf '%s' "${runtime_digest}" | grep -q '[^0-9a-f]' \
 && case "${STRAD_REVISION}" in ????????????????????????????????????????) ;; *) exit 64 ;; esac \
 && ! printf '%s' "${STRAD_REVISION}" | grep -q '[^0-9a-f]'

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY migrations/ ./migrations/
COPY src/ ./src/
RUN cargo build --locked --release --bin strad \
 && test -x /build/target/release/strad

FROM ${STRAD_RUNTIME_IMAGE} AS runtime
ARG STRAD_REVISION
LABEL org.opencontainers.image.title="Strad" \
      org.opencontainers.image.description="Rikune AI binary analysis workbench" \
      org.opencontainers.image.revision="${STRAD_REVISION}"
WORKDIR /app
COPY --from=builder --chown=65532:65532 /build/target/release/strad /app/strad
COPY --chown=65532:65532 templates/ /app/templates/
COPY --chown=65532:65532 static/ /app/static/
USER 65532:65532
EXPOSE 9360
ENTRYPOINT ["/app/strad"]
HEALTHCHECK --interval=15s --timeout=5s --start-period=15s --retries=3 \
  CMD ["/app/strad", "healthcheck"]
