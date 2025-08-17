FROM gcr.io/distroless/cc-debian12:latest AS object
FROM ubuntu:latest AS builder
RUN apt-get update && apt-get install -y binutils
RUN mkdir -p /fake
RUN mkdir -p /work
RUN mkdir -p /ldwork
COPY --from=object /usr/lib/*-linux-gnu/lib*.so* /fake/
COPY --from=object /lib/*-linux-gnu/lib*.so* /fake/
COPY --from=object /lib*/ld-linux*.so* /ldwork/
COPY .out out
RUN if [ "$(arch)" = "x86_64" ]; then \
        mv /out/ndns-amd64 /work/binary; \
    else \
        mv /out/ndns-arm64 /work/binary; \
    fi
RUN ldd /work/binary | grep "=> /" | awk '{print $3}' | xargs -n1 basename | xargs -I{} cp "/fake/{}" /work/
RUN strip /work/*.so*
FROM scratch
COPY --from=builder /work /work
COPY --from=builder /ldwork /lib64
COPY --from=builder /ldwork /lib
ENV LD_LIBRARY_PATH=/work
ENTRYPOINT ["/work/binary"]