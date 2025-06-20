FROM alpine:latest
RUN apk add --no-cache cabal ghc ca-certificates
WORKDIR /anonymos
COPY userland/shell /anonymos/userland/shell
RUN cd userland/shell && cabal update && cabal build
CMD ["/bin/bash"]
