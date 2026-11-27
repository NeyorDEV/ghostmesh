# GhostMesh relay + rendezvous server.
#
#   docker build -t ghost-relay .
#   docker run -d --name ghost-relay --restart unless-stopped \
#       -p 8443:8443 -p 8444:8444 -v ghost-relay-data:/data ghost-relay
#
# The relay private key lives in the /data volume (ghost-relay.key). Read the public key to give to
# clients from the first lines of `docker logs ghost-relay`.

FROM rust:1-slim AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p ghost-relay

FROM debian:stable-slim
RUN useradd --system --create-home --home-dir /data ghost
COPY --from=build /src/target/release/ghost-relay /usr/local/bin/ghost-relay
USER ghost
WORKDIR /data
VOLUME /data
EXPOSE 8443/tcp 8444/tcp
ENTRYPOINT ["ghost-relay", "--listen", "0.0.0.0:8443", "--rendezvous-listen", "0.0.0.0:8444", "--key-file", "/data/ghost-relay.key"]
