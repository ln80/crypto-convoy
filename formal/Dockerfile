# Tamarin and Maude for check:formal on machines with no native build (Intel macOS): plan 027.
# Each download is pinned by its SHA-256, recorded when it was first fetched (2026-10-30).
FROM ubuntu:24.04

RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates curl unzip libgmp10 libffi8 zlib1g graphviz \
  && rm -rf /var/lib/apt/lists/*

ARG TAMARIN=https://github.com/tamarin-prover/tamarin-prover/releases/download/1.12.0/tamarin-prover-1.12.0-linux64-ubuntu.tar.gz
ARG TAMARIN_SHA256=201be06f469e47cff554df6ca93db8366fc2c69d70c61fcbd1370a1074b469c6
ARG MAUDE=https://github.com/maude-lang/Maude/releases/download/Maude3.5.1/Maude-3.5.1-linux-x86_64.zip
ARG MAUDE_SHA256=72ed1ca87e3b3d0dfc6ee1436baf154bf04c45ff97d521bec040c5e8dfc8f92c

RUN curl -fsSL -o /tmp/tamarin.tar.gz "$TAMARIN" \
  && echo "$TAMARIN_SHA256  /tmp/tamarin.tar.gz" | sha256sum -c - \
  && tar -xzf /tmp/tamarin.tar.gz -C /usr/local/bin tamarin-prover \
  && curl -fsSL -o /tmp/maude.zip "$MAUDE" \
  && echo "$MAUDE_SHA256  /tmp/maude.zip" | sha256sum -c - \
  && mkdir -p /opt/maude && unzip -q /tmp/maude.zip -d /opt/maude \
  && ln -s /opt/maude/maude /usr/local/bin/maude \
  && rm /tmp/tamarin.tar.gz /tmp/maude.zip

ENV MAUDE_LIB=/opt/maude LANG=C.UTF-8 LC_ALL=C.UTF-8
WORKDIR /formal
ENTRYPOINT ["tamarin-prover"]
