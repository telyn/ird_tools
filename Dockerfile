FROM debian:13 AS builder

RUN apt-get update -y \
 && apt-get install -y gcc make libz-dev

COPY . /irdtools

RUN cd /irdtools \
 && make

FROM debian:13

COPY --from=builder /irdtools/ird_tools /usr/bin/ird_tools

RUN apt-get update -y \
 && apt-get install -y zlib1g \
 && apt-get clean

WORKDIR /data
