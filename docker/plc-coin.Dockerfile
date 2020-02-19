FROM packages.plc.sits.pro/plc-blockchain/debian-9-platincoin-base:latest

ARG PLATINCOIN_VERSION

ENV PLATINCOIN_VERSION=$PLATINCOIN_VERSION
ENV PLATINCOIN_DATA=/home/platincoin/.platincoin

COPY docker/docker-entrypoint.sh /entrypoint.sh
COPY build/debian/usr/local/bin/platincoind /usr/bin/platincoind
COPY build/debian/usr/local/bin/platincoin-cli /usr/bin/platincoin-cli

RUN chmod 755 /entrypoint.sh

VOLUME ["/home/platincoin/.platincoin"]

EXPOSE 19330 19331

ENTRYPOINT ["/entrypoint.sh"]

CMD ["platincoind"]