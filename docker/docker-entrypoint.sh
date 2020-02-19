#!/bin/sh
set -e

if [ $(echo "$1" | cut -c1) = "-" ]; then
    echo "$0: assuming arguments for platincoind"
    
    set -- platincoind "$@"
fi

if [ $(echo "$1" | cut -c1) = "-" ] || [ "$1" = "platincoind" ]; then
    mkdir -p "$PLATINCOIN_DATA"
    chmod 770 "$PLATINCOIN_DATA" || echo "Could notchmod $PLATINCOIN_DATA (may not have appropriate permissions)"
    chown -R platincoin "$PLATINCOIN_DATA" || echo "Could notchown $PLATINCOIN_DATA (may not have appropriate permissions)"
    
    echo "$0: setting data directory to $PLATINCOIN_DATA"
    
    set -- "$@" -datadir="$PLATINCOIN_DATA"
fi

exec "$@"