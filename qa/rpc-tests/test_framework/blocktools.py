#!/usr/bin/env python3
# blocktools.py - utilities for manipulating blocks and transactions
# Copyright (c) 2015-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from .mininode import *
from .script import CScript, OP_TRUE, OP_CHECKSIG, OP_RETURN, OP_HASH160, OP_EQUAL, GetP2SHMoneyboxScript
from .util import *
import binascii

# Create a block (with regtest difficulty)
def create_block(hashprev, coinbase, nTime=None):
    block = CBlock()
    if nTime is None:
        import time
        block.nTime = int(time.time()+600)
    else:
        block.nTime = nTime
    block.hashPrevBlock = hashprev
    block.nBits = 0x1f7fffff # Will break after a difficulty adjustment...
    block.vtx.append(coinbase)
    block.hashMerkleRoot = block.calc_merkle_root()
    block.calc_sha256()
    return block

# From BIP141
WITNESS_COMMITMENT_HEADER = b"\xaa\x21\xa9\xed"

# According to BIP141, blocks with witness rules active must commit to the
# hash of all in-block transactions including witness.
def add_witness_commitment(block, nonce=0):
    # First calculate the merkle root of the block's
    # transactions, with witnesses.
    witness_nonce = nonce
    witness_root = block.calc_witness_merkle_root()
    witness_commitment = uint256_from_str(hash256(ser_uint256(witness_root)+ser_uint256(witness_nonce)))
    # witness_nonce should go to coinbase witness.
    block.vtx[0].wit.vtxinwit = [CTxInWitness()]
    block.vtx[0].wit.vtxinwit[0].scriptWitness.stack = [ser_uint256(witness_nonce)]

    # witness commitment is the last OP_RETURN output in coinbase
    output_data = WITNESS_COMMITMENT_HEADER + ser_uint256(witness_commitment)
    block.vtx[0].vout.append(CTxOut(0, CScript([OP_RETURN, output_data])))
    block.vtx[0].rehash()
    block.hashMerkleRoot = block.calc_merkle_root()
    block.rehash()


def serialize_script_num(value):
    r = bytearray(0)
    if value == 0:
        return r
    neg = value < 0
    absvalue = -value if neg else value
    while (absvalue):
        r.append(int(absvalue & 0xff))
        absvalue >>= 8
    if r[-1] & 0x80:
        r.append(0x80 if neg else 0)
    elif neg:
        r[-1] |= 0x80
    return r


def get_subsidy(height, minerfees):
    if height <= 100:
        return 6000000*COIN
    return max(500000, int(minerfees / 2))  # int(0.005*COIN)


def get_plc_award(height, refill_moneybox_amount, AWARD_UNIT = 10 * COIN):
    if height <= 100:
        return [AWARD_UNIT] * 10
    outputs = [AWARD_UNIT] * (refill_moneybox_amount // AWARD_UNIT)
    if (refill_moneybox_amount % AWARD_UNIT) > 0:
        outputs.append(refill_moneybox_amount % AWARD_UNIT)
    assert_greater_than_or_equal(10, len(outputs))
    return outputs


# Create a coinbase transaction.
# If pubkey is passed in, the coinbase output will be a P2PK output;
# otherwise an anyone-can-spend output.
def create_coinbase(height, pubkey = None, minerfees = 0, refill_moneybox_amount = 0, granularity = 10 * COIN,
                    moneyboxscript = GetP2SHMoneyboxScript()):
    coinbase = CTransaction()
    coinbase.vin.append(CTxIn(COutPoint(0, 0xffffffff), 
                ser_string(serialize_script_num(height)), 0xffffffff))
    coinbase.vout = []

    subsidy = CTxOut()
    subsidy.nValue = get_subsidy(height, minerfees)
    if (pubkey != None):
        subsidy.scriptPubKey = CScript([pubkey, OP_CHECKSIG])
    else:
        subsidy.scriptPubKey = CScript([OP_TRUE])

    if (subsidy.nValue > 0):
        coinbase.vout.append(subsidy)

    for elem in get_plc_award(height, refill_moneybox_amount, AWARD_UNIT = granularity):
        plcaward = CTxOut()
        plcaward.nValue = elem
        plcaward.scriptPubKey = moneyboxscript
        coinbase.vout.append(plcaward)

    coinbase.calc_sha256()
    return coinbase


# Create a transaction.
# If the scriptPubKey is not specified, make it anyone-can-spend.
def create_transaction(prevtx, n, sig, value, scriptPubKey=CScript()):
    tx = CTransaction()
    assert(n < len(prevtx.vout))
    tx.vin.append(CTxIn(COutPoint(prevtx.sha256, n), sig, 0xffffffff))
    tx.vout.append(CTxOut(value, scriptPubKey))
    tx.calc_sha256()
    return tx

def get_legacy_sigopcount_block(block, fAccurate=True):
    count = 0
    for tx in block.vtx:
        count += get_legacy_sigopcount_tx(tx, fAccurate)
    return count

def get_legacy_sigopcount_tx(tx, fAccurate=True):
    count = 0
    for i in tx.vout:
        count += i.scriptPubKey.GetSigOpCount(fAccurate)
    for j in tx.vin:
        # scriptSig might be of type bytes, so convert to CScript for the moment
        count += CScript(j.scriptSig).GetSigOpCount(fAccurate)
    return count
