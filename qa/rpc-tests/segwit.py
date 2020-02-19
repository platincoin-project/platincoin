#!/usr/bin/env python3
# Copyright (c) 2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

#
# Test the SegWit changeover logic
#

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
from test_framework.mininode import sha256, ripemd160, CTransaction, CTxIn, COutPoint, CTxOut
from test_framework.address import script_to_p2sh, key_to_p2pkh
from test_framework.script import CScript, OP_HASH160, OP_CHECKSIG, OP_0, hash160, OP_EQUAL, OP_DUP, OP_EQUALVERIFY, OP_1, OP_2, OP_CHECKMULTISIG, OP_TRUE
from io import BytesIO
from test_framework.mininode import ToHex, FromHex, COIN

NODE_0 = 0
NODE_1 = 1
NODE_2 = 2
WIT_V0 = 0
WIT_V1 = 1

def witness_script(version, pubkey):
    if (version == 0):
        pubkeyhash = bytes_to_hex_str(ripemd160(sha256(hex_str_to_bytes(pubkey))))
        pkscript = "0014" + pubkeyhash
    elif (version == 1):
        # 1-of-1 multisig
        scripthash = bytes_to_hex_str(sha256(hex_str_to_bytes("5121" + pubkey + "51ae")))
        pkscript = "0020" + scripthash
    else:
        assert("Wrong version" == "0 or 1")
    return pkscript

def addlength(script):
    scriptlen = format(len(script)//2, 'x')
    assert(len(scriptlen) == 2)
    return scriptlen + script

def create_witnessprogram(version, node, utxo, pubkey, encode_p2sh, amount):
    pkscript = witness_script(version, pubkey)
    if (encode_p2sh):
        p2sh_hash = bytes_to_hex_str(ripemd160(sha256(hex_str_to_bytes(pkscript))))
        pkscript = "a914"+p2sh_hash+"87"
    inputs = []
    outputs = {}
    inputs.append({ "txid" : utxo["txid"], "vout" : utxo["vout"]} )
    DUMMY_P2SH = "P4tGp8vqTE2Jf65iNZMxr3LBH8Yzpw1jD3L5" # P2SH of "OP_4"
    outputs[DUMMY_P2SH] = amount
    tx_to_witness = node.createrawtransaction(inputs,outputs)
    #replace dummy output with our own
    tx_to_witness = tx_to_witness[0:110] + addlength(pkscript) + tx_to_witness[-8:]
    return tx_to_witness

def send_to_witness(version, node, utxo, pubkey, encode_p2sh, amount, sign=True, insert_redeem_script=""):
    tx_to_witness = create_witnessprogram(version, node, utxo, pubkey, encode_p2sh, amount)
    if (sign):
        signed = node.signrawtransaction(tx_to_witness)
        assert("errors" not in signed or len(["errors"]) == 0)
        return node.sendrawtransaction(signed["hex"])
    else:
        if (insert_redeem_script):
            tx_to_witness = tx_to_witness[0:82] + addlength(insert_redeem_script) + tx_to_witness[84:]

    return node.sendrawtransaction(tx_to_witness)


def getutxo(node, txid):
    for utxo in node.listunspent():
        if utxo["txid"] == txid:
            return utxo


def find_unspent(node, min_value=0):
    for utxo in node.listunspent():
        if min_value == 0:
            return utxo
        if utxo['amount'] >= min_value:
            return utxo


class SegWitTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True
        self.num_nodes = 3

    def setup_network(self):
        self.nodes = []
        self.nodes.append(start_node(0, self.options.tmpdir, ["-logtimemicros", "-debug", "-walletprematurewitness", "-rpcserialversion=0"]))
        self.nodes.append(start_node(1, self.options.tmpdir, ["-logtimemicros", "-debug", "-blockversion=4", "-promiscuousmempoolflags=517", "-prematurewitness", "-walletprematurewitness", "-rpcserialversion=1"]))
        self.nodes.append(start_node(2, self.options.tmpdir, ["-logtimemicros", "-debug", "-blockversion=536870915", "-promiscuousmempoolflags=517", "-prematurewitness", "-walletprematurewitness"]))
        connect_nodes(self.nodes[1], 0)
        connect_nodes(self.nodes[2], 1)
        connect_nodes(self.nodes[0], 2)
        self.is_network_split = False
        self.sync_all()

    def success_mine(self, node, txid, sign, redeem_script=""):
        utxo = getutxo(node, txid)
        send_to_witness(1, node, utxo, self.pubkey[0], False, utxo['amount'] - Decimal("0.001"), sign, redeem_script)
        block = node.generate(1)
        assert_equal(len(node.getblock(block[0])["tx"]), 2)
        sync_blocks(self.nodes)

    def skip_mine(self, node, txid, sign, redeem_script=""):
        utxo = getutxo(node, txid)
        send_to_witness(1, node, utxo, self.pubkey[0], False, utxo['amount'] - Decimal("0.001"), sign, redeem_script)
        block = node.generate(1)
        assert_equal(len(node.getblock(block[0])["tx"]), 1)
        sync_blocks(self.nodes)

    def fail_accept(self, node, txid, sign, redeem_script=""):
        try:
            send_to_witness(1, node, getutxo(node, txid), self.pubkey[0], False, Decimal("49.998"), sign, redeem_script)
        except JSONRPCException as exp:
            assert(exp.error["code"] == -26)
        else:
            raise AssertionError("Tx should not have been accepted")

    def fail_mine(self, node, txid, sign, redeem_script=""):
        utxo = getutxo(node, txid)
        send_to_witness(1, node, utxo, self.pubkey[0], False, utxo['amount'] - Decimal("0.001"), sign, redeem_script)
        try:
            node.generate(1)
        except JSONRPCException as exp:
            assert(exp.error["code"] == -1)
        else:
            raise AssertionError("Created valid block when TestBlockValidity should have failed")
        sync_blocks(self.nodes)

    def run_test(self):
        self.nodes[0].generate(10)
        self.nodes[0].generate(100)
        self.nodes[0].generate(51) #block 161

        print("Verify sigops are counted in GBT with pre-BIP141 rules before the fork")
        txid = self.nodes[0].sendtoaddress(self.nodes[0].getnewaddress(), 1)
        tmpl = self.nodes[0].getblocktemplate({})
        assert_equal(tmpl['sizelimit'], 1000000)
        assert('weightlimit' not in tmpl)
        assert_equal(tmpl['sigoplimit'], 20000)
        assert_equal(tmpl['transactions'][0]['hash'], txid)
        assert_equal(tmpl['transactions'][0]['sigops'], 2)
        tmpl = self.nodes[0].getblocktemplate({'rules':['segwit']})
        assert_equal(tmpl['sizelimit'], 1000000)
        assert('weightlimit' not in tmpl)
        assert_equal(tmpl['sigoplimit'], 20000)
        assert_equal(tmpl['transactions'][0]['hash'], txid)
        assert_equal(tmpl['transactions'][0]['sigops'], 2)
        self.nodes[0].generate(1) #block 162

        balance_presetup = self.nodes[0].getbalance()
        self.pubkey = []
        p2sh_ids = [] # p2sh_ids[NODE][VER] is an array of txids that spend to a witness version VER pkscript to an address for NODE embedded in p2sh
        wit_ids = [] # wit_ids[NODE][VER] is an array of txids that spend to a witness version VER pkscript to an address for NODE via bare witness
        for i in range(3):
            newaddress = self.nodes[i].getnewaddress()
            self.pubkey.append(self.nodes[i].validateaddress(newaddress)["pubkey"])
            multiaddress = self.nodes[i].addmultisigaddress(1, [self.pubkey[-1]])
            self.nodes[i].addwitnessaddress(newaddress)
            self.nodes[i].addwitnessaddress(multiaddress)
            p2sh_ids.append([])
            wit_ids.append([])
            for v in range(2):
                p2sh_ids[i].append([])
                wit_ids[i].append([])

        amounts = []
        for n in range(3):
            amounts.append(0)

        for i in range(5):
            for n in range(3):
                for v in range(2):
                    utxo = find_unspent(self.nodes[0])
                    amounts[n] += utxo['amount']-Decimal("0.001")
                    wit_ids[n][v].append(send_to_witness(v, self.nodes[0], utxo, self.pubkey[n], False, utxo['amount']-Decimal("0.001")))
                    utxo = find_unspent(self.nodes[0])
                    amounts[n] += utxo['amount']-Decimal("0.001")
                    p2sh_ids[n][v].append(send_to_witness(v, self.nodes[0], utxo, self.pubkey[n], True, utxo['amount']-Decimal("0.001")))

        self.nodes[0].generate(1) #block 163
        sync_blocks(self.nodes)

        # Make sure all nodes recognize the transactions as theirs
        # unknown fee
        assert_equal(self.nodes[1].getbalance(), amounts[1]) # 20*Decimal("49.999"))
        assert_equal(self.nodes[2].getbalance(), amounts[2]) # 20*Decimal("49.999"))

        self.nodes[0].generate(260) #block 423
        sync_blocks(self.nodes)

        print("Verify default node can't accept any witness format txs before fork")
        # unsigned, no scriptsig
        self.fail_accept(self.nodes[0], wit_ids[NODE_0][WIT_V0][0], False)
        self.fail_accept(self.nodes[0], wit_ids[NODE_0][WIT_V1][0], False)
        self.fail_accept(self.nodes[0], p2sh_ids[NODE_0][WIT_V0][0], False)
        self.fail_accept(self.nodes[0], p2sh_ids[NODE_0][WIT_V1][0], False)
        # unsigned with redeem script
        self.fail_accept(self.nodes[0], p2sh_ids[NODE_0][WIT_V0][0], False, addlength(witness_script(0, self.pubkey[0])))
        self.fail_accept(self.nodes[0], p2sh_ids[NODE_0][WIT_V1][0], False, addlength(witness_script(1, self.pubkey[0])))
        # signed
        self.fail_accept(self.nodes[0], wit_ids[NODE_0][WIT_V0][0], True)
        self.fail_accept(self.nodes[0], wit_ids[NODE_0][WIT_V1][0], True)
        self.fail_accept(self.nodes[0], p2sh_ids[NODE_0][WIT_V0][0], True)
        self.fail_accept(self.nodes[0], p2sh_ids[NODE_0][WIT_V1][0], True)

        print("Verify witness txs are skipped for mining before the fork")
        self.skip_mine(self.nodes[2], wit_ids[NODE_2][WIT_V0][0], True) #block 424
        self.skip_mine(self.nodes[2], wit_ids[NODE_2][WIT_V1][0], True) #block 425
        self.skip_mine(self.nodes[2], p2sh_ids[NODE_2][WIT_V0][0], True) #block 426
        self.skip_mine(self.nodes[2], p2sh_ids[NODE_2][WIT_V1][0], True) #block 427

        # TODO: An old node would see these txs without witnesses and be able to mine them

        print("Verify unsigned bare witness txs in versionbits-setting blocks are valid before the fork")
        self.success_mine(self.nodes[2], wit_ids[NODE_2][WIT_V0][1], False) #block 428
        self.success_mine(self.nodes[2], wit_ids[NODE_2][WIT_V1][1], False) #block 429

        print("Verify unsigned p2sh witness txs without a redeem script are invalid")
        self.fail_accept(self.nodes[2], p2sh_ids[NODE_2][WIT_V0][1], False)
        self.fail_accept(self.nodes[2], p2sh_ids[NODE_2][WIT_V1][1], False)

        print("Verify unsigned p2sh witness txs with a redeem script in versionbits-settings blocks are valid before the fork")
        self.success_mine(self.nodes[2], p2sh_ids[NODE_2][WIT_V0][1], False, addlength(witness_script(0, self.pubkey[2]))) #block 430
        self.success_mine(self.nodes[2], p2sh_ids[NODE_2][WIT_V1][1], False, addlength(witness_script(1, self.pubkey[2]))) #block 431

        print("Verify previous witness txs skipped for mining can now be mined")
        assert_equal(len(self.nodes[2].getrawmempool()), 4)
        block = self.nodes[2].generate(1)  # block 432 (first block with new rules; 432 = 144 * 3)
        sync_blocks(self.nodes)
        assert_equal(len(self.nodes[2].getrawmempool()), 0)
        segwit_tx_list = self.nodes[2].getblock(block[0])["tx"]
        assert_equal(len(segwit_tx_list), 5)

        print("Verify block and transaction serialization rpcs return differing serializations depending on rpc serialization flag")
        assert (self.nodes[2].getblock(block[0], False) != self.nodes[0].getblock(block[0], False))
        assert (self.nodes[1].getblock(block[0], False) == self.nodes[2].getblock(block[0], False))
        for txid in segwit_tx_list:
            tx = FromHex(CTransaction(), self.nodes[2].gettransaction(txid)["hex"])
            assert(self.nodes[2].getrawtransaction(txid) != self.nodes[0].getrawtransaction(txid))
            assert(self.nodes[1].getrawtransaction(txid, 0) == self.nodes[2].getrawtransaction(txid))
            assert(self.nodes[0].getrawtransaction(txid) != self.nodes[2].gettransaction(txid)["hex"])
            assert(self.nodes[1].getrawtransaction(txid) == self.nodes[2].gettransaction(txid)["hex"])
            assert(self.nodes[0].getrawtransaction(txid) == bytes_to_hex_str(tx.serialize_without_witness()))

        print("Verify witness txs without witness data are invalid after the fork")
        self.fail_mine(self.nodes[2], wit_ids[NODE_2][WIT_V0][2], False)
        self.fail_mine(self.nodes[2], wit_ids[NODE_2][WIT_V1][2], False)
        self.fail_mine(self.nodes[2], p2sh_ids[NODE_2][WIT_V0][2], False, addlength(witness_script(0, self.pubkey[2])))
        self.fail_mine(self.nodes[2], p2sh_ids[NODE_2][WIT_V1][2], False, addlength(witness_script(1, self.pubkey[2])))

        print("Verify default node can now use witness txs")
        self.success_mine(self.nodes[0], wit_ids[NODE_0][WIT_V0][0], True) #block 432
        self.success_mine(self.nodes[0], wit_ids[NODE_0][WIT_V1][0], True) #block 433
        self.success_mine(self.nodes[0], p2sh_ids[NODE_0][WIT_V0][0], True) #block 434
        self.success_mine(self.nodes[0], p2sh_ids[NODE_0][WIT_V1][0], True) #block 435

        print("Verify sigops are counted in GBT with BIP141 rules after the fork")
        txid = self.nodes[0].sendtoaddress(self.nodes[0].getnewaddress(), 1)
        tmpl = self.nodes[0].getblocktemplate({'rules':['segwit']})
        assert_greater_than_or_equal(tmpl['sizelimit'], 3999577)  # actual maximum size is lower due to minimum mandatory non-witness data
        assert_equal(tmpl['weightlimit'], 4000000)
        assert_equal(tmpl['sigoplimit'], 80000)
        assert_equal(tmpl['transactions'][0]['txid'], txid)
        #assert_equal(tmpl['transactions'][0]['sigops'], 8)

        self.nodes[0].generate(1) # Mine a block to clear the gbt cache

        print("Non-segwit miners are able to use GBT response after activation.")
        # Create a 3-tx chain: tx1 (non-segwit input, paying to a segwit output) ->
        #                      tx2 (segwit input, paying to a non-segwit output) ->
        #                      tx3 (non-segwit input, paying to a non-segwit output).
        # tx1 is allowed to appear in the block, but no others.
        txid1 = send_to_witness(1, self.nodes[0], find_unspent(self.nodes[0], 6000000), self.pubkey[0], False, Decimal('5999999.99'))
        hex_tx = self.nodes[0].gettransaction(txid)['hex']
        tx = FromHex(CTransaction(), hex_tx)
        assert(tx.wit.is_null()) # This should not be a segwit input
        assert(txid1 in self.nodes[0].getrawmempool())

        # Now create tx2, which will spend from txid1.
        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(int(txid1, 16), 0), b''))
        tx.vout.append(CTxOut(int(5999999.98*COIN), CScript([OP_TRUE])))
        tx2_hex = self.nodes[0].signrawtransaction(ToHex(tx))['hex']
        txid2 = self.nodes[0].sendrawtransaction(tx2_hex)
        tx = FromHex(CTransaction(), tx2_hex)
        assert(not tx.wit.is_null())

        # Now create tx3, which will spend from txid2
        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(int(txid2, 16), 0), b""))
        tx.vout.append(CTxOut(int(5999999.95*COIN), CScript([OP_TRUE]))) # Huge fee
        tx.calc_sha256()
        txid3 = self.nodes[0].sendrawtransaction(ToHex(tx))
        assert(tx.wit.is_null())
        assert(txid3 in self.nodes[0].getrawmempool())

        # Now try calling getblocktemplate() without segwit support.
        template = self.nodes[0].getblocktemplate()

        # Check that tx1 is the only transaction of the 3 in the template.
        template_txids = [ t['txid'] for t in template['transactions'] ]
        assert(txid2 not in template_txids and txid3 not in template_txids)
        assert(txid1 in template_txids)

        # Check that running with segwit support results in all 3 being included.
        template = self.nodes[0].getblocktemplate({"rules": ["segwit"]})
        template_txids = [ t['txid'] for t in template['transactions'] ]
        assert(txid1 in template_txids)
        assert(txid2 in template_txids)
        assert(txid3 in template_txids)

        # Mine a block to clear the gbt cache again.
        self.nodes[0].generate(1)

        print("Verify behaviour of importaddress, addwitnessaddress and listunspent")

        # Some public keys to be used later
        pubkeys = [
            "03d7a1cfe0ab9dd0d05fc6900ec42cac0848829157207b951eee4e42d815b41f64", # P4snHKyksXnxK1fwZgXmZjFqWrFQM3emdmaB
            "022280b488da63c7b8417da714add9c32a9fd0174fc263fd24b9e979604b9625d3", # P4sce5u5MUNvb8pfSYMCdvBKSSEb3HcdmKth
            "043d5584722f39263001cbbeb7405c4cf67518a6d4935815ef5077d5faf1e6e2f9a018175e69cad3b9eb715ebda6a3f0cb63fcf631b948b2715cff64ea57eaa967", # P4saDbBzHSya3WDHE9Y5LuAXqd6A6WU7nRqr
            "0228313c98766f455f52d500fe7aa304a7ea4de9058d7f4b1ab8aa1eff287f53a1", # P4serm2Ujghxiv4SujLUhwWq1X1Qb5CUet58
            "02f58eb34e2963698641a82b7c117396d71ff8381e79bf1d7d7e9f6ca7298bb106", # P4sd831Fridto9UPfHvSdg3t6NCVNHMdtcRZ
            "0288c1e7d39af0dd1007c782f61bbf9857b9ad8201e742b6832228b0efe62c334b", # P4soJxqqVJckwfUmfwhZR7pNjGLCFMB6f1fn
            "046b7f10e220adf082ff4f68e7b4102ce875e22e7822d41107ae288ed04295d264acf8665d8b864daa8daa52d642aad3d41ab62462e78750e4a2102381b8018b47", # P4sbmSFoKPv4dXMPKdzitWF54GbBntWgo58y
        ]

        # Import a compressed key and an uncompressed key, generate some multisig addresses
        self.nodes[0].importprivkey("2qeWAQhPFzkVpGF1PhrAmEHH1uNqHn33ofTAdadwvTmDxyay4a8Fa")
        uncompressed_spendable_address = ["P4siJTivGLuDE3yZjz8a4mRdxhsvmLDNoW7x"]
        self.nodes[0].importprivkey("97iVW1Hj95pPwaWzg5WB6opDzExu413G8vRqgHaVQv5qqsC6JHK4Wj")
        compressed_spendable_address = ["P4sdEZYVrButUSE8nF6XFFWatamEPc7XzrV7"]
        assert ((self.nodes[0].validateaddress(uncompressed_spendable_address[0])['iscompressed'] == False))
        assert ((self.nodes[0].validateaddress(compressed_spendable_address[0])['iscompressed'] == True))

        self.nodes[0].importpubkey(pubkeys[0])
        compressed_solvable_address = [key_to_p2pkh(pubkeys[0])]
        self.nodes[0].importpubkey(pubkeys[1])
        compressed_solvable_address.append(key_to_p2pkh(pubkeys[1]))
        self.nodes[0].importpubkey(pubkeys[2])
        uncompressed_solvable_address = [key_to_p2pkh(pubkeys[2])]

        spendable_anytime = []                      # These outputs should be seen anytime after importprivkey and addmultisigaddress
        spendable_after_importaddress = []          # These outputs should be seen after importaddress
        solvable_after_importaddress = []           # These outputs should be seen after importaddress but not spendable
        unsolvable_after_importaddress = []         # These outputs should be unsolvable after importaddress
        solvable_anytime = []                       # These outputs should be solvable after importpubkey
        unseen_anytime = []                         # These outputs should never be seen

        uncompressed_spendable_address.append(self.nodes[0].addmultisigaddress(2, [uncompressed_spendable_address[0], compressed_spendable_address[0]]))
        uncompressed_spendable_address.append(self.nodes[0].addmultisigaddress(2, [uncompressed_spendable_address[0], uncompressed_spendable_address[0]]))
        compressed_spendable_address.append(self.nodes[0].addmultisigaddress(2, [compressed_spendable_address[0], compressed_spendable_address[0]]))
        uncompressed_solvable_address.append(self.nodes[0].addmultisigaddress(2, [compressed_spendable_address[0], uncompressed_solvable_address[0]]))
        compressed_solvable_address.append(self.nodes[0].addmultisigaddress(2, [compressed_spendable_address[0], compressed_solvable_address[0]]))
        compressed_solvable_address.append(self.nodes[0].addmultisigaddress(2, [compressed_solvable_address[0], compressed_solvable_address[1]]))
        unknown_address = ["P4smB3h7Ep9m8wb8ybp4c5xKAcgjXyZvmg3W", "P4tGp8vqTE2Jf65iNZMxr3LBH8Yzpw1jD3L5"]

        # Test multisig_without_privkey
        # We have 2 public keys without private keys, use addmultisigaddress to add to wallet.
        # Money sent to P2SH of multisig of this should only be seen after importaddress with the BASE58 P2SH address.

        multisig_without_privkey_address = self.nodes[0].addmultisigaddress(2, [pubkeys[3], pubkeys[4]])
        script = CScript([OP_2, hex_str_to_bytes(pubkeys[3]), hex_str_to_bytes(pubkeys[4]), OP_2, OP_CHECKMULTISIG])
        solvable_after_importaddress.append(CScript([OP_HASH160, hash160(script), OP_EQUAL]))

        for i in compressed_spendable_address:
            v = self.nodes[0].validateaddress(i)
            if (v['isscript']):
                [bare, p2sh, p2wsh, p2sh_p2wsh] = self.p2sh_address_to_script(v)
                # bare and p2sh multisig with compressed keys should always be spendable
                spendable_anytime.extend([bare, p2sh])
                # P2WSH and P2SH(P2WSH) multisig with compressed keys are spendable after direct importaddress
                spendable_after_importaddress.extend([p2wsh, p2sh_p2wsh])
            else:
                [p2wpkh, p2sh_p2wpkh, p2pk, p2pkh, p2sh_p2pk, p2sh_p2pkh, p2wsh_p2pk, p2wsh_p2pkh, p2sh_p2wsh_p2pk, p2sh_p2wsh_p2pkh] = self.p2pkh_address_to_script(v)
                # normal P2PKH and P2PK with compressed keys should always be spendable
                spendable_anytime.extend([p2pkh, p2pk])
                # P2SH_P2PK, P2SH_P2PKH, and witness with compressed keys are spendable after direct importaddress
                spendable_after_importaddress.extend([p2wpkh, p2sh_p2wpkh, p2sh_p2pk, p2sh_p2pkh, p2wsh_p2pk, p2wsh_p2pkh, p2sh_p2wsh_p2pk, p2sh_p2wsh_p2pkh])

        for i in uncompressed_spendable_address:
            v = self.nodes[0].validateaddress(i)
            if (v['isscript']):
                [bare, p2sh, p2wsh, p2sh_p2wsh] = self.p2sh_address_to_script(v)
                # bare and p2sh multisig with uncompressed keys should always be spendable
                spendable_anytime.extend([bare, p2sh])
                # P2WSH and P2SH(P2WSH) multisig with uncompressed keys are never seen
                unseen_anytime.extend([p2wsh, p2sh_p2wsh])
            else:
                [p2wpkh, p2sh_p2wpkh, p2pk, p2pkh, p2sh_p2pk, p2sh_p2pkh, p2wsh_p2pk, p2wsh_p2pkh, p2sh_p2wsh_p2pk, p2sh_p2wsh_p2pkh] = self.p2pkh_address_to_script(v)
                # normal P2PKH and P2PK with uncompressed keys should always be spendable
                spendable_anytime.extend([p2pkh, p2pk])
                # P2SH_P2PK and P2SH_P2PKH are spendable after direct importaddress
                spendable_after_importaddress.extend([p2sh_p2pk, p2sh_p2pkh])
                # witness with uncompressed keys are never seen
                unseen_anytime.extend([p2wpkh, p2sh_p2wpkh, p2wsh_p2pk, p2wsh_p2pkh, p2sh_p2wsh_p2pk, p2sh_p2wsh_p2pkh])

        for i in compressed_solvable_address:
            v = self.nodes[0].validateaddress(i)
            if (v['isscript']):
                # Multisig without private is not seen after addmultisigaddress, but seen after importaddress
                [bare, p2sh, p2wsh, p2sh_p2wsh] = self.p2sh_address_to_script(v)
                solvable_after_importaddress.extend([bare, p2sh, p2wsh, p2sh_p2wsh])
            else:
                [p2wpkh, p2sh_p2wpkh, p2pk, p2pkh, p2sh_p2pk, p2sh_p2pkh, p2wsh_p2pk, p2wsh_p2pkh, p2sh_p2wsh_p2pk, p2sh_p2wsh_p2pkh] = self.p2pkh_address_to_script(v)
                # normal P2PKH and P2PK with compressed keys should always be seen
                solvable_anytime.extend([p2pkh, p2pk])
                # P2SH_P2PK, P2SH_P2PKH, and witness with compressed keys are seen after direct importaddress
                solvable_after_importaddress.extend([p2wpkh, p2sh_p2wpkh, p2sh_p2pk, p2sh_p2pkh, p2wsh_p2pk, p2wsh_p2pkh, p2sh_p2wsh_p2pk, p2sh_p2wsh_p2pkh])

        for i in uncompressed_solvable_address:
            v = self.nodes[0].validateaddress(i)
            if (v['isscript']):
                [bare, p2sh, p2wsh, p2sh_p2wsh] = self.p2sh_address_to_script(v)
                # Base uncompressed multisig without private is not seen after addmultisigaddress, but seen after importaddress
                solvable_after_importaddress.extend([bare, p2sh])
                # P2WSH and P2SH(P2WSH) multisig with uncompressed keys are never seen
                unseen_anytime.extend([p2wsh, p2sh_p2wsh])
            else:
                [p2wpkh, p2sh_p2wpkh, p2pk, p2pkh, p2sh_p2pk, p2sh_p2pkh, p2wsh_p2pk, p2wsh_p2pkh, p2sh_p2wsh_p2pk, p2sh_p2wsh_p2pkh] = self.p2pkh_address_to_script(v)
                # normal P2PKH and P2PK with uncompressed keys should always be seen
                solvable_anytime.extend([p2pkh, p2pk])
                # P2SH_P2PK, P2SH_P2PKH with uncompressed keys are seen after direct importaddress
                solvable_after_importaddress.extend([p2sh_p2pk, p2sh_p2pkh])
                # witness with uncompressed keys are never seen
                unseen_anytime.extend([p2wpkh, p2sh_p2wpkh, p2wsh_p2pk, p2wsh_p2pkh, p2sh_p2wsh_p2pk, p2sh_p2wsh_p2pkh])

        op1 = CScript([OP_1])
        op0 = CScript([OP_0])
        unsolvable_address = ["P4srB1NDJkwyJ6LgTfyHM5kcx9aYuc3HJALg", "P4tGp8vqTE2Jf65iNZMxr3LBH8Yzpw1jD3L5", script_to_p2sh(op1), script_to_p2sh(op0)]
        unsolvable_address_key = hex_str_to_bytes("02341AEC7587A51CDE5279E0630A531AEA2615A9F80B17E8D9376327BAEAA59E3D")
        unsolvablep2pkh = CScript([OP_DUP, OP_HASH160, hash160(unsolvable_address_key), OP_EQUALVERIFY, OP_CHECKSIG])
        unsolvablep2wshp2pkh = CScript([OP_0, sha256(unsolvablep2pkh)])
        p2shop0 = CScript([OP_HASH160, hash160(op0), OP_EQUAL])
        p2wshop1 = CScript([OP_0, sha256(op1)])
        unsolvable_after_importaddress.append(unsolvablep2pkh)
        unsolvable_after_importaddress.append(unsolvablep2wshp2pkh)
        unsolvable_after_importaddress.append(op1) # OP_1 will be imported as script
        unsolvable_after_importaddress.append(p2wshop1)
        unseen_anytime.append(op0) # OP_0 will be imported as P2SH address with no script provided
        unsolvable_after_importaddress.append(p2shop0)

        spendable_txid = []
        solvable_txid = []
        spendable_txid.append(self.mine_and_test_listunspent(spendable_anytime, 2))
        solvable_txid.append(self.mine_and_test_listunspent(solvable_anytime, 1))
        self.mine_and_test_listunspent(spendable_after_importaddress + solvable_after_importaddress + unseen_anytime + unsolvable_after_importaddress, 0)

        importlist = []
        for i in compressed_spendable_address + uncompressed_spendable_address + compressed_solvable_address + uncompressed_solvable_address:
            v = self.nodes[0].validateaddress(i)
            if (v['isscript']):
                bare = hex_str_to_bytes(v['hex'])
                importlist.append(bytes_to_hex_str(bare))
                importlist.append(bytes_to_hex_str(CScript([OP_0, sha256(bare)])))
            else:
                pubkey = hex_str_to_bytes(v['pubkey'])
                p2pk = CScript([pubkey, OP_CHECKSIG])
                p2pkh = CScript([OP_DUP, OP_HASH160, hash160(pubkey), OP_EQUALVERIFY, OP_CHECKSIG])
                importlist.append(bytes_to_hex_str(p2pk))
                importlist.append(bytes_to_hex_str(p2pkh))
                importlist.append(bytes_to_hex_str(CScript([OP_0, hash160(pubkey)])))
                importlist.append(bytes_to_hex_str(CScript([OP_0, sha256(p2pk)])))
                importlist.append(bytes_to_hex_str(CScript([OP_0, sha256(p2pkh)])))

        importlist.append(bytes_to_hex_str(unsolvablep2pkh))
        importlist.append(bytes_to_hex_str(unsolvablep2wshp2pkh))
        importlist.append(bytes_to_hex_str(op1))
        importlist.append(bytes_to_hex_str(p2wshop1))

        for i in importlist:
            try:
                self.nodes[0].importaddress(i,"",False,True)
            except JSONRPCException as exp:
                assert_equal(exp.error["message"], "The wallet already contains the private key for this address or script")

        self.nodes[0].importaddress(script_to_p2sh(op0)) # import OP_0 as address only
        self.nodes[0].importaddress(multisig_without_privkey_address) # Test multisig_without_privkey

        spendable_txid.append(self.mine_and_test_listunspent(spendable_anytime + spendable_after_importaddress, 2))
        solvable_txid.append(self.mine_and_test_listunspent(solvable_anytime + solvable_after_importaddress, 1))
        self.mine_and_test_listunspent(unsolvable_after_importaddress, 1)
        self.mine_and_test_listunspent(unseen_anytime, 0)

        # addwitnessaddress should refuse to return a witness address if an uncompressed key is used or the address is
        # not in the wallet
        # note that no witness address should be returned by unsolvable addresses
        # the multisig_without_privkey_address will fail because its keys were not added with importpubkey
        for i in uncompressed_spendable_address + uncompressed_solvable_address + unknown_address + unsolvable_address + [multisig_without_privkey_address]:
            try:
                self.nodes[0].addwitnessaddress(i)
            except JSONRPCException as exp:
                assert_equal(exp.error["message"], "Public key or redeemscript not known to wallet, or the key is uncompressed")
            else:
                assert(False)

        for i in compressed_spendable_address + compressed_solvable_address:
            witaddress = self.nodes[0].addwitnessaddress(i)
            # addwitnessaddress should return the same address if it is a known P2SH-witness address
            assert_equal(witaddress, self.nodes[0].addwitnessaddress(witaddress))

        spendable_txid.append(self.mine_and_test_listunspent(spendable_anytime + spendable_after_importaddress, 2))
        solvable_txid.append(self.mine_and_test_listunspent(solvable_anytime + solvable_after_importaddress, 1))
        self.mine_and_test_listunspent(unsolvable_after_importaddress, 1)
        self.mine_and_test_listunspent(unseen_anytime, 0)

        # Repeat some tests. This time we don't add witness scripts with importaddress
        # Import a compressed key and an uncompressed key, generate some multisig addresses
        self.nodes[0].importprivkey("2qeWqR7wYKpDXZYFhhEZcbFBfYiJ2VaXeb3CaHwz77PWdDVrtVh4M")
        uncompressed_spendable_address = ["P4spbfVFFbVQU22zMnWDKPsTzLemSht46WSn"]
        self.nodes[0].importprivkey("97ibzCsyKePb9mFBxJbx9KeQUkRQGGMrquwSqxAvqzUXT4vP4saF3s")
        compressed_spendable_address = ["P4shb6vM4PfZBo7RKRgw7xvcYh2MeEWXHCWH"]

        self.nodes[0].importpubkey(pubkeys[5])
        compressed_solvable_address = [key_to_p2pkh(pubkeys[5])]
        self.nodes[0].importpubkey(pubkeys[6])
        uncompressed_solvable_address = [key_to_p2pkh(pubkeys[6])]

        spendable_after_addwitnessaddress = []      # These outputs should be seen after importaddress
        solvable_after_addwitnessaddress=[]         # These outputs should be seen after importaddress but not spendable
        unseen_anytime = []                         # These outputs should never be seen

        uncompressed_spendable_address.append(self.nodes[0].addmultisigaddress(2, [uncompressed_spendable_address[0], compressed_spendable_address[0]]))
        uncompressed_spendable_address.append(self.nodes[0].addmultisigaddress(2, [uncompressed_spendable_address[0], uncompressed_spendable_address[0]]))
        compressed_spendable_address.append(self.nodes[0].addmultisigaddress(2, [compressed_spendable_address[0], compressed_spendable_address[0]]))
        uncompressed_solvable_address.append(self.nodes[0].addmultisigaddress(2, [compressed_solvable_address[0], uncompressed_solvable_address[0]]))
        compressed_solvable_address.append(self.nodes[0].addmultisigaddress(2, [compressed_spendable_address[0], compressed_solvable_address[0]]))

        premature_witaddress = []

        for i in compressed_spendable_address:
            v = self.nodes[0].validateaddress(i)
            if (v['isscript']):
                [bare, p2sh, p2wsh, p2sh_p2wsh] = self.p2sh_address_to_script(v)
                # P2WSH and P2SH(P2WSH) multisig with compressed keys are spendable after addwitnessaddress
                spendable_after_addwitnessaddress.extend([p2wsh, p2sh_p2wsh])
                premature_witaddress.append(script_to_p2sh(p2wsh))
            else:
                [p2wpkh, p2sh_p2wpkh, p2pk, p2pkh, p2sh_p2pk, p2sh_p2pkh, p2wsh_p2pk, p2wsh_p2pkh, p2sh_p2wsh_p2pk, p2sh_p2wsh_p2pkh] = self.p2pkh_address_to_script(v)
                # P2WPKH, P2SH_P2WPKH are spendable after addwitnessaddress
                spendable_after_addwitnessaddress.extend([p2wpkh, p2sh_p2wpkh])
                premature_witaddress.append(script_to_p2sh(p2wpkh))

        for i in uncompressed_spendable_address + uncompressed_solvable_address:
            v = self.nodes[0].validateaddress(i)
            if (v['isscript']):
                [bare, p2sh, p2wsh, p2sh_p2wsh] = self.p2sh_address_to_script(v)
                # P2WSH and P2SH(P2WSH) multisig with uncompressed keys are never seen
                unseen_anytime.extend([p2wsh, p2sh_p2wsh])
            else:
                [p2wpkh, p2sh_p2wpkh, p2pk, p2pkh, p2sh_p2pk, p2sh_p2pkh, p2wsh_p2pk, p2wsh_p2pkh, p2sh_p2wsh_p2pk, p2sh_p2wsh_p2pkh] = self.p2pkh_address_to_script(v)
                # P2WPKH, P2SH_P2WPKH with uncompressed keys are never seen
                unseen_anytime.extend([p2wpkh, p2sh_p2wpkh])

        for i in compressed_solvable_address:
            v = self.nodes[0].validateaddress(i)
            if (v['isscript']):
                # P2WSH multisig without private key are seen after addwitnessaddress
                [bare, p2sh, p2wsh, p2sh_p2wsh] = self.p2sh_address_to_script(v)
                solvable_after_addwitnessaddress.extend([p2wsh, p2sh_p2wsh])
                premature_witaddress.append(script_to_p2sh(p2wsh))
            else:
                [p2wpkh, p2sh_p2wpkh, p2pk, p2pkh, p2sh_p2pk, p2sh_p2pkh, p2wsh_p2pk, p2wsh_p2pkh, p2sh_p2wsh_p2pk, p2sh_p2wsh_p2pkh] = self.p2pkh_address_to_script(v)
                # P2SH_P2PK, P2SH_P2PKH with compressed keys are seen after addwitnessaddress
                solvable_after_addwitnessaddress.extend([p2wpkh, p2sh_p2wpkh])
                premature_witaddress.append(script_to_p2sh(p2wpkh))

        self.mine_and_test_listunspent(spendable_after_addwitnessaddress + solvable_after_addwitnessaddress + unseen_anytime, 0)

        # addwitnessaddress should refuse to return a witness address if an uncompressed key is used
        # note that a multisig address returned by addmultisigaddress is not solvable until it is added with importaddress
        # premature_witaddress are not accepted until the script is added with addwitnessaddress first
        for i in uncompressed_spendable_address + uncompressed_solvable_address + premature_witaddress + [compressed_solvable_address[1]]:
            try:
                self.nodes[0].addwitnessaddress(i)
            except JSONRPCException as exp:
                assert_equal(exp.error["message"], "Public key or redeemscript not known to wallet, or the key is uncompressed")
            else:
                assert(False)

        # after importaddress it should pass addwitnessaddress
        v = self.nodes[0].validateaddress(compressed_solvable_address[1])
        self.nodes[0].importaddress(v['hex'],"",False,True)
        for i in compressed_spendable_address + compressed_solvable_address + premature_witaddress:
            witaddress = self.nodes[0].addwitnessaddress(i)
            assert_equal(witaddress, self.nodes[0].addwitnessaddress(witaddress))

        spendable_txid.append(self.mine_and_test_listunspent(spendable_after_addwitnessaddress, 2))
        solvable_txid.append(self.mine_and_test_listunspent(solvable_after_addwitnessaddress, 1))
        self.mine_and_test_listunspent(unseen_anytime, 0)

        # Check that spendable outputs are really spendable
        self.create_and_mine_tx_from_txids(spendable_txid)

        addresses = [
            "P4snHKyksXnxK1fwZgXmZjFqWrFQM3emdmaB",
            "P4sce5u5MUNvb8pfSYMCdvBKSSEb3HcdmKth",
            "P4saDbBzHSya3WDHE9Y5LuAXqd6A6WU7nRqr",
            "P4serm2Ujghxiv4SujLUhwWq1X1Qb5CUet58",
            "P4sd831Fridto9UPfHvSdg3t6NCVNHMdtcRZ",
            "P4soJxqqVJckwfUmfwhZR7pNjGLCFMB6f1fn",
            "P4sbmSFoKPv4dXMPKdzitWF54GbBntWgo58y"
        ]

        privkeys = [
            "97iW9ERfdVAZRbCMPneNfWX4pJ9Pu93qsef9ZyrDrgakoU4G3XW2ZB",
            "97ibzrMqyK2ZqRW6YudqxLDuxGtsp6XEx1WbWvYvtfPEFAV7mKcJam",
            "2qeXGKi3b1o594iNGn6kdU1ttFEMF2RaRW7hkxm66kRwhKqFsAh4F",
            "97iZMyZ8Akww5wtEYJRrtS5toKrQ47oYoeD9zwA6d2PH93FdqFP31Q",
            "97iVXTiaYvgnt7z3bWZkoQEad8JMjvyekzNtixHwpgGC88oC1n7x78",
            "97iWSxXceNFydyrG6VhsKN1QJge2iaUSVMUFMrJKysJiEBmCpnpMqh",
            "2qeXVU9TSmKkzSBaodDbMF6PM7AsDRjoc9GfCv5dSCg6rtUNXgqoS"
        ]

        # import all the private keys so solvable addresses become spendable
        for key in privkeys:
            self.nodes[0].importprivkey(key)

        # Check accordance between addresses, pubkeys and privkeys:
        assert_equal(len(addresses), len(pubkeys))
        assert_equal(len(addresses), len(privkeys))
        for i in range(len(addresses)):
            v = self.nodes[0].validateaddress(addresses[i])
            assert_equal(v['address'], addresses[i])
            assert_equal(v['pubkey'], pubkeys[i])
            assert_equal(v['isvalid'], True)
            assert_equal(v['ismine'], True)
            assert_equal(self.nodes[0].dumpprivkey(addresses[i]), privkeys[i])

        self.create_and_mine_tx_from_txids(solvable_txid)

    def mine_and_test_listunspent(self, script_list, ismine):
        utxo = find_unspent(self.nodes[0], 50)
        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(int('0x'+utxo['txid'],0), utxo['vout'])))
        for i in script_list:
            tx.vout.append(CTxOut(10000000, i))
        tx.rehash()
        signresultfull = self.nodes[0].signrawtransaction(bytes_to_hex_str(tx.serialize_without_witness()))
        assert_equal(signresultfull['complete'], True)
        signresult = signresultfull['hex']
        txid = self.nodes[0].sendrawtransaction(signresult, True)
        self.nodes[0].generate(1)
        sync_blocks(self.nodes)
        watchcount = 0
        spendcount = 0
        for i in self.nodes[0].listunspent():
            if (i['txid'] == txid):
                watchcount += 1
                if (i['spendable'] == True):
                    spendcount += 1
        if (ismine == 2):
            assert_equal(spendcount, len(script_list))
        elif (ismine == 1):
            assert_equal(watchcount, len(script_list))
            assert_equal(spendcount, 0)
        else:
            assert_equal(spendcount, 0)
            assert_equal(watchcount, 0)
        return txid

    def p2sh_address_to_script(self,v):
        bare = CScript(hex_str_to_bytes(v['hex']))
        p2sh = CScript(hex_str_to_bytes(v['scriptPubKey']))
        p2wsh = CScript([OP_0, sha256(bare)])
        p2sh_p2wsh = CScript([OP_HASH160, hash160(p2wsh), OP_EQUAL])
        return([bare, p2sh, p2wsh, p2sh_p2wsh])

    def p2pkh_address_to_script(self,v):
        pubkey = hex_str_to_bytes(v['pubkey'])
        p2wpkh = CScript([OP_0, hash160(pubkey)])
        p2sh_p2wpkh = CScript([OP_HASH160, hash160(p2wpkh), OP_EQUAL])
        p2pk = CScript([pubkey, OP_CHECKSIG])
        p2pkh = CScript(hex_str_to_bytes(v['scriptPubKey']))
        p2sh_p2pk = CScript([OP_HASH160, hash160(p2pk), OP_EQUAL])
        p2sh_p2pkh = CScript([OP_HASH160, hash160(p2pkh), OP_EQUAL])
        p2wsh_p2pk = CScript([OP_0, sha256(p2pk)])
        p2wsh_p2pkh = CScript([OP_0, sha256(p2pkh)])
        p2sh_p2wsh_p2pk = CScript([OP_HASH160, hash160(p2wsh_p2pk), OP_EQUAL])
        p2sh_p2wsh_p2pkh = CScript([OP_HASH160, hash160(p2wsh_p2pkh), OP_EQUAL])
        return [p2wpkh, p2sh_p2wpkh, p2pk, p2pkh, p2sh_p2pk, p2sh_p2pkh, p2wsh_p2pk, p2wsh_p2pkh, p2sh_p2wsh_p2pk, p2sh_p2wsh_p2pkh]

    def create_and_mine_tx_from_txids(self, txids, success = True):
        tx = CTransaction()
        for txid in txids:
            txtmp = CTransaction()
            txraw = self.nodes[0].getrawtransaction(txid)
            f = BytesIO(hex_str_to_bytes(txraw))
            txtmp.deserialize(f)
            for j in range(len(txtmp.vout)):
                tx.vin.append(CTxIn(COutPoint(int('0x'+txid,0), j)))
        tx.vout.append(CTxOut(0, CScript([OP_TRUE])))
        tx.rehash()
        signresultfull = self.nodes[0].signrawtransaction(bytes_to_hex_str(tx.serialize_without_witness()))
        signresult = signresultfull['hex']
        assert_equal(signresultfull['complete'], True)
        self.nodes[0].sendrawtransaction(signresult, True)
        self.nodes[0].generate(1)
        sync_blocks(self.nodes)


if __name__ == '__main__':
    SegWitTest().main()
