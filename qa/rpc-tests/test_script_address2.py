#!/usr/bin/env python3
# Copyright (c) 2015-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

#
# Test new Platincoin multisig prefix functionality.
#

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
import decimal

class ScriptAddress2Test(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.num_nodes = 3
        self.setup_clean_chain = True

    def setup_network(self):
        self.nodes = []
        self.nodes.append(start_node(0, self.options.tmpdir, []))
        self.nodes.append(start_node(1, self.options.tmpdir, []))
        self.nodes.append(start_node(2, self.options.tmpdir, []))
        connect_nodes(self.nodes[1], 0)
        connect_nodes(self.nodes[2], 0)
        self.is_network_split = False
        self.sync_all()

    def run_test(self):
        cnt = self.nodes[0].getblockcount()

        # Mine some blocks
        self.nodes[1].generate(10)
        self.nodes[1].generate(100)
        self.sync_all()
        if (self.nodes[0].getblockcount() != cnt + 110):
            raise AssertionError("Failed to mine 110 blocks")

        addr = self.nodes[0].getnewaddress()
        addr2 = self.nodes[0].getnewaddress()
        multisig_addr = self.nodes[0].addmultisigaddress(2, [addr, addr2], "multisigaccount")
        assert_equal(multisig_addr[0], 'P')
        assert_equal(multisig_addr[1], '4')

        # Send to a new multisig address
        txid = self.nodes[1].sendtoaddress(multisig_addr, 1)
        blocks = self.nodes[1].generate(3)
        self.sync_all()
        tx = self.nodes[2].getrawtransaction(txid, 1)
        dest_addrs = [tx["vout"][0]['scriptPubKey']['addresses'][0],
                      tx["vout"][1]['scriptPubKey']['addresses'][0]]
        assert(multisig_addr in dest_addrs)

        # Spend from the new multisig address
        addr3 = self.nodes[1].getnewaddress()
        txid = self.nodes[0].sendfrom("multisigaccount", addr3, Decimal('0.8'))
        blocks = self.nodes[0].generate(2)
        self.sync_all()
        assert(self.nodes[0].getbalance("multisigaccount", 1) < Decimal('0.2'))
        assert(self.nodes[1].listtransactions()[-1]['address'] == addr3)

        # Send to an old multisig address. The api addmultisigaddress
        # can only generate a new address so we manually compute
        # multisig_addr_old beforehand using an old client.
        priv_keys = ["97iZ8kxRr1ZpoM3Weo2MwsdjhdH9Q6CUfDkRjkrvGMqn7c5wF4EVNd",
                     "97icNm5hLZ8k7J3QyUfyrafG1xYnt11gMeH7TUBBwMGcTSumHRDsLc"]

        addrs = ["P4sgnfnvk5PwxaagTNrmoy5wg8EzjeEvRiEX",
                 "P4sp8F4qX2HKcLvSAnDTzQaXF2ESqgMWQUgk"]

        self.nodes[0].importprivkey(priv_keys[0])
        self.nodes[0].importprivkey(priv_keys[1])

        multisig_addr_new = self.nodes[0].addmultisigaddress(2, addrs, "multisigaccount2")
        assert_equal(multisig_addr_new, "P4sufXuZ4etQqvQmirEAWtPuTncXg8x9iB9D")

        txid = self.nodes[1].sendtoaddress(multisig_addr_new, 1)
        blocks = self.nodes[1].generate(1)
        self.sync_all()
        tx = self.nodes[2].getrawtransaction(txid, 1)
        dest_addrs = [tx["vout"][0]['scriptPubKey']['addresses'][0],
                      tx["vout"][1]['scriptPubKey']['addresses'][0]]
        assert(multisig_addr_new in dest_addrs)

        # Spend from the new multisig address
        addr4 = self.nodes[1].getnewaddress()
        txid = self.nodes[0].sendfrom("multisigaccount2", addr4, Decimal('0.8'))
        blocks = self.nodes[0].generate(2)
        self.sync_all()
        assert(self.nodes[0].getbalance("multisigaccount2", 1) < Decimal('0.2'))
        assert(self.nodes[1].listtransactions()[-1]['address'] == addr4)


if __name__ == '__main__':
    ScriptAddress2Test().main()
