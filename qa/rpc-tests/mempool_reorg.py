#!/usr/bin/env python3
# Copyright (c) 2014-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

#
# Test re-org scenarios with a mempool that contains transactions
# that spend (directly or indirectly) coinbase transactions.
#

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *

# Create one-input, one-output, no-fee transaction:
class MempoolCoinbaseTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.num_nodes = 2
        self.setup_clean_chain = True

    alert_filename = None  # Set by setup_network

    def setup_network(self):
        args = ["-checkmempool", "-debug=mempool"]
        self.nodes = []
        self.nodes.append(start_node(0, self.options.tmpdir, args))
        self.nodes.append(start_node(1, self.options.tmpdir, args))
        connect_nodes(self.nodes[1], 0)
        self.is_network_split = False
        self.sync_all()

    def run_test(self):
        self.nodes[0].generate(200)
        self.sync_all()

        # Mine three blocks. After this, nodes[0] blocks
        # 101, 102, and 103 are spendable.
        new_blocks = self.nodes[1].generate(3)
        self.sync_all()

        node0_address = self.nodes[0].getnewaddress()
        node1_address = self.nodes[1].getnewaddress()
        print('node0_address: {}, node1_address: {}'.format(node0_address, node1_address))

        # Three scenarios for re-orging coinbase spends in the memory pool:
        # 1. Direct coinbase spend  :  spend_101
        # 2. Indirect (coinbase spend in chain, child in mempool) : spend_102 and spend_102_1
        # 3. Indirect (coinbase and child both in chain) : spend_103 and spend_103_1
        # Use invalidateblock to make all of the above coinbase spends invalid (immature coinbase),
        # and make sure the mempool code behaves correctly.
        b = [ self.nodes[0].getblockhash(n) for n in range(101, 105) ]
        coinbase_txids = [ self.nodes[0].getblock(h)['tx'][0] for h in b ]
        print('block hashes for range(101,105): {}, coinbase_txids: {}'.format(b, coinbase_txids))
        spend_101_raw = create_tx(self.nodes[0], coinbase_txids[1], node1_address, Decimal('0.004'))
        spend_102_raw = create_tx(self.nodes[0], coinbase_txids[2], node0_address, Decimal('0.004'))
        spend_103_raw = create_tx(self.nodes[0], coinbase_txids[3], node0_address, Decimal('0.004'))
        print('spend_101_raw ({}): {}'.format(len(spend_101_raw) // 2, spend_101_raw))
        print('spend_102_raw ({}): {}'.format(len(spend_102_raw) // 2, spend_102_raw))
        print('spend_103_raw ({}): {}'.format(len(spend_103_raw) // 2, spend_103_raw))

        # Create a block-height-locked transaction which will be invalid after reorg
        timelock_tx = self.nodes[0].createrawtransaction([{"txid": coinbase_txids[0], "vout": 0}], {node0_address: Decimal('0.004')})
        # Set the time lock
        timelock_tx = timelock_tx.replace("ffffffff", "11111191", 1)
        timelock_tx = timelock_tx[:-8] + hex(self.nodes[0].getblockcount() + 2)[2:] + "000000"
        timelock_tx = self.nodes[0].signrawtransaction(timelock_tx)["hex"]
        print('timelock_tx ({}): {}'.format(len(timelock_tx) // 2, timelock_tx))
        assert_raises(JSONRPCException, self.nodes[0].sendrawtransaction, timelock_tx)

        # Broadcast and mine spend_102 and 103:
        spend_102_id = self.nodes[0].sendrawtransaction(spend_102_raw)
        print('spend_102_id: {}'.format(spend_102_id))
        spend_103_id = self.nodes[0].sendrawtransaction(spend_103_raw)
        print('spend_103_id: {}'.format(spend_103_id))
        self.nodes[0].generate(1)
        assert_raises(JSONRPCException, self.nodes[0].sendrawtransaction, timelock_tx)

        # Create 102_1 and 103_1:
        spend_102_1_raw = create_tx(self.nodes[0], spend_102_id, node1_address, Decimal('0.003'))
        spend_103_1_raw = create_tx(self.nodes[0], spend_103_id, node1_address, Decimal('0.003'))
        print('spend_102_1_raw ({}): {}'.format(len(spend_102_1_raw) // 2, spend_102_1_raw))
        print('spend_103_1_raw ({}): {}'.format(len(spend_103_1_raw) // 2, spend_103_1_raw))

        # Broadcast and mine 103_1:
        spend_103_1_id = self.nodes[0].sendrawtransaction(spend_103_1_raw)
        print('spend_103_1_id: {}'.format(spend_103_1_id))
        last_block = self.nodes[0].generate(1)
        print('last_block: {}'.format(last_block[0]))
        timelock_tx_id = self.nodes[0].sendrawtransaction(timelock_tx)
        print('timelock_tx_id: {}'.format(timelock_tx_id))

        # ... now put spend_101 and spend_102_1 in memory pools:
        spend_101_id = self.nodes[0].sendrawtransaction(spend_101_raw)
        print('spend_101_id: {}'.format(spend_101_id))
        spend_102_1_id = self.nodes[0].sendrawtransaction(spend_102_1_raw)
        print('spend_102_1_id: {}'.format(spend_102_1_id))

        self.sync_all()

        assert_equal(set(self.nodes[0].getrawmempool()), {spend_101_id, spend_102_1_id, timelock_tx_id})

        for node in self.nodes:
            node.invalidateblock(last_block[0])
        assert_equal(set(self.nodes[0].getrawmempool()), {spend_101_id, spend_102_1_id, spend_103_1_id})

        # Use invalidateblock to re-org back and make all those coinbase spends
        # immature/invalid:
        for node in self.nodes:
            node.invalidateblock(new_blocks[0])

        self.sync_all()

        # mempool should be empty.
        assert_equal(set(self.nodes[0].getrawmempool()), set())

if __name__ == '__main__':
    MempoolCoinbaseTest().main()
