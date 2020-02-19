#!/usr/bin/env python3
# Copyright (c) 2014-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# Exercise the wallet keypool, and interaction with wallet encryption/locking

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *

class KeyPoolTest(BitcoinTestFramework):

    def run_test(self):
        nodes = self.nodes
        addr_before_encrypting = nodes[0].getnewaddress()
        addr_before_encrypting_data = nodes[0].validateaddress(addr_before_encrypting)
        wallet_info_old = nodes[0].getwalletinfo()
        assert(addr_before_encrypting_data['hdmasterkeyid'] == wallet_info_old['hdmasterkeyid'])
        
        # Encrypt wallet and wait to terminate
        nodes[0].encryptwallet('test')
        bitcoind_processes[0].wait()
        # Restart node 0
        nodes[0] = start_node(0, self.options.tmpdir)
        # Keep creating keys
        addr = nodes[0].getnewaddress()
        addr_data = nodes[0].validateaddress(addr)
        wallet_info = nodes[0].getwalletinfo()
        assert(addr_before_encrypting_data['hdmasterkeyid'] != wallet_info['hdmasterkeyid'])
        assert(addr_data['hdmasterkeyid'] == wallet_info['hdmasterkeyid'])
        
        try:
            addr = nodes[0].getnewaddress()
            raise AssertionError('Keypool should be exhausted after one address')
        except JSONRPCException as e:
            assert(e.error['code'] == -12)
            assert ('Keypool ran out' in e.error['message'])

        # put three new keys in the keypool
        nodes[0].walletpassphrase('test', 12000)
        nodes[0].keypoolrefill(3)
        nodes[0].walletlock()

        # drain the keys
        addr = set()
        addr.add(nodes[0].getrawchangeaddress())
        addr.add(nodes[0].getrawchangeaddress())
        addr.add(nodes[0].getrawchangeaddress())
        addr.add(nodes[0].getrawchangeaddress())
        # assert that four unique addresses were returned
        assert(len(addr) == 4)
        # the next one should fail
        try:
            addr = nodes[0].getrawchangeaddress()
            raise AssertionError('Keypool should be exhausted after three addresses')
        except JSONRPCException as e:
            assert(e.error['code'] == -12)
            assert ('Keypool ran out' in e.error['message'])

        # refill keypool with three new addresses
        nodes[0].walletpassphrase('test', 1)
        nodes[0].keypoolrefill(3)
        # test walletpassphrase timeout
        time.sleep(1.1)
        assert_equal(nodes[0].getwalletinfo()["unlocked_until"], 0)

        # generate() consumes a new key only once, then uses it for further calls
        # Case 1: try to take a new key via generate(), when keepool is exhausted:
        nodes[0].getnewaddress()
        nodes[0].getnewaddress()
        nodes[0].getnewaddress()
        nodes[0].getnewaddress()
        try:
            nodes[0].generate(1)
            raise AssertionError('Keypool should be exhausted here')
        except JSONRPCException as e:
            assert(e.error['code'] == -12)
            assert('Keypool ran out' in e.error['message'])

        nodes[0].walletpassphrase('test', 12000)
        nodes[0].keypoolrefill(2)
        nodes[0].walletlock()

        # Case 2: ensure that generate() doesn't consume keeys after the first call:
        for i in range(15):
            nodes[0].generate(1)

        # Case 3: ensure that generate() consumed only one kee:
        nodes[0].getnewaddress()
        nodes[0].getnewaddress()
        try:
            nodes[0].getnewaddress()
            raise AssertionError('Keypool should be exhausted here')
        except JSONRPCException as e:
            assert (e.error['code'] == -12)
            assert ('Keypool ran out' in e.error['message'])

        # Case 4: ensure that generate() works when keepool is exhausted:
        nodes[0].generate(1)

    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True
        self.num_nodes = 1

    def setup_network(self):
        self.nodes = self.setup_nodes()

if __name__ == '__main__':
    KeyPoolTest().main()
