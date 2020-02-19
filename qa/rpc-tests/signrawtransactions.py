#!/usr/bin/env python3
# Copyright (c) 2015-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *


class SignRawTransactionsTest(BitcoinTestFramework):
    """Tests transaction signing via RPC command "signrawtransaction"."""

    def __init__(self):
        super().__init__()
        self.setup_clean_chain = True
        self.num_nodes = 1

    def setup_network(self, split=False):
        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir)
        self.is_network_split = False

    def successful_signing_test(self):
        """Creates and signs a valid raw transaction with one input.

        Expected results:

        1) The transaction has a complete set of signatures
        2) No script verification error occurred"""
        privKeys = ['97iVxAyQhuD4Sv3dX5ua9yuGWCDwcjMJu13aoYgHC2WYvCz6hPvF8J', '97iYzhEw55nnkfQB2UegQL8wpAotzTzHBrjiZUTkbDTAhh8b2qBmhG']

        inputs = [
            # Valid pay-to-pubkey scripts
            {'txid': 'f73ab7aa5c3ffae730f5b11f16550a7cebfe5bb69ff0e7a297f17f799173e574', 'vout': 0,
             'scriptPubKey': '76a91449997dcf043af12246f5cce3a870454c19ad003188ac'},
            {'txid': '55638c2c3fe245f8d3ffee872fdf3aab2f919e6f814e043d85b86f1630153195', 'vout': 0,
             'scriptPubKey': '76a914c1c8a7db54b74ac2e982ea2f5a15fe9adc05873a88ac'},
        ]

        outputs = {'P4sofJRU91HuwBj5pY1ZoUvwxkRHD5RTrgx6': 0.1}

        rawTx = self.nodes[0].createrawtransaction(inputs, outputs)
        rawTxSigned = self.nodes[0].signrawtransaction(rawTx, inputs, privKeys)

        # 1) The transaction has a complete set of signatures
        assert 'complete' in rawTxSigned
        assert_equal(rawTxSigned['complete'], True)

        # 2) No script verification error occurred
        assert 'errors' not in rawTxSigned

        # Check that signrawtransaction doesn't blow up on garbage merge attempts
        dummyTxInconsistent = self.nodes[0].createrawtransaction([inputs[0]], outputs)
        rawTxUnsigned = self.nodes[0].signrawtransaction(rawTx + dummyTxInconsistent, inputs)

        assert 'complete' in rawTxUnsigned
        assert_equal(rawTxUnsigned['complete'], False)

        # Check that signrawtransaction properly merges unsigned and signed txn, even with garbage in the middle
        rawTxSigned2 = self.nodes[0].signrawtransaction(rawTxUnsigned["hex"] + dummyTxInconsistent + rawTxSigned["hex"], inputs)

        assert 'complete' in rawTxSigned2
        assert_equal(rawTxSigned2['complete'], True)

        assert 'errors' not in rawTxSigned2


    def script_verification_error_test(self):
        """Creates and signs a raw transaction with valid (vin 0), invalid (vin 1) and one missing (vin 2) input script.

        Expected results:

        3) The transaction has no complete set of signatures
        4) Two script verification errors occurred
        5) Script verification errors have certain properties ("txid", "vout", "scriptSig", "sequence", "error")
        6) The verification errors refer to the invalid (vin 1) and missing input (vin 2)"""
        privKeys = ['97iVxAyQhuD4Sv3dX5ua9yuGWCDwcjMJu13aoYgHC2WYvCz6hPvF8J']

        inputs = [
            # Valid pay-to-pubkey script
            {'txid': 'f73ab7aa5c3ffae730f5b11f16550a7cebfe5bb69ff0e7a297f17f799173e574', 'vout': 0},
            # Invalid script
            {'txid': 'f22bf6c5a22b7eac44ab29be0cb24c44f308087924063ec7292ac5ca46078020', 'vout': 7},
            # Missing scriptPubKey
            {'txid': 'f73ab7aa5c3ffae730f5b11f16550a7cebfe5bb69ff0e7a297f17f799173e574', 'vout': 1},
        ]

        scripts = [
            # Valid pay-to-pubkey script
            {'txid': 'f73ab7aa5c3ffae730f5b11f16550a7cebfe5bb69ff0e7a297f17f799173e574', 'vout': 0,
             'scriptPubKey': '76a91449997dcf043af12246f5cce3a870454c19ad003188ac'},
            # Invalid script
            {'txid': 'f22bf6c5a22b7eac44ab29be0cb24c44f308087924063ec7292ac5ca46078020', 'vout': 7,
             'scriptPubKey': 'badbadbadbad'}
        ]

        outputs = {'P4sofJRU91HuwBj5pY1ZoUvwxkRHD5RTrgx6': 0.1}

        rawTx = self.nodes[0].createrawtransaction(inputs, outputs)

        # Make sure decoderawtransaction is at least marginally sane
        decodedRawTx = self.nodes[0].decoderawtransaction(rawTx)
        for i, inp in enumerate(inputs):
            assert_equal(decodedRawTx["vin"][i]["txid"], inp["txid"])
            assert_equal(decodedRawTx["vin"][i]["vout"], inp["vout"])

        # Make sure decoderawtransaction throws if there is extra data
        assert_raises(JSONRPCException, self.nodes[0].decoderawtransaction, rawTx + "00")

        rawTxSigned = self.nodes[0].signrawtransaction(rawTx, scripts, privKeys)

        # 3) The transaction has no complete set of signatures
        assert 'complete' in rawTxSigned
        assert_equal(rawTxSigned['complete'], False)

        # 4) Two script verification errors occurred
        assert 'errors' in rawTxSigned
        assert_equal(len(rawTxSigned['errors']), 2)

        # 5) Script verification errors have certain properties
        assert 'txid' in rawTxSigned['errors'][0]
        assert 'vout' in rawTxSigned['errors'][0]
        assert 'scriptSig' in rawTxSigned['errors'][0]
        assert 'sequence' in rawTxSigned['errors'][0]
        assert 'error' in rawTxSigned['errors'][0]

        # 6) The verification errors refer to the invalid (vin 1) and missing input (vin 2)
        assert_equal(rawTxSigned['errors'][0]['txid'], inputs[1]['txid'])
        assert_equal(rawTxSigned['errors'][0]['vout'], inputs[1]['vout'])
        assert_equal(rawTxSigned['errors'][1]['txid'], inputs[2]['txid'])
        assert_equal(rawTxSigned['errors'][1]['vout'], inputs[2]['vout'])

    def run_test(self):
        self.successful_signing_test()
        self.script_verification_error_test()


if __name__ == '__main__':
    SignRawTransactionsTest().main()
