#!/usr/bin/env python3
# Copyright (c) 2019 The Platincoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#

from test_framework.mininode import *
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *
from test_framework.script import *
from test_framework.key import CECKey, CPubKey, sign_compact, recover_public_key
from test_framework.blocktools import create_coinbase, create_block
from minting_testcases import get_minting_testcases, BAD_REWARD_LIMIT_EXCEEDED

'''
MintingTest
'''

HAS_DEVICE_KEY      = 0x00000001
HAS_BEN_KEY         = 0x00000002
HAS_EXPIRATION_DATE = 0x00000004
HAS_MINTING_LIMIT   = 0x00000008
HAS_OTHER_DATA      = 0x00000800
FAST_MINTING        = 0x00010000
TOTAL_PUBKEYS_COUNT_MASK     = 0x0000f000
REQUIRED_PUBKEYS_COUNT_MASK  = 0xf0000000
GENEZIS_PRIV_KEY0_HEX = 'b342f7905eafa2fc41286d56f0b72ca7e165bca230f202eb5fd20bb32cfa72ca'
GENEZIS_PRIV_KEY1_HEX = 'bfad79ac763e6fe95221fef9438c2d307b7c01f99ec9db8628971c6db44b94cf'
GUESS_SIGSIZES_MAX_ATTEMPTS = 5000
print_buffer = ''

def split_names(names_str):
    names_list = names_str.split('+')
    if '' in names_list:
        names_list.remove('')
    return names_list

def print_to_buffer(s):
    global print_buffer
    print_buffer += s
    print_buffer += '\n'

# TestNode: bare-bones "peer".
class TestNode(SingleNodeConnCB):
    def __init__(self):
        SingleNodeConnCB.__init__(self)
        self.reject_message = None

    def add_connection(self, conn):
        self.connection = conn
        self.peer_disconnected = False

    def on_close(self, conn):
        self.peer_disconnected = True

    def wait_for_disconnect(self):
        def disconnected():
            return self.peer_disconnected
        return wait_until(disconnected, timeout=10)

    def on_reject(self, conn, message):
        self.reject_message = message

class MintingTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.genezis_key0 = CECKey()
        self.genezis_key0.set_secretbytes(hex_str_to_bytes(GENEZIS_PRIV_KEY0_HEX))
        if not self.genezis_key0.is_compressed():
            self.genezis_key0.set_compressed(True)
        self.virtual_cur_time_offset = 0
        self.txmap = {}
        self.seeds_for_keys = set()
        self.user_keys = []
        self.user_keys_m = None
        self.ben_key = None
        self.keys_count_required = None
        self.keys_count_used = None

    def add_options(self, parser):
        parser.add_option("--runtestcase", dest="runtestcase", action="store", help="runtestcase")
        parser.add_option("--mintalltestcases", dest="mintalltestcases", action="store", help="mint all testcases: run all test scenarios")

    def setup_network(self):
        self.nodes = []
        self.nodes.append(start_node(0, self.options.tmpdir, ['-debug', '-whitelist=127.0.0.1']))
        self.nodes.append(start_node(1, self.options.tmpdir, ['-debug']))
        connect_nodes_bi(self.nodes, 0, 1)
        node0 = self.nodes[0]

        # Setup the p2p connections and start up the network thread.
        self.test_node = TestNode()
        connection = NodeConn('127.0.0.1', p2p_port(0), node0, self.test_node)
        self.test_node.add_connection(connection)
        NetworkThread().start()
        self.test_node.wait_for_verack()
        self.test_node.sync_with_ping()

    def check_parameters(self, params):
        assert (type(params['greenflag']) == type(True))
        assert (type(params['ben_enabled']) == type(True))
        assert (type(params['accepted']) == type(True))
        assert (params['fee_user_percent'] == 'auto' or (params['fee_user_percent'] >= 0 and params['fee_user_percent'] <= 100))
        assert ('ben' not in params['reward_to'] or params['ben_enabled'] == True)  # if reward goes to ben, ben_enabled must be True
        assert (params['refill_moneybox'] == 'script' or params['refill_moneybox'] == 'node' or params['refill_moneybox'] == 'random')
        assert (params['keys_count_total'] >= 1 and params['keys_count_total'] <= 15)

        if 'revoke_root_cert' in params:
            assert (params['revoke_root_cert'] == True or params['revoke_root_cert'] == False)
        if 'revoke_user_cert' in params:
            assert (params['revoke_user_cert'] == True or params['revoke_user_cert'] == False)
        if 'refill_moneybox_accepted' in params:
            assert (params['refill_moneybox_accepted'] == True or params['refill_moneybox_accepted'] == False)
        if 'green_flag_in_user_cert' in params:
            assert (params['green_flag_in_user_cert'] == True or params['green_flag_in_user_cert'] == False)
        if 'invalid_root_cert_ref' in params:
            assert (params['invalid_root_cert_ref'] in [1,2,3,4,5,6])
        if 'invalid_user_cert_ref' in params:
            assert (params['invalid_user_cert_ref'] in [1,2,3,4,5])
        if 'invalid_refill_moneybox' in params:
            assert (params['invalid_refill_moneybox'] in [1,2,3,4,5])
        if 'step2_enabled' in params and params['step2_enabled'] == True:
            assert_equal(params['accepted'], True)  # if step2 presents, step1 must be successful
            assert_in('step2_wait_interval', params)
            assert_in('step2_rewardamount', params)
            assert_in('step2_reward_to', params)
            assert_in('step2_accepted', params)
            assert ('ben' not in params['step2_reward_to'] or params['ben_enabled'] == True)  # if reward goes to ben, ben_enabled must be True
            assert (type(params['step2_accepted']) == type(True))
        if 'step3_enabled' in params and params['step3_enabled'] == True:
            assert_equal(params['accepted'], True)  # if step3 presents, step1 must be successful
            assert_equal(params['step2_enabled'], True)  # if step3 presents, step2 must present too
            assert_equal(params['step2_accepted'], True)  # if step3 presents, step2 must be successful
            assert_in('step3_wait_interval', params)
            assert_in('step3_rewardamount', params)
            assert_in('step3_reward_to', params)
            assert_in('step3_accepted', params)
            assert ('ben' not in params['step3_reward_to'] or params['ben_enabled'] == True)  # if reward goes to ben, ben_enabled must be True
            assert (type(params['step3_accepted']) == type(True))
        if 'keys_count_required' not in params or params['keys_count_required'] is None:
            params['keys_count_required'] = 0
        if params['keys_count_required'] == 'random':
            params['keys_count_required'] = random.randint(1, params['keys_count_total'])
        if params['keys_count_used'] == 'auto':
            required = params['keys_count_required'] if params['keys_count_required'] > 0 else params['keys_count_total']
            params['keys_count_used'] = required


    def pay_to_address(self, address, amount, generate_block = True):
        amount = ToCoins(amount)
        node0 = self.nodes[0]
        txid = node0.sendtoaddress(address, amount)
        if generate_block:
            blocks = node0.generate(1)
            self.test_node.sync_with_ping()
            block = node0.getblock(blocks[0])
            blocktime = block['time']
            assert_in(txid, block['tx']) # Ensure the transaction is accepted by the node and is included into a block
            print('pay_to_address {} amount {}: height: {}, time: {}'.format(address, amount, block['height'], blocktime))
        else:
            # Ensure our transaction is accepted by the node and is included into mempool:
            self.test_node.sync_with_ping()
            mempool = node0.getrawmempool()
            assert_in(txid, mempool)
            blocktime = None
        tx = node0.getrawtransaction(txid, True)
        outputindex = -1
        for i, vout in enumerate(tx['vout']):
            if vout['value'] == amount:
                outputindex = vout['n']
                assert_equal(i, vout['n'])
                break
        assert (outputindex != -1)
        self.txmap[txid] = tx
        return (COutPoint(int(txid, 16), outputindex), blocktime)

    def get_multisig_script(self, keys, keys_count_unlock):
        multisigscript = CScript([keys_count_unlock])
        for key in keys:
            multisigscript += key.get_pubkey()
        multisigscript += len(keys)
        multisigscript += CScriptOp(OP_CHECKMULTISIG)
        return multisigscript

    def pay_to_multisig_address(self, keys, amount, keys_count_unlock, generate_block = True):
        multisigscript = self.get_multisig_script(keys, keys_count_unlock)
        address = ScriptAddress(multisigscript)
        pubkeys_hex = [bytes_to_hex_str(key.get_pubkey()) for key in keys]
        print('pay_to_multisig_address, keys count total: {}, keys count unlock: {}, pubkeys: {}, multisigscript ({}): {}, address: {}, amount: {}'.format(
            len(keys), keys_count_unlock, pubkeys_hex, len(multisigscript), bytes_to_hex_str(multisigscript), address, amount))
        return self.pay_to_address(address, amount, generate_block)

    def get_unique_rand_for_key(self):
        while True:
            n = random.randint(0, 0xffffffff)
            if n in self.seeds_for_keys:
                continue
            self.seeds_for_keys.add(n)
            return n

    def create_key(self, key_name, cert_name = None, print_func = print):
        predefined_keys = \
        {
            # For debug, to use given keys to reproduce exactly like in log:
            # ('user_key_0', 'root_cert'): 1586207744,
            # ('user_key_0', 'ca3_cert'): 2768265604,
            # ('user_key_1', 'ca3_cert'): 2366347457,
        }
        if (key_name, cert_name) in predefined_keys:
            n = predefined_keys[(key_name, cert_name)]
            self.seeds_for_keys.add(n)
        else:
            n = self.get_unique_rand_for_key()
        key = CECKey()
        key.set_secretbytes(struct.pack(b"<I", n) * 8)
        if not key.is_compressed():
            key.set_compressed(True)
        pubkey = key.get_pubkey()
        print_func('Details for {} in {}: n: {}, pubkey ({}): {}, pubkeyhash: {}, address: {}, priv_key: {}'.
                   format(key_name, cert_name, n, len(pubkey), bytes_to_hex_str(pubkey), bytes_to_hex_str(reverse(hash160(pubkey))),
                          AddressFromPubkey(pubkey), bytes_to_hex_str(key.get_secret())))
        return key

    def create_other_keys(self, count, name, cert_name = None):
        other_keys = []
        for i in range(count):
            other_keys.append(self.create_key(name + '_' + str(i), cert_name))
        return other_keys

    def create_cert(self, utxo_coins, amount, parent_key, keys_count_total, keys_count_required, green_flag, has_device, has_ben, cert_name,
                    user_keys_to_use = None, alt_dest_pubkeyhash = None, exp_date_offset = None, mint_limit = None):
        bestblockhash = self.nodes[0].getbestblockhash()
        block_time = self.nodes[0].getblock(bestblockhash)['time'] + 1

        assert_greater_than(keys_count_total, 0)
        node0 = self.nodes[0]
        parent_pubkey_bin = parent_key.get_pubkey()
        pubkeyhash = hash160(parent_pubkey_bin)

        user_keys = []
        dev_key = CECKey()
        ben_key = CECKey()
        if user_keys_to_use is None:
            for i in range(keys_count_total):
                user_key = self.create_key('user_key_{}'.format(i), cert_name)
                user_keys.append(user_key)
        else:
            assert_equal(len(user_keys_to_use), keys_count_total)
            user_keys = user_keys_to_use
        flags = 0
        if green_flag:
            flags |= FAST_MINTING
        if has_device:
            flags |= HAS_DEVICE_KEY
        if has_ben:
            flags |= HAS_BEN_KEY
        if exp_date_offset is not None:
            flags |= HAS_EXPIRATION_DATE
        if mint_limit is not None:
            flags |= HAS_MINTING_LIMIT
        flags |= ((keys_count_total << 12) & TOTAL_PUBKEYS_COUNT_MASK)
        if keys_count_required is not None:
            assert_greater_than(keys_count_required, 0)
            flags |= ((keys_count_required << 28) & REQUIRED_PUBKEYS_COUNT_MASK)

        block1 = bytearray(struct.pack(b"<I", flags))
        for user_key in user_keys:
            user_pubkeyhash = hash160(user_key.get_pubkey())
            block1.extend(user_pubkeyhash)
        if has_device:
            dev_key = self.create_key('dev_key', cert_name)
            dev_pubkeyhash = hash160(dev_key.get_pubkey())
            block1.extend(dev_pubkeyhash)
        if has_ben:
            ben_key = self.create_key('ben_key', cert_name)
            ben_pubkeyhash = hash160(ben_key.get_pubkey())
            block1.extend(ben_pubkeyhash)
        if exp_date_offset is not None:
            block1.extend(struct.pack(b"<I", block_time + exp_date_offset))
        if mint_limit is not None:
            block1.extend(struct.pack(b"<q", mint_limit))
        block1_hash = hash256(block1)
        # block2 = parent_key.sign(block1_hash)
        block2 = sign_compact(block1_hash, parent_key.get_secret())
        dest_pubkeyhash = alt_dest_pubkeyhash if alt_dest_pubkeyhash is not None else pubkeyhash
        scriptOutPKH = CScript([block1, block2, OP_2DROP, OP_DUP, OP_HASH160, dest_pubkeyhash, OP_EQUALVERIFY, OP_CHECKSIG])
        tx2 = CTransaction()
        tx2.vin.append(CTxIn(utxo_coins, b"", 0xffffffff))
        tx2.vout.append(CTxOut(ToSatoshi(amount), scriptOutPKH))

        scriptPubKey = GetP2PKHScript(pubkeyhash)
        (sig_hash, err) = SignatureHash(scriptPubKey, tx2, 0, SIGHASH_ALL)
        assert (err is None)
        signature = parent_key.sign(sig_hash) + bytes(bytearray([SIGHASH_ALL]))
        tx2.vin[0].scriptSig = CScript([signature, parent_pubkey_bin])
        tx2.rehash()

        print('cert {}: tx2.hash: {}, scriptPubKey ({}): {}, block1_hash: {}, parent_pubkey: {}, parent_pubkeyhash: {}, parent_privkey: {}, signature ({}): {}, amount: {}, block_time: {}, exp_date_offset: {}, mint_limit: {}'.
              format(cert_name, tx2.hash, len(scriptOutPKH), bytes_to_hex_str(scriptOutPKH),
                     bytes_to_hex_str(reverse(block1_hash)), bytes_to_hex_str(parent_key.get_pubkey()),
                     bytes_to_hex_str(reverse(hash160(parent_key.get_pubkey()))), bytes_to_hex_str(parent_key.get_secret()),
                     len(signature), bytes_to_hex_str(signature), amount, block_time, exp_date_offset, mint_limit))
        tx2_full = tx2.serialize()
        print('tx2 full ({}): {}'.format(len(tx2_full), bytes_to_hex_str(tx2_full)))

        height = self.nodes[0].getblockcount() + 1
        block = create_block(int(bestblockhash, 16), create_coinbase(height), block_time)
        block.vtx.extend([tx2])
        block.hashMerkleRoot = block.calc_merkle_root()
        block.solve()

        block_message = msg_block(block)
        self.test_node.send_message(block_message)
        self.test_node.sync_with_ping()

        new_best_hash = node0.getbestblockhash()
        last_block = node0.getblock(new_best_hash)
        assert_equal(self.nodes[0].getblockcount(), height)
        assert (bestblockhash != new_best_hash)

        # Ensure our transaction is accepted by the node and is included into a block:
        assert_in(tx2.hash, last_block['tx'])
        self.txmap[tx2.hash] = tx2
        return (user_keys, dev_key, ben_key, COutPoint(tx2.sha256, 0), last_block['time'])

    def emulate_fast_wait(self, time_seconds, timepoint_from = None, description = None):
        generate_period = 90
        while time_seconds // generate_period > 100:
            generate_period *= 2
        return self.emulate_wait(time_seconds, timepoint_from, description, generate_period)

    def emulate_wait(self, time_seconds, timepoint_from = None, description = None, generate_period = 90):
        time_seconds_orig = time_seconds
        start_wait_time_real = int(time.time())
        start_wait_time_virt = start_wait_time_real + self.virtual_cur_time_offset
        if timepoint_from is not None:
            time_seconds += (timepoint_from - start_wait_time_virt)
        blocks = time_seconds // generate_period
        print('will wait {} seconds (before correction {} seconds), generate_period: {}, blocks: {}, start_wait_time_virt: {}, virtual_cur_time_offset: {}, timepoint_from: {}, description: {}'.
              format(time_seconds, time_seconds_orig, generate_period, blocks, start_wait_time_real + self.virtual_cur_time_offset, self.virtual_cur_time_offset, timepoint_from, description))
        if time_seconds <= 0:
            # after correction wait time may become negative - ignore it
            assert_greater_than_or_equal(time_seconds_orig, 0)
            return
        self.nodes[0].setmocktime(start_wait_time_virt)
        self.nodes[1].setmocktime(start_wait_time_virt)
        if time_seconds > 0:
            self.nodes[0].generate(1)
        for i in range(blocks):
            step = generate_period if i > 0 else generate_period + (time_seconds % generate_period)
            self.virtual_cur_time_offset += step
            self.nodes[0].setmocktime(start_wait_time_real + self.virtual_cur_time_offset)
            self.nodes[1].setmocktime(start_wait_time_real + self.virtual_cur_time_offset)
            blockhashes = self.nodes[0].generate(1)
            print('wait, block {} time: {}'.format(i, self.nodes[0].getblock(blockhashes[0])['time']))
        sync_chain(self.nodes)
        self.test_node.sync_with_ping()

    def get_utxo(self, address, from_conf = 6, to_conf = 9999999):
        # find utxos with the help of the second node:
        sync_chain(self.nodes)
        node1 = self.nodes[1]
        print('will import address {}...'.format(address))
        node1.importaddress(address)
        return node1.listunspent(from_conf, to_conf, [address])


    def get_extra_moneybox_inputs_count(self, params):
        if 'extra_moneybox_inputs_count' in params:
            return params['extra_moneybox_inputs_count']
        return 0


    def get_moneybox_outputs_names(self, params):
        if 'moneybox_change_dest' in params:
            return split_names(params['moneybox_change_dest'])
        return ['moneybox']

    def get_dest_scriptpubkey(self, dest_output, print_func = print):
        if dest_output == 'moneybox':
            return GetP2SHMoneyboxScript()
        elif dest_output == 'user':
            multisig_script = self.get_multisig_script(self.user_keys, self.keys_count_used)
            return GetP2SHScript(hash160(multisig_script))
        elif dest_output == 'user_shuffled':
            assert_greater_than(len(self.user_keys), 1)
            keys_shuffled = [key for key in self.user_keys]
            while keys_shuffled == self.user_keys:
                random.shuffle(keys_shuffled)
            multisig_script = self.get_multisig_script(keys_shuffled, self.keys_count_used)
            return GetP2SHScript(hash160(multisig_script))
        elif dest_output == 'user_pure_multisig':
            return self.get_multisig_script(self.user_keys, self.keys_count_used)
        elif dest_output == 'ben':
            return GetP2PKHScript(hash160(self.ben_key.get_pubkey()))
        elif dest_output == 'other_p2pkh' or dest_output == 'other':
            other_key = self.create_key('other_p2pkh', print_func = print_func)
            return GetP2PKHScript(hash160(other_key.get_pubkey()))
        elif dest_output == 'other_p2sh':
            other_key = self.create_key('other_p2sh', print_func = print_func)
            return GetP2SHScript(hash160(other_key.get_pubkey()))
        elif dest_output == 'op_true':
            return CScript([OP_TRUE])
        elif dest_output == 'op_false':
            return CScript([OP_FALSE])
        else:
            raise AssertionError('invalid dest_output: {}'.format(dest_output))

    def appent_moneybox_outputs_to_tx(self, tx3, amount, params, print_func = print):
        moneybox_change_dest = self.get_moneybox_outputs_names(params)
        moneybox_outputs_count = len(moneybox_change_dest)
        amount_to_each = ToSatoshi(amount) // moneybox_outputs_count if moneybox_outputs_count > 0 else 0
        amount_sum = 0

        for i, dest_output in enumerate(moneybox_change_dest):
            amount_chunk = amount_to_each if i + 1 < moneybox_outputs_count else (ToSatoshi(amount) - amount_sum)
            amount_sum += amount_chunk
            tx3.vout.append(CTxOut(ToSatoshi(amount_chunk), self.get_dest_scriptpubkey(dest_output, print_func)))

            if dest_output == 'moneybox':
                print_func('tx3 vout[{}] moneybox: {}'.format(len(tx3.vout) - 1, ToCoins(amount_chunk)))
            else:
                print_func('tx3 vout[{}] pseudo-moneybox: {}, dest_output: {}'.format(len(tx3.vout) - 1, ToCoins(amount_chunk), dest_output))


    def get_user_outputs_names(self, params):
        if 'user_outputs_dest' in params:
            return split_names(params['user_outputs_dest'])
        return ['user']


    def appent_user_outputs_to_tx(self, tx3, amount, params, print_func = print):
        user_outputs_dest = self.get_user_outputs_names(params)
        user_outputs_cnt = len(user_outputs_dest)
        amount_to_each = ToSatoshi(amount) // user_outputs_cnt if user_outputs_cnt > 0 else 0
        amount_sum = 0
        vout_indexes = []

        for i, dest_output in enumerate(user_outputs_dest):
            amount_chunk = amount_to_each if i+1 < user_outputs_cnt else (ToSatoshi(amount) - amount_sum)
            amount_sum += amount_chunk
            tx3.vout.append(CTxOut(amount_chunk, self.get_dest_scriptpubkey(dest_output, print_func)))
            vout_indexes.append(len(tx3.vout) - 1)

            if dest_output == 'user':
                print_func('tx3 vout[{}] user_output: {}'.format(len(tx3.vout) - 1, ToCoins(amount_chunk)))
            else:
                print_func('tx3 vout[{}] pseudo_user_output: {}, dest_output: {}'.format(len(tx3.vout) - 1, ToCoins(amount_chunk), dest_output))

        return vout_indexes


    def get_all_reward_outputs_names(self, params):
        if 'reward_to' in params:
            return split_names(params['reward_to'])
        return ['user']


    ''' Return real outputs names, excluding 'user', because reward to user doesn't create separate outputs '''
    def get_real_reward_outputs_names(self, params):
        names = self.get_all_reward_outputs_names(params)
        return [x for x in names if x != 'user']


    def appent_reward_outputs_to_tx(self, tx3, amount, params, user_output_index, print_func = print):
        reward_outputs_dest = self.get_all_reward_outputs_names(params)
        reward_outputs_cnt = len(reward_outputs_dest)
        amount_to_each = ToSatoshi(amount) // reward_outputs_cnt if reward_outputs_cnt > 0 else 0
        amount_sum = 0
        reward_add_to_user_output = 0

        for i, dest_output in enumerate(reward_outputs_dest):
            amount_chunk = amount_to_each if i+1 < reward_outputs_cnt else (ToSatoshi(amount) - amount_sum)
            amount_sum += amount_chunk

            if dest_output == 'user':
                # add amount to existing user output, don't append output to transaction:
                reward_add_to_user_output += amount_chunk
                if user_output_index != -1:
                    tx3.vout[user_output_index].nValue += ToSatoshi(amount_chunk)
                    print_func('adding reward amount {} to existing user_output {}, now {}'.format(
                        ToCoins(amount_chunk), user_output_index, ToCoins(tx3.vout[user_output_index].nValue)))
            else:
                tx3.vout.append(CTxOut(ToSatoshi(amount_chunk), self.get_dest_scriptpubkey(dest_output, print_func)))
                print_func('tx3 vout[{}] reward_output: {}, reward_to: {}'.format(len(tx3.vout) - 1, ToCoins(amount_chunk), dest_output))

    def get_bytes_in_tx_inputs(self, tx, start_index, count):
        bytes_cnt = 0
        for i in range(start_index, start_index + count):
            bytes_cnt += len(tx.vin[i].serialize())
        return bytes_cnt

    def mint(self, user_inputs, utxo_cert_root, utxo_cert_ca3, rewardamount, reward_to, accepted, params):
        skip_checks = False
        p2sh_like_dests = set(['user', 'user_shuffled', 'moneybox', 'other_p2sh'])
        p2pkh_like_dests = set(['ben', 'other', 'other_p2pkh'])
        moneybox_outputs_names = self.get_moneybox_outputs_names(params)
        user_outputs_names = self.get_user_outputs_names(params)
        rewadr_real_output_names = self.get_real_reward_outputs_names(params)
        if len(moneybox_outputs_names) == 0 or set.union(set(moneybox_outputs_names), p2sh_like_dests) != p2sh_like_dests:
            # if no moneybox outputs (first condition) or at least one output is not p2sh-like (second condition),
            # skip checks, this is non-standard transaction:
            skip_checks = True
        if len(user_outputs_names) == 0 or set.union(set(user_outputs_names), p2sh_like_dests) != p2sh_like_dests:
            # if no user outputs (first condition) or at least one output is not p2sh-like (second condition),
            # skip checks, this is non-standard transaction:
            skip_checks = True
        if set.union(set(rewadr_real_output_names), p2pkh_like_dests) != p2pkh_like_dests:
            # if at least one reward output is not p2pkh-like, skip checks, because we consider all outputs are p2pkh-like:
            skip_checks = True
        if skip_checks:
            print('skip_checks == True')
        if self.user_keys_m is None:
            # In regular workflow user_keys_m and user_keys are the same, but in some special case they may be different.
            self.user_keys_m = self.user_keys

        fee_total_given = params['fee_total']
        fee_user_percent_orig = 0 \
            if params['fee_user_percent'] == 'auto' and (reward_to == 'user' or reward_to == 'ben') \
            else params['fee_user_percent']
        node0 = self.nodes[0]
        multisig_script = self.get_multisig_script(self.user_keys, self.keys_count_used)
        moneybox_inputs = self.get_utxo(MoneyboxP2SHAddress())
        assert_greater_than(len(user_inputs), 0)
        assert_greater_than(len(moneybox_inputs), 0)
        attemps = 0
        total_delta_user = 0        # accumulated difference between real and guessed sizes of tx user bytes (for statistics analysis)
        total_delta_moneybox = 0    # accumulated difference between real and guessed sizes of tx moneybox bytes (for statistics analysis)

        while True:
            # will use print_to_buffer() instead of print() function inside this loop,
            # because we need to print only successful (last) attempt of composing transaction:
            global print_buffer
            print_buffer = ''
            tx3 = CTransaction()
            user_amount = Decimal('0')
            reward_to_ben = ToCoins(rewardamount)
            reward_change = Decimal('0')
            reward_taken = Decimal('0')
            extra_moneybox_inputs_count = self.get_extra_moneybox_inputs_count(params)
            moneybox_inputs_enough = False
            for user_input in user_inputs:
                tx3.vin.append(CTxIn(user_input, multisig_script, 0xffffffff))
                user_input_hash_hex = hashToHex(user_input.hash)
                assert_in(user_input_hash_hex, self.txmap)
                tx_prev = self.txmap[user_input_hash_hex]
                print_to_buffer('tx_prev: {}'.format(tx_prev))
                assert_equal(tx_prev['vout'][user_input.n]['n'], user_input.n)
                amount = tx_prev['vout'][user_input.n]['value']
                user_amount += amount
                print_to_buffer('tx3 vin[{}] user_input amount: {}'.format(len(tx3.vin)-1, amount))
            for moneybox_input in moneybox_inputs:
                if moneybox_input['amount'] < 10:
                    print_to_buffer('skipped moneybox entry {}:{} with amount {}'.format(moneybox_input['txid'], moneybox_input['vout'], moneybox_input['amount']))
                    continue # Lets take full moneybox entries
                tx3.vin.append(CTxIn(COutPoint(int(moneybox_input['txid'], 16), moneybox_input['vout']), hex_str_to_bytes(moneybox_input['scriptPubKey']), 0xffffffff))
                reward_taken += moneybox_input['amount']
                print_to_buffer('tx3 vin[{}] moneybox_input amount: {}'.format(len(tx3.vin)-1, moneybox_input['amount']))
                if reward_taken > reward_to_ben:
                    if extra_moneybox_inputs_count > 0:
                        extra_moneybox_inputs_count -= 1
                    else:
                        reward_change = reward_taken - reward_to_ben
                        moneybox_inputs_enough = True
                        break

            assert_equal(moneybox_inputs_enough, True)

            relayfee = node0.getnetworkinfo()['relayfee']  #  (numeric) minimum relay fee for non-free transactions in PLC/kB
            SIGNATURE_SIZE_MIN = 71   # signature is appr 71-72 bytes (with the last byte SIGHASH_TYPE)
            SIGNATURE_SIZE_MAX = 72
            PUBKEY_SIZE = 33
            TXID_SIZE = 32
            HASH160_SIZE = 20

            INPUT_BYTES_BESIDES_SCRIPTSIG = (
                    32 +  # hash
                    4 +   # n
                    1 +   # scriptSigLen
                    4     # nSequence
            )
            P2PKH_OUTPUT_BYTES = (
                    8 +   # nValue
                    1 +   # scriptPubkeyLen
                    HASH160_SIZE + 5
            )
            P2SH_OUTPUT_BYTES = (
                    8 +   # nValue
                    1 +   # scriptPubkeyLen
                    HASH160_SIZE + 3
            )
            COMMON_BYTES = (
                    4 +   # tx version
                    1 +   # inputs count (VarInt)
                    1 +   # outputs count (VarInt)
                    4     # nLockTime
            )

            def get_scriptsig_bytes_cnt_in_user_input(keys_cnt, multisig_script_len):
                # 1 + (SIGNATURE_SIZE + 1) * keys_count_used + len(multisig_script) + 1 + x + (2 if too_long else 0)
                sig_lens_list = [random.randint(SIGNATURE_SIZE_MIN, SIGNATURE_SIZE_MAX) + 1 for _ in range(keys_cnt)]
                sig_lens_sum = sum(sig_lens_list)
                body_len = sig_lens_sum + multisig_script_len + 2
                if multisig_script_len > 0xff:
                    body_len += 2  # OP_PUSHDATA2 then multisig_script_len
                elif multisig_script_len > 0x4b:
                    body_len += 1  # OP_PUSHDATA1 then multisig_script_len
                if body_len > 252:
                    return body_len + 2
                return body_len

            def get_scriptsig_bytes_cnt_in_moneybox_input(keys_cnt):
                # (SIGNATURE_SIZE + 1 + PUBKEY_SIZE + 1) * keys_count_used + TXID_SIZE + 2 + TXID_SIZE + 2 + 2 + (2 if too_long else 0)
                sig_lens_list = [random.randint(SIGNATURE_SIZE_MIN, SIGNATURE_SIZE_MAX) + PUBKEY_SIZE + 2 for _ in range(keys_cnt)]
                sig_lens_sum = sum(sig_lens_list)
                body_len = sig_lens_sum + TXID_SIZE + 1 + 1 + TXID_SIZE + 1 + 1 + 2
                if body_len > 252:
                    return body_len + 2
                return body_len

            assert_equal(len(multisig_script), 3 + (PUBKEY_SIZE + 1) * len(self.user_keys))
            user_inputs_lens_list = [get_scriptsig_bytes_cnt_in_user_input(self.keys_count_used, len(multisig_script)) + INPUT_BYTES_BESIDES_SCRIPTSIG for _ in range(len(user_inputs))]
            user_inputs_lens_sum = sum(user_inputs_lens_list)
            moneybox_inputs_lens_list = [get_scriptsig_bytes_cnt_in_moneybox_input(self.keys_count_used) + INPUT_BYTES_BESIDES_SCRIPTSIG for _ in range(len(tx3.vin) - len(user_inputs))]
            moneybox_inputs_lens_sum = sum(moneybox_inputs_lens_list)
            bytes_user_part = user_inputs_lens_sum + \
                              len(self.get_user_outputs_names(params)) * P2SH_OUTPUT_BYTES + \
                              len(self.get_real_reward_outputs_names(params)) * P2PKH_OUTPUT_BYTES
            bytes_moneybox_part = moneybox_inputs_lens_sum + \
                                  len(self.get_moneybox_outputs_names(params)) * P2SH_OUTPUT_BYTES

            tx_size = bytes_user_part + bytes_moneybox_part + COMMON_BYTES
            # will take (relayfee * 5)
            total_fee_calculated = Decimal(tx_size) * relayfee * 5 / Decimal(1000)
            if fee_user_percent_orig == 'auto':
                # We decided to consider COMMON_BYTES as user part of transaction:
                fee_user_percent = Decimal(bytes_user_part + COMMON_BYTES) / Decimal(tx_size)
            else:
                fee_user_percent = Decimal(fee_user_percent_orig) / 100
            assert(fee_user_percent >= 0 and fee_user_percent <= 1)
            total_fee = ToCoins(fee_total_given) if fee_total_given != 'auto' else total_fee_calculated
            fee_user = total_fee * fee_user_percent
            fee_moneybox = total_fee * (1 - fee_user_percent)
            print_to_buffer('mint: fee calculation: relayfee: {}, bytes_user_part: {}, bytes_moneybox_part: {}, total_fee_calculated: {}, total_fee: {}, fee_user_percent: {}'.
                  format(relayfee, bytes_user_part, bytes_moneybox_part, total_fee_calculated, total_fee, fee_user_percent))

            # append user_outputs to tx:
            user_outputs_indexes = self.appent_user_outputs_to_tx(tx3, user_amount, params, print_to_buffer)
            user_output_index = -1 if len(user_outputs_indexes) == 0 else user_outputs_indexes[-1]

            # append reward_outputs to tx:
            reward_payed = reward_to_ben - fee_user
            if len(self.get_real_reward_outputs_names(params)) > 0:
                # if reward is payed to separate output(s), must be (reward > fee_user)
                assert_greater_than(reward_to_ben, fee_user)
                print_to_buffer('reward_payed: {}, reward_to_ben: {}, fee_user: {}'.format(ToCoins(reward_payed), reward_to_ben, ToCoins(fee_user)))
            self.appent_reward_outputs_to_tx(tx3, reward_payed, params, user_output_index, print_to_buffer)

            # append moneybox_outputs to tx:
            reward_change_orig = reward_change
            reward_change -= fee_moneybox
            print_to_buffer('moneybox change (reward_change_orig - fee_moneybox): {}, reward_change_orig: {}, fee_moneybox: {}'.
                  format(ToCoins(reward_change), reward_change_orig, ToCoins(fee_moneybox)))
            self.appent_moneybox_outputs_to_tx(tx3, reward_change, params, print_to_buffer)

            total_fee_real = ToSatoshi(user_amount + reward_taken)
            for vout in tx3.vout:
                assert_greater_than(total_fee_real, ToSatoshi(vout.nValue))
                total_fee_real -= ToSatoshi(vout.nValue)
            print_to_buffer('mint, total_fee_real (after correction): {}'.format(ToCoins(total_fee_real)))
            if not skip_checks:
                assert_greater_than_or_equal(1, abs(total_fee_real - ToSatoshi(total_fee)))   # assumed fee and real fee may differ on 1 satoshi due to fractional number truncation

            def select_keys(keys, count, indexes = None):
                assert_greater_than_or_equal(len(keys), count)
                if indexes is None:
                    indexes = []
                    while len(indexes) < count:
                        next = random.randint(0, len(keys) - 1)
                        if next not in indexes:
                            indexes.append(next)
                    indexes.sort()
                else:
                    assert_equal(len(indexes), count)
                ret_keys = []
                for i in indexes:
                    ret_keys.append(keys[i])
                return (ret_keys, indexes)

            (used_user_keys, indexes) = select_keys(self.user_keys, self.keys_count_used)
            (used_user_keys_m, _) = select_keys(self.user_keys_m, self.keys_count_used, indexes)
            print_to_buffer('indexes for used_keys ({}): {}'.format(len(indexes), indexes))

            for i in range(len(user_inputs)):
                scriptSig = CScript([OP_0])
                (sig_hash, err) = SignatureHash(CScript(tx3.vin[i].scriptSig), tx3, i, SIGHASH_ALL)
                assert (err is None)
                for user_key in used_user_keys:
                    signature = user_key.sign(sig_hash) + bytes(bytearray([SIGHASH_ALL]))
                    scriptSig += signature
                    print_to_buffer('mint, user input {}, pubkey: {}, signature ({}): {}'.format(i, bytes_to_hex_str(user_key.get_pubkey()), len(signature), bytes_to_hex_str(signature)))
                scriptSig += multisig_script
                tx3.vin[i].scriptSig = scriptSig
                print_to_buffer('mint, user input {}, sig_hash ({}): {}, scriptSig ({}): {}'.format(
                    i, len(sig_hash), bytes_to_hex_str(reverse(sig_hash)), len(scriptSig), bytes_to_hex_str(scriptSig)))
            for i in range(len(user_inputs), len(tx3.vin)):
                # There are no common rules of composing signature for p2sh transaction inputs,
                # we made agreement to replace scriptSig with inner script (CScript(OP_CHECKREWARD)), not
                # with the public key script of the referenced transaction output
                # (excluding all occurences of OP CODESEPARATOR in it), as for p2pkh transactions:
                scriptSig = CScript([OP_CHECKREWARD])
                (sig_hash, err) = SignatureHash(scriptSig, tx3, i, SIGHASH_ALL)
                assert (err is None)
                signatures_and_keys = []
                for user_key in used_user_keys_m:
                    signature = user_key.sign(sig_hash) + bytes(bytearray([SIGHASH_ALL]))
                    signatures_and_keys.append(signature)
                    signatures_and_keys.append(user_key.get_pubkey())
                tx3.vin[i].scriptSig = CScript(signatures_and_keys +
                                               [ ser_uint256(utxo_cert_root.hash), utxo_cert_root.n,
                                                 ser_uint256(utxo_cert_ca3.hash), utxo_cert_ca3.n,
                                                 CScript([OP_CHECKREWARD])])
                signatures_and_keys_hex = [bytes_to_hex_str(item) for item in signatures_and_keys]
                print_to_buffer('mint, moneybox input {}, sig_hash ({}): {}, keys_count_used: {}, signatures_and_keys: {}, scriptSig ({}): {}'.format(
                    i, len(sig_hash), bytes_to_hex_str(reverse(sig_hash)),
                    self.keys_count_used, signatures_and_keys_hex,
                    len(tx3.vin[i].scriptSig), bytes_to_hex_str(tx3.vin[i].scriptSig)))

            user_bytes_real = self.get_bytes_in_tx_inputs(tx3, 0, len(user_inputs))
            moneybox_bytes_real = self.get_bytes_in_tx_inputs(tx3, len(user_inputs), len(tx3.vin) - len(user_inputs))
            if user_bytes_real == user_inputs_lens_sum and moneybox_bytes_real == moneybox_inputs_lens_sum:
                print('Guessed signature sizes, user_bytes: {}, moneybox_bytes: {}'.format(user_bytes_real, moneybox_bytes_real))
                print(print_buffer, end='')
                break
            attemps += 1
            total_delta_user += (user_bytes_real - user_inputs_lens_sum)
            total_delta_moneybox += (moneybox_bytes_real - moneybox_inputs_lens_sum)
            print('Didn\'t guess signature sizes, attemps: {}, user_bytes_real: {}, user_bytes_guessed: {}, mb_bytes_real: {}, mb_bytes_guessed: {}, total_delta_user: {}, total_delta_mb: {}'.
                  format(attemps, user_bytes_real, user_inputs_lens_sum, moneybox_bytes_real, moneybox_inputs_lens_sum, total_delta_user, total_delta_moneybox))
            assert_greater_than(GUESS_SIGSIZES_MAX_ATTEMPTS, attemps) # if we didn't guess in GUESS_SIGSIZES_MAX_ATTEMPTS attempts, something goes wrong

        tx3.rehash()
        print('tx3.hash: {}, multisig_script ({}): {}'.format(tx3.hash, len(multisig_script), bytes_to_hex_str(multisig_script)))

        tx_message = msg_tx(tx3)
        tx_message_bytes = tx_message.serialize()

        tx_real_size = len(tx_message_bytes)
        print('tx_size: {}, hex tx3: {}'.format(tx_real_size, bytes_to_hex_str(tx_message_bytes)))
        if not skip_checks:
            assert_equal(tx_real_size, tx_size)

        self.test_node.send_message(tx_message)
        self.test_node.sync_with_ping()

        # Ensure our transaction is accepted by the node and is included into mempool:
        mempool = node0.getrawmempool()
        assert_equal(tx3.hash in mempool, accepted)

        if accepted == False:
            error = params['error'] if 'error' in params else None
            if error is not None and error[0] is not None:
                assert_equal(self.test_node.reject_message.code, error[0])
            if error is not None and error[1] is not None:
                assert_startswith(self.test_node.reject_message.reason.decode('ascii'), error[1])

        return (tx3.hash, user_outputs_indexes, ToSatoshi(reward_taken - reward_change), ToSatoshi(reward_payed))

    def refill_moneybox(self, amount, params, parent_hash = None, parent_block = None, skip_transactions = []):
        active = (params['refill_moneybox'] == 'script') or (params['refill_moneybox'] == 'random' and random.randint(0, 1) == 0)
        invalid_refill_moneybox = params['invalid_refill_moneybox'] if 'invalid_refill_moneybox' in params else None
        refill_moneybox_dest_list = split_names(params['refill_moneybox_dest']) if 'refill_moneybox_dest' in params else None
        refill_moneybox_accepted = params['refill_moneybox_accepted'] if 'refill_moneybox_accepted' in params else True
        print('will refill_moneybox, amount: {}, active: {}, refill_moneybox_accepted: {}'.format(amount, active, refill_moneybox_accepted))
        if invalid_refill_moneybox is not None:
            print('invalid_refill_moneybox: {}'.format(invalid_refill_moneybox))
        if refill_moneybox_dest_list is not None:
            assert_equal(len(refill_moneybox_dest_list), 1) # only one destination is supported
            print('refill_moneybox_dest_list ({}): {}'.format(len(refill_moneybox_dest_list), refill_moneybox_dest_list))
        node0 = self.nodes[0]
        if active:
            # We compose a new block and refill money-box, and then ensure the node accepts this block:
            self.test_node.sync_with_ping()
            if parent_hash is None:
                parent_hash = node0.getbestblockhash()
            if parent_block is None:
                parent_block = node0.getblock(parent_hash)
            print('parent_block: {}'.format(parent_block))
            assert_equal(parent_hash, parent_block['hash'])
            block = CBlock()
            block.nVersion = parent_block['version']
            block.hashPrevBlock = int(parent_hash, 16)
            block.nTime = parent_block['time'] + 1
            block.nBits = int(parent_block['bits'], 16)
            height = parent_block['height'] + 1
            if invalid_refill_moneybox is None and refill_moneybox_dest_list is None:
                # regular workflow:
                coinbase = create_coinbase(height, None, 0, ToSatoshi(amount))
            elif invalid_refill_moneybox == 1:
                coinbase = create_coinbase(height, None, 0, 0)
            elif invalid_refill_moneybox == 2:
                coinbase = create_coinbase(height, None, 0, ToSatoshi(amount) - 1)
            elif invalid_refill_moneybox == 3:
                coinbase = create_coinbase(height, None, 0, ToSatoshi(amount) + 1)
            elif invalid_refill_moneybox == 4:
                coinbase = create_coinbase(height, None, 0, ToSatoshi(amount), granularity = 5 * COIN)
            elif invalid_refill_moneybox == 5:
                coinbase = create_coinbase(height, None, 0, ToSatoshi(amount), granularity = 15 * COIN)
            elif len(refill_moneybox_dest_list) == 1:
                coinbase = create_coinbase(height, None, 0, ToSatoshi(amount),
                                           moneyboxscript = self.get_dest_scriptpubkey(refill_moneybox_dest_list[0]))
            else:
                assert (0)
            block.vtx.append(coinbase)
            mempool = node0.getrawmempool()
            for txid in mempool:
                if txid not in skip_transactions:
                    tx = FromHex(CTransaction(), node0.getrawtransaction(txid))
                    block.vtx.append(tx)
                    print('tx from mempool {}: added to block'.format(txid))
                else:
                    print('tx from mempool {}: skipped'.format(txid))
            block.hashMerkleRoot = block.calc_merkle_root()
            block.nNonce = random.randint(0,0xffff)
            block.solve()
            self.test_node.send_and_ping(msg_block(block))
            print('bestblockhash: {}, block.hash: {}, refill_moneybox_accepted: {}'.format(node0.getbestblockhash(), block.hash, refill_moneybox_accepted))
            assert_equal(int(node0.getbestblockhash(), 16) == block.sha256, refill_moneybox_accepted)
            return block.hash
        else:
            # We tell the node to generate a new block, and then ensure that money-box is refilled with expected amount:
            assert_equal(len(skip_transactions), 0) # if we want to skip transactions, we must generate a new block ourselves, not by node
            node0.generate(1)
            self.test_node.sync_with_ping()
            best_hash = node0.getbestblockhash()
            last_block = node0.getblock(best_hash)
            amount_got = Decimal(0)
            txid0 = last_block['tx'][0]
            txraw0 = node0.getrawtransaction(txid0)
            tx0 = node0.decoderawtransaction(txraw0)
            moneybox_script_hex = bytes_to_hex_str(GetP2SHMoneyboxScript())
            for i, vout in enumerate(tx0['vout']):
                scriptPubKey = vout['scriptPubKey']['hex']
                if i == 0:
                    assert(scriptPubKey != moneybox_script_hex)
                    continue
                if hex_str_to_bytes(scriptPubKey)[0] == int(OP_RETURN):
                    continue
                if i != 0:
                    assert_equal(scriptPubKey, moneybox_script_hex)
                    amount_got += vout['value']
            print('amount expected: {}, amount got: {}, refill_moneybox_accepted: {}'.format(
                ToCoins(amount), ToCoins(amount_got), refill_moneybox_accepted))
            assert_equal(ToSatoshi(amount_got) == ToSatoshi(amount), refill_moneybox_accepted)
            return best_hash

    def spend_utxo(self, utxo, key):
        utxo_hash_hex = hashToHex(utxo.hash)
        assert_in(utxo_hash_hex, self.txmap)
        prevtx = self.txmap[utxo_hash_hex]
        assert_greater_than(len(prevtx.vout), utxo.n)
        amount = prevtx.vout[utxo.n].nValue
        amount_orig = amount
        amount -= ToSatoshi('0.01')
        prevScriptPubKey = prevtx.vout[utxo.n].scriptPubKey
        tx4 = CTransaction()
        tx4.vin.append(CTxIn(utxo, b"", 0xffffffff))
        tx4.vout.append(CTxOut(amount, GetP2PKHScript(hash160(b'xyu')))) # send money to 'xyu'
        (sig_hash, err) = SignatureHash(prevScriptPubKey, tx4, 0, SIGHASH_ALL)
        assert (err is None)
        signature = key.sign(sig_hash) + bytes(bytearray([SIGHASH_ALL]))
        tx4.vin[0].scriptSig = CScript([signature, key.get_pubkey()])
        tx4.rehash()

        print('spend_utxo, utxo: {}, amount: {}, amount_orig: {}, pubkeyhash: {}, txid: {}, prevScriptPubKey ({}): {}'.
              format(utxo, amount, amount_orig, bytes_to_hex_str(reverse(hash160(key.get_pubkey()))), tx4.hash,
                     len(prevScriptPubKey), bytes_to_hex_str(prevScriptPubKey)))

        tx_message = msg_tx(tx4)
        self.test_node.send_message(tx_message)
        self.test_node.sync_with_ping()

        node0 = self.nodes[0]
        node0.generate(1)
        self.test_node.sync_with_ping()
        best_hash = node0.getbestblockhash()
        last_block = node0.getblock(best_hash)
        # Ensure our transaction is accepted by the node and is included into a block:
        assert_in(tx4.hash, last_block['tx'])
        del self.txmap[utxo_hash_hex]


    def create_root_certificate(self, params):
        scenario = params['invalid_root_cert_ref'] if 'invalid_root_cert_ref' in params else None
        utxo_cert_root = None
        ca3_key = None

        if scenario is None:
            # regular workflow
            pass
        elif scenario == 1:
            # non-existing transaction (certificate)
            utxo_cert_root = COutPoint(uint256_from_str(hash256(b'xyu')), 50)
        elif scenario == 2:
            # regular P2PKH transaction, not certificate
            (utxo_cert_root, _) = self.pay_to_address(AddressFromPubkey(self.genezis_key0.get_pubkey()), params['rootcertamount'])
        elif scenario == 3:
            # invalid certificate: transfers money to another P2PKH address, not to itself
            away_key = self.create_key('away_key', 'fake_root_cert')
            (utxo_coins_root, _) = self.pay_to_address(AddressFromPubkey(self.genezis_key0.get_pubkey()),
                                                       ToCoins(params['rootcertamount']) + ToCoins('0.01'))
            (ca3_keys, _, _, utxo_cert_root, _) = self.create_cert(utxo_coins_root, params['rootcertamount'],
                                                                   self.genezis_key0, 1, 1, params['greenflag'], False, False,
                                                                   'fake_root_cert', alt_dest_pubkeyhash = hash160(away_key.get_pubkey()))
            assert_equal(len(ca3_keys), 1)
            ca3_key = ca3_keys[0]
        elif scenario == 4:
            # will be processed in update_root_certificate() later
            # another root certificate, not a parent of user certificate (CA3 keys in root and user certificates are different)
            pass
        elif scenario == 5:
            # invalid root certificate, with unknown root key not mentioned in genezis block
            fake_genezis_key = self.create_key('fake_genezis_key')
            (utxo_coins_root, _) = self.pay_to_address(AddressFromPubkey(fake_genezis_key.get_pubkey()),
                                                       ToCoins(params['rootcertamount']) + ToCoins('0.01'))
            (ca3_keys, _, _, utxo_cert_root, _) = self.create_cert(utxo_coins_root, params['rootcertamount'],
                                                                   fake_genezis_key, 1, 1, params['greenflag'], False,
                                                                   False, 'fake_root_cert')
            assert_equal(len(ca3_keys), 1)
            ca3_key = ca3_keys[0]
        elif scenario == 6:
            # use GENEZIS_PRIV_KEY1_HEX instead of GENEZIS_PRIV_KEY0_HEX:
            genezis_key1 = CECKey()
            genezis_key1.set_secretbytes(hex_str_to_bytes(GENEZIS_PRIV_KEY1_HEX))
            if not genezis_key1.is_compressed():
                genezis_key1.set_compressed(True)
            (utxo_coins_root, _) = self.pay_to_address(AddressFromPubkey(genezis_key1.get_pubkey()),
                                                       ToCoins(params['rootcertamount']) + ToCoins('0.01'))
            (ca3_keys, _, _, utxo_cert_root, _) = self.create_cert(utxo_coins_root, params['rootcertamount'],
                                                                   genezis_key1, 1, 1, params['greenflag'], False,
                                                                   False, 'root_cert')
            assert_equal(len(ca3_keys), 1)
            ca3_key = ca3_keys[0]
        else:
            assert (0)

        if utxo_cert_root is not None:
            if ca3_key is None:
                ca3_key = self.create_key('ca3_key', 'fake_root_cert')
            print('create_root_certificate, invalid_root_cert_ref, scenario: {}, utxo_cert_root: {}'.format(scenario, utxo_cert_root))
            return (utxo_cert_root, ca3_key)

        #
        # now regular workflow:
        #

        # Script pays to address ROOT_PKH:
        (utxo_coins_root, _) = self.pay_to_address(AddressFromPubkey(self.genezis_key0.get_pubkey()),
                                                   ToCoins(params['rootcertamount']) + ToCoins('0.01'))

        # Скрипт переводит с адреса ROOT_PKH на этот же адрес некоторую сумму, например 1 PLC, активируя CA3_PKH ключ.
        (ca3_keys, _, _, utxo_cert_root, _) = self.create_cert(utxo_coins_root, params['rootcertamount'],
                                                               self.genezis_key0,
                                                               1, 1, params['greenflag'], False, False, 'root_cert')
        assert_equal(len(ca3_keys), 1)
        ca3_key = ca3_keys[0]
        return (utxo_cert_root, ca3_key)


    def update_root_certificate(self, params, utxo_cert_root):
        scenario = params['invalid_root_cert_ref'] if 'invalid_root_cert_ref' in params else None
        if 'revoke_root_cert' in params and params['revoke_root_cert'] == True:
            self.spend_utxo(utxo_cert_root, self.genezis_key0)
            print('update_root_certificate: revoke_root_cert == True, spending {}'.format(utxo_cert_root))

        if scenario == 4:
            # another root certificate, not a parent of user certificate (CA3 keys in root and user certificates are different)
            # create one more root certificate:
            (utxo_coins_root, _) = self.pay_to_address(AddressFromPubkey(self.genezis_key0.get_pubkey()), ToCoins(params['rootcertamount']) + ToCoins('0.01'))
            (_, _, _, utxo_cert_root, _) = self.create_cert(utxo_coins_root, params['rootcertamount'], self.genezis_key0,
                                                                  1, 1, params['greenflag'], False, False, 'root_cert_2')
            print('update_root_certificate, invalid_root_cert_ref, scenario: {}, utxo_cert_root: {}'.format(scenario, utxo_cert_root))

        return utxo_cert_root


    def create_user_certificate(self, params, ca3_key, user_keys_to_use = None):
        scenario = params['invalid_user_cert_ref'] if 'invalid_user_cert_ref' in params else None
        green_flag_in_user_cert = params['green_flag_in_user_cert'] if 'green_flag_in_user_cert' in params else False
        utxo_cert_ca3 = None
        user_keys = None
        ben_key = None
        time_ca3 = None

        if scenario is None:
            # regular workflow
            pass
        elif scenario == 1:
            # non-existing transaction (certificate)
            utxo_cert_ca3 = COutPoint(uint256_from_str(hash256(b'xyu_ca3')), 100)
        elif scenario == 2:
            # regular P2PKH transaction, not certificate
            (utxo_cert_ca3, _) = self.pay_to_address(AddressFromPubkey(ca3_key.get_pubkey()), params['ca3certamount'])
        elif scenario == 3:
            # invalid certificate: transfers money to another P2PKH address, not to itself
            away_key = self.create_key('away_key', 'fake_ca3_cert')
            (utxo_coins_ca3, _) = self.pay_to_address(AddressFromPubkey(ca3_key.get_pubkey()), ToCoins(params['ca3certamount']) + ToCoins('0.01'))
            (user_keys, _, ben_key, utxo_cert_ca3, time_ca3) = self.create_cert(utxo_coins_ca3, params['ca3certamount'],
                                                                                ca3_key, params['keys_count_total'], self.keys_count_required,
                                                                                green_flag_in_user_cert, True,
                                                                                params['ben_enabled'], 'fake_ca3_cert', user_keys_to_use,
                                                                                alt_dest_pubkeyhash=hash160(away_key.get_pubkey()))
        elif scenario == 4:
            # will be processed in update_user_certificate() later
            # another user certificate, not a parent of used user keys (user keys used in minting transaction and given in this certificate are different)
            pass
        elif scenario == 5:
            # will be processed in update_user_certificate() later
            pass
        else:
            assert (0)

        if utxo_cert_ca3 is not None:
            if user_keys is None:
                user_keys = self.create_other_keys(params['keys_count_total'], 'user_key', 'fake_ca3_cert')
            if ben_key is None:
                ben_key = self.create_key('ben_key', 'fake_ca3_cert')
            if time_ca3 is None:
                node0 = self.nodes[0]
                node0.generate(1)
                self.test_node.sync_with_ping()
                best_hash = node0.getbestblockhash()
                last_block = node0.getblock(best_hash)
                time_ca3 = last_block['time']
            print('create_user_certificate, invalid_user_cert_ref, scenario: {}, utxo_cert_ca3: {}, time_ca3: {}'.format(scenario, utxo_cert_ca3, time_ca3))
            return (user_keys, ben_key, utxo_cert_ca3, time_ca3)

        #
        # now regular workflow:
        #

        # Script pays to address CA3_PKH:
        (utxo_coins_ca3, _) = self.pay_to_address(AddressFromPubkey(ca3_key.get_pubkey()), ToCoins(params['ca3certamount']) + ToCoins('0.01'))

        # Скрипт переводит с адреса CA3_PKH на этот же адрес некоторую сумму, например 10 mPLC, активируя User_PKH ключи.
        exp_date_offset = params['ca3_expiration_offset'] if 'ca3_expiration_offset' in params else None
        mint_limit = params['ca3_minting_limit'] if 'ca3_minting_limit' in params else None
        (user_keys, _, ben_key, utxo_cert_ca3, time_ca3) = self.create_cert(utxo_coins_ca3, params['ca3certamount'],
                                                                            ca3_key, params['keys_count_total'], self.keys_count_required,
                                                                            False, True, params['ben_enabled'], 'ca3_cert',
                                                                            user_keys_to_use,
                                                                            exp_date_offset=exp_date_offset,
                                                                            mint_limit=mint_limit)
        assert_equal(len(user_keys), params['keys_count_total'])
        return (user_keys, ben_key, utxo_cert_ca3, time_ca3)


    def update_user_certificate(self, params, utxo_cert_ca3, ca3_key, time_ca3):
        scenario = params['invalid_user_cert_ref'] if 'invalid_user_cert_ref' in params else None

        if 'revoke_user_cert' in params and params['revoke_user_cert'] == True:
            self.spend_utxo(utxo_cert_ca3, ca3_key)
            print('update_user_certificate: revoke_user_cert == True, spending {}'.format(utxo_cert_ca3))

        if scenario == 4:
            # another user certificate, not a parent of used user keys (user keys used in minting transaction and given in this certificate are different)
            (utxo_coins_ca3, _) = self.pay_to_address(AddressFromPubkey(ca3_key.get_pubkey()),
                                                      ToCoins(params['ca3certamount']) + ToCoins('0.01'))
            (_, _, _, utxo_cert_ca3, time_ca3) = self.create_cert(utxo_coins_ca3, params['ca3certamount'], ca3_key,
                                                                  params['keys_count_total'], self.keys_count_required,
                                                                  False, True, params['ben_enabled'], 'ca3_cert_2')
            print('update_user_certificate: invalid_user_cert_ref, scenario: {}, utxo_cert_ca3: {}'.format(scenario, utxo_cert_ca3))
        if scenario == 5:
            # invalid user coins (not mentioned in CA3 certificate), but valid user keys for signing moneybox outputs in minting tx
            self.spend_utxo(utxo_cert_ca3, ca3_key)
            (utxo_coins_ca3, _) = self.pay_to_address(AddressFromPubkey(ca3_key.get_pubkey()),
                                                      ToCoins(params['ca3certamount']) + ToCoins('0.01'))
            (self.user_keys_m, _, self.ben_key, utxo_cert_ca3, time_ca3) = self.create_cert(utxo_coins_ca3, params['ca3certamount'],
                                                                                            ca3_key, params['keys_count_total'], self.keys_count_required,
                                                                                            False, True, params['ben_enabled'], 'ca3_cert_m')
            print('update_user_certificate: invalid_user_cert_ref, scenario: {}, utxo_cert_ca3: {}'.format(scenario, utxo_cert_ca3))

        return (utxo_cert_ca3, time_ca3)


    def create_user_coins(self, user_keys, params):
        user_outputs = []
        if 'more_useramount1' in params:
            (user_output, _) = self.pay_to_multisig_address(user_keys, ToCoins(params['more_useramount1']), self.keys_count_used, False)
            user_outputs.append(user_output)
        if 'more_useramount2' in params:
            (user_output, _) = self.pay_to_multisig_address(user_keys, ToCoins(params['more_useramount2']), self.keys_count_used, False)
            user_outputs.append(user_output)
        (user_output, time_usermoney) = self.pay_to_multisig_address(user_keys, ToCoins(params['useramount']), self.keys_count_used)
        user_outputs.append(user_output)
        return (user_outputs, time_usermoney)


    def check_spent_amount_in_cert(self, outpoint, amount_expected):
        txid_hex = '%064x' % (outpoint.hash)
        txout = self.nodes[0].gettxout(txid_hex, outpoint.n)
        if amount_expected == 0 and (txout is None or 'storage' not in txout):
            return
        storage_bin = hex_str_to_bytes(txout['storage'])
        assert_greater_than_or_equal(len(storage_bin), 16)
        amount_got = struct.unpack("<q", storage_bin[8:16])[0]
        assert_equal(amount_expected, amount_got)


    def run_testcase(self, params):
        node0 = self.nodes[0]
        node0.generate(101)
        self.test_node.sync_with_ping()
        total_rewardamount = 0
        self.keys_count_required = params['keys_count_required'] if params['keys_count_required'] > 0 else params['keys_count_total']
        self.keys_count_used = params['keys_count_used']

        # Create root certificate:
        (utxo_cert_root, ca3_key) = self.create_root_certificate(params)
        utxo_cert_root = self.update_root_certificate(params, utxo_cert_root)

        if params['ca3_age'] >= params['usermoney_age']:
            # User certificate is older than user money, create it first:

            # Create user certificate:
            (self.user_keys, self.ben_key, utxo_cert_ca3, time_ca3) = self.create_user_certificate(params, ca3_key)
            (utxo_cert_ca3, time_ca3) = self.update_user_certificate(params, utxo_cert_ca3, ca3_key, time_ca3)

            # Wait:
            delta_age = params['ca3_age'] - params['usermoney_age']
            self.emulate_fast_wait(delta_age, time_ca3, 'delta_age (ca3_age - usermoney_age)')

            # Script pays to multisig-address [User_PKH]:
            (user_outputs, time_usermoney) = self.create_user_coins(self.user_keys, params)

            # Wait:
            self.emulate_fast_wait(params['usermoney_age'], time_usermoney, 'usermoney_age')

        else:
            # User money is older than user certificate, create it first:

            # Script pays to multisig-address [User_PKH]:
            self.user_keys = self.create_other_keys(params['keys_count_total'], 'user_key', 'ca3_cert')
            (user_outputs, time_usermoney) = self.create_user_coins(self.user_keys, params)

            # Wait:
            delta_age = params['usermoney_age'] - params['ca3_age']
            self.emulate_fast_wait(delta_age, time_usermoney, 'delta_age (usermoney_age - ca3_age)')

            # Create user certificate:
            (self.user_keys, self.ben_key, utxo_cert_ca3, time_ca3) = self.create_user_certificate(params, ca3_key, self.user_keys)
            (utxo_cert_ca3, time_ca3) = self.update_user_certificate(params, utxo_cert_ca3, ca3_key, time_ca3)

            # Wait:
            self.emulate_fast_wait(params['ca3_age'], time_ca3, 'ca3_age')

        if params['name'].startswith('special_'):
            self.run_special_testcase(params, {
                'user_outputs': user_outputs,
                'utxo_cert_root': utxo_cert_root,
                'utxo_cert_ca3': utxo_cert_ca3,
            })
            return

        # step8
        # Скрипт начисляет проценты на положенную сумму из копилки, соблюдая гранулярность аутпутов из копилки,
        # в соответствии с флагом greenFlag, возрастом user-сертификата, возрастом пользовательских денег
        # на адресе User_PKH, на которые начисляются проценты, и процентной ставкой из user-сертификата
        rewardamount = params['rewardamount']
        reward_to = params['reward_to']
        accepted = params['accepted']
        (mint_txid, mint_user_outputs_indexes, spent, reward_payed) = self.mint(user_outputs, utxo_cert_root, utxo_cert_ca3,
                                                                                rewardamount, reward_to, accepted, params)
        self.check_spent_amount_in_cert(utxo_cert_ca3, 0) # amount is counted after generating a block, now must be zero in any case

        # step9
        # Проверка пополнения копилки на сумму, которая была потрачена.
        if params['accepted']:
            self.refill_moneybox(spent, params)
            total_rewardamount += reward_payed
            if 'ca3_minting_limit' in params and params['ca3_minting_limit'] is not None:
                self.check_spent_amount_in_cert(utxo_cert_ca3, total_rewardamount)

        if 'step2_enabled' in params and params['step2_enabled'] == True:
            print('Will run step2...')
            # update user_outputs: now they are user outputs from previous mint tx:
            user_outputs = [COutPoint(int(mint_txid, 16), i) for i in mint_user_outputs_indexes]
            self.txmap[mint_txid] = node0.getrawtransaction(mint_txid, True)
            last_block_time = node0.getblock(node0.getbestblockhash())['time']
            self.emulate_fast_wait(params['step2_wait_interval'], last_block_time, 'step2_wait_interval')
            rewardamount = params['step2_rewardamount']
            reward_to = params['step2_reward_to']
            accepted = params['step2_accepted']
            (mint_txid, mint_user_outputs_indexes, spent, reward_payed) = self.mint(user_outputs, utxo_cert_root, utxo_cert_ca3, rewardamount, reward_to, accepted, params)
            if params['step2_accepted']:
                self.refill_moneybox(spent, params)
                total_rewardamount += reward_payed
                if 'ca3_minting_limit' in params and params['ca3_minting_limit'] is not None:
                    self.check_spent_amount_in_cert(utxo_cert_ca3, total_rewardamount)

        if 'step3_enabled' in params and params['step3_enabled'] == True:
            print('Will run step3...')
            # update user_outputs: now they are user outputs from previous mint tx:
            user_outputs = [COutPoint(int(mint_txid, 16), i) for i in mint_user_outputs_indexes]
            self.txmap[mint_txid] = node0.getrawtransaction(mint_txid, True)
            last_block_time = node0.getblock(node0.getbestblockhash())['time']
            self.emulate_fast_wait(params['step3_wait_interval'], last_block_time, 'step3_wait_interval')
            rewardamount = params['step3_rewardamount']
            reward_to = params['step3_reward_to']
            accepted = params['step3_accepted']
            (_, _, spent, reward_payed) = self.mint(user_outputs, utxo_cert_root, utxo_cert_ca3, rewardamount, reward_to, accepted, params)
            if params['step3_accepted']:
                self.refill_moneybox(spent, params)
                total_rewardamount += reward_payed
                if 'ca3_minting_limit' in params and params['ca3_minting_limit'] is not None:
                    self.check_spent_amount_in_cert(utxo_cert_ca3, total_rewardamount)


    def run_special_testcase(self, params, args):
        if params['name'] == 'special_minting_limit_mempool':
            return self.run_special_minting_limit_mempool(params, args)
        if params['name'] == 'special_minting_limit_fork_blocks':
            return self.run_special_minting_limit_fork_blocks(params, args)
        assert(0) # unknown special testcase


    def run_special_minting_limit_mempool(self, params, args):
        user_outputs = args['user_outputs']
        utxo_cert_root = args['utxo_cert_root']
        utxo_cert_ca3 = args['utxo_cert_ca3']
        ca3_minting_limit = params['ca3_minting_limit']
        rewardamount = params['rewardamount']
        reward_to = params['reward_to']
        accepted = params['accepted']

        assert_equal(len(user_outputs), 3)
        assert_equal(accepted, True)
        assert_greater_than(ca3_minting_limit, 0)
        assert_equal(ToSatoshi(ca3_minting_limit), ToSatoshi(rewardamount))
        assert_equal(ToSatoshi(params['useramount']), ToSatoshi(params['more_useramount1']))
        assert_equal(ToSatoshi(params['useramount']), ToSatoshi(params['more_useramount2']))

        # first try to mint all outputs at once in 1 transaction, must be rejected (limit exceeded):
        print('will run reject step...')
        params['error'] = (64, BAD_REWARD_LIMIT_EXCEEDED)
        (_, _, spent, _) = self.mint(user_outputs, utxo_cert_root, utxo_cert_ca3, rewardamount * 3, reward_to, False, params)
        self.check_spent_amount_in_cert(utxo_cert_ca3, 0)  # tx was rejected, nothing was counted

        # and now mint one by one, must be accepted:
        total_spent = 0
        total_rewardamount = 0
        for i, user_output in enumerate(user_outputs):
            print('will run step {}...'.format(i))
            (_, _, spent, reward_payed) = self.mint([user_output], utxo_cert_root, utxo_cert_ca3, rewardamount, reward_to, True, params)
            total_spent += spent
            total_rewardamount += reward_payed
            self.check_spent_amount_in_cert(utxo_cert_ca3, 0)  # amount is counted only after generating a block, now zero

        self.refill_moneybox(total_spent, params)
        self.check_spent_amount_in_cert(utxo_cert_ca3, total_rewardamount)


    def run_special_minting_limit_fork_blocks(self, params, args):
        user_outputs = args['user_outputs']
        utxo_cert_root = args['utxo_cert_root']
        utxo_cert_ca3 = args['utxo_cert_ca3']
        ca3_minting_limit = params['ca3_minting_limit']
        rewardamount = params['rewardamount']
        reward_to = params['reward_to']
        accepted = params['accepted']

        assert_equal(len(user_outputs), 3)
        assert_equal(accepted, True)
        assert_greater_than(ca3_minting_limit, 0)
        assert_equal(ToSatoshi(ca3_minting_limit), ToSatoshi(rewardamount * 2))
        assert_equal(ToSatoshi(params['useramount']), ToSatoshi(params['more_useramount1']))
        assert_equal(ToSatoshi(params['useramount']), ToSatoshi(params['more_useramount2']))
        assert_equal(params['refill_moneybox'], 'script')
        assert('refill_moneybox_accepted' not in params or params['refill_moneybox_accepted'] == True)

        # blocks: --> B1
        print('Will run step B1...')
        hash_b0 = self.nodes[0].getbestblockhash()
        print('hash_b0: {}'.format(hash_b0))
        (_, _, spent_b1, reward_payed_b1) = self.mint([user_outputs[0]], utxo_cert_root, utxo_cert_ca3, rewardamount,
                                                      reward_to, accepted, params)
        self.check_spent_amount_in_cert(utxo_cert_ca3, 0)  # amount is counted only after generating a block, now zero
        hash_b1 = self.refill_moneybox(spent_b1, params)
        print('hash_b1: {}'.format(hash_b1))
        self.check_spent_amount_in_cert(utxo_cert_ca3, reward_payed_b1)

        # blocks: --> B1
        #         \-> B2
        print('Will run step B2...')
        (mint2_txid, _, spent_b2, reward_payed_b2) = self.mint([user_outputs[1]], utxo_cert_root, utxo_cert_ca3,
                                                               rewardamount, reward_to, accepted, params)
        self.check_spent_amount_in_cert(utxo_cert_ca3, reward_payed_b1)  # nothing was changed - new block hasn't been generated yet
        params['refill_moneybox_accepted'] = False
        hash_b2 = self.refill_moneybox(spent_b2, params, hash_b0)
        print('hash_b2: {}'.format(hash_b2))
        self.check_spent_amount_in_cert(utxo_cert_ca3, reward_payed_b1)  # nothing was changed - this block wasn't accepted

        # blocks: --> B1
        #         \-> B2 --> B3
        print('Will run step B3...')
        (_, _, spent_b3, reward_payed_b3) = self.mint([user_outputs[2]], utxo_cert_root, utxo_cert_ca3, rewardamount,
                                                      reward_to, accepted, params)
        self.check_spent_amount_in_cert(utxo_cert_ca3, reward_payed_b1)  # nothing was changed - new block hasn't been generated yet
        params['refill_moneybox_accepted'] = True
        block_b0 = self.nodes[0].getblock(hash_b0)
        block_b2 = { 'version': block_b0['version'], 'bits': block_b0['bits'], 'hash': hash_b2, 'height': block_b0['height'] + 1, 'time': block_b0['time'] + 1 }
        self.refill_moneybox(spent_b3, params, hash_b2, block_b2, skip_transactions=[mint2_txid]) # mint2_txid is in block B2, but before accepting block B3 it is still in mempool
        self.check_spent_amount_in_cert(utxo_cert_ca3, reward_payed_b2 + reward_payed_b3)  # B1 went off, now B2 + B3

        assert_equal(ToSatoshi(ca3_minting_limit), reward_payed_b2 + reward_payed_b3)


    def run_test(self):
        name = self.options.runtestcase
        if name is None:
            # minting.py without parameters - ignore it
            return
        testcase = get_minting_testcases()[name]
        assert (testcase is not None)

        print('Running testcase {}:\n{}'.format(name, testcase))
        self.check_parameters(testcase)
        print('Updated parameters: {}'.format(testcase))
        self.run_testcase(testcase)
        print('End of testcase {}'.format(name))


if __name__ == '__main__':
    MintingTest().main()
