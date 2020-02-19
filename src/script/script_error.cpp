// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "script_error.h"

const char* ScriptErrorString(const ScriptError serror)
{
    switch (serror)
    {
        case SCRIPT_ERR_OK:
            return "No error";
        case SCRIPT_ERR_EVAL_FALSE:
            return "Script evaluated without error but finished with a false/empty top stack element";
        case SCRIPT_ERR_VERIFY:
            return "Script failed an OP_VERIFY operation";
        case SCRIPT_ERR_EQUALVERIFY:
            return "Script failed an OP_EQUALVERIFY operation";
        case SCRIPT_ERR_CHECKMULTISIGVERIFY:
            return "Script failed an OP_CHECKMULTISIGVERIFY operation";
        case SCRIPT_ERR_CHECKSIGVERIFY:
            return "Script failed an OP_CHECKSIGVERIFY operation";
        case SCRIPT_ERR_NUMEQUALVERIFY:
            return "Script failed an OP_NUMEQUALVERIFY operation";
        case SCRIPT_ERR_SCRIPT_SIZE:
            return "Script is too big";
        case SCRIPT_ERR_PUSH_SIZE:
            return "Push value size limit exceeded";
        case SCRIPT_ERR_OP_COUNT:
            return "Operation limit exceeded";
        case SCRIPT_ERR_STACK_SIZE:
            return "Stack size limit exceeded";
        case SCRIPT_ERR_SIG_COUNT:
            return "Signature count negative or greater than pubkey count";
        case SCRIPT_ERR_PUBKEY_COUNT:
            return "Pubkey count negative or limit exceeded";
        case SCRIPT_ERR_BAD_OPCODE:
            return "Opcode missing or not understood";
        case SCRIPT_ERR_DISABLED_OPCODE:
            return "Attempted to use a disabled opcode";
        case SCRIPT_ERR_INVALID_STACK_OPERATION:
            return "Operation not valid with the current stack size";
        case SCRIPT_ERR_INVALID_ALTSTACK_OPERATION:
            return "Operation not valid with the current altstack size";
        case SCRIPT_ERR_OP_RETURN:
            return "OP_RETURN was encountered";
        case SCRIPT_ERR_UNBALANCED_CONDITIONAL:
            return "Invalid OP_IF construction";
        case SCRIPT_ERR_NEGATIVE_LOCKTIME:
            return "Negative locktime";
        case SCRIPT_ERR_UNSATISFIED_LOCKTIME:
            return "Locktime requirement not satisfied";
        case SCRIPT_ERR_SIG_HASHTYPE:
            return "Signature hash type missing or not understood";
        case SCRIPT_ERR_SIG_DER:
            return "Non-canonical DER signature";
        case SCRIPT_ERR_MINIMALDATA:
            return "Data push larger than necessary";
        case SCRIPT_ERR_SIG_PUSHONLY:
            return "Only non-push operators allowed in signatures";
        case SCRIPT_ERR_SIG_HIGH_S:
            return "Non-canonical signature: S value is unnecessarily high";
        case SCRIPT_ERR_SIG_NULLDUMMY:
            return "Dummy CHECKMULTISIG argument must be zero";
        case SCRIPT_ERR_MINIMALIF:
            return "OP_IF/NOTIF argument must be minimal";
        case SCRIPT_ERR_SIG_NULLFAIL:
            return "Signature must be zero for failed CHECK(MULTI)SIG operation";
        case SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS:
            return "NOPx reserved for soft-fork upgrades";
        case SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM:
            return "Witness version reserved for soft-fork upgrades";
        case SCRIPT_ERR_PUBKEYTYPE:
            return "Public key is neither compressed or uncompressed";
        case SCRIPT_ERR_WITNESS_PROGRAM_WRONG_LENGTH:
            return "Witness program has incorrect length";
        case SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY:
            return "Witness program was passed an empty witness";
        case SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH:
            return "Witness program hash mismatch";
        case SCRIPT_ERR_WITNESS_MALLEATED:
            return "Witness requires empty scriptSig";
        case SCRIPT_ERR_WITNESS_MALLEATED_P2SH:
            return "Witness requires only-redeemscript scriptSig";
        case SCRIPT_ERR_WITNESS_UNEXPECTED:
            return "Witness provided for non-witness script";
        case SCRIPT_ERR_WITNESS_PUBKEYTYPE:
            return "Using non-compressed keys in segwit";
        case SCRIPT_ERR_BAD_REWARD:
            return "Bad reward";
        case SCRIPT_ERR_BAD_REWARD_USER_ADDRESS:
            return "Bad reward, incorrect user address";
        case SCRIPT_ERR_BAD_REWARD_SCRIPT:
            return "Bad reward, script";
        case SCRIPT_ERR_BAD_REWARD_ZERO_PERCENT:
            return "Bad reward, zero percent";
        case SCRIPT_ERR_BAD_REWARD_CERT_EXPIRED:
            return "Bad reward, cert expired";
        case SCRIPT_ERR_BAD_REWARD_SPENT:
            return "Bad reward, vin spent";
        case SCRIPT_ERR_BAD_REWARD_ADDR_MISMATCH:
            return "Bad reward, user address mismatch";
        case SCRIPT_ERR_VAD_REWARD_NOT_MATURED:
            return "Bad reward, not matured";
        case SCRIPT_ERR_BAD_REWARD_MANY_MONEYBOX:
            return "Bad reward, too many moneybox inputs";
        case SCRIPT_ERR_BAD_REWARD_NO_USER_VINS:
            return "Bad reward, no user inputs";
        case SCRIPT_ERR_BAD_REWARD_MANY_MONEYBOX_OUTS:
            return "Bad reward, too many moneybox outputs";
        case SCRIPT_ERR_BAD_REWARD_MANY_USER_OUTS:
            return "Bad reward, too many user outputs";
        case SCRIPT_ERR_BAD_REWARD_MANY_BEN_OUTS:
            return "Bad reward, too many beneficiary outputs";
        case SCRIPT_ERR_BAD_REWARD_ROBBERY:
            return "Bad reward. Everybody be cool, this is a robbery!!!";
        case SCRIPT_ERR_BAD_REWARD_LESS_THAN_FEE:
            return "Bad reward, less than transaction fee";
        case SCRIPT_ERR_BAD_REWARD_BIG_BEN:
            return "Bad reward, BIG BEN";
        case SCRIPT_ERR_BAD_REWARD_NOSIG:
            return "Bad reward, no signatures";
        case SCRIPT_ERR_BAD_REWARD_WRONG_SIG:
            return "Bad reward, wrong signatures count";
        case SCRIPT_ERR_BAD_REWARD_INVALID_SIG:
            return "Bad reward, invalid signature";
        case SCRIPT_ERR_BAD_REWARD_LIMIT:
            return "Bad reward, limit exceeded";
        case SCRIPT_ERR_UNKNOWN_ERROR:
        case SCRIPT_ERR_ERROR_COUNT:
        default: break;
    }
    return "unknown error";
}
