//******************************************************************************
//******************************************************************************

#include "plcvalidator.h"
#include "pubkey.h"
#include "validation.h"
#include "streams.h"
#include "script/standard.h"
#include "base58.h"
#include "util.h"

#include <algorithm>

#include <boost/range/adaptor/reversed.hpp>

namespace plc
{

//******************************************************************************
//******************************************************************************
class Validator::Impl
{
    friend class Validator;

protected:
    // return block timestamp
    // reqire cs_main!!!
    unsigned int getBlockTimestamp(const int & blockNo) const;

    // reqire cs_main!!!
    // see getBlockTimestamp
    bool verifyCert(const Certificate          & cert,
                    std::vector<std::vector<unsigned char> > & pubkeysOrHash,
                    CertParameters             & params) const;

    bool getCertParams(const Certificate & cert,
                       CertParameters    & params) const;
};

//******************************************************************************
// reqire cs_main!!!
//******************************************************************************
unsigned int Validator::Impl::getBlockTimestamp(const int & blockNo) const
{
    if (blockNo < 0 || blockNo > chainActive.Height())
    {
        // block not found???
        return 0;
    }

    CBlockIndex * index = chainActive[blockNo];
    if (!index)
    {
        return 0;
    }

    return index->nTime;
}

//******************************************************************************
// reqire cs_main!!!
//******************************************************************************
bool Validator::Impl::verifyCert(const Certificate & cert,
                                 std::vector<std::vector<unsigned char> > & pubkeysOrHash,
                                 CertParameters & params) const
{
    if (pubkeysOrHash.size() == 0)
    {
        LogPrintf("%s: no pubkeys\n", __func__);
        return false;
    }

    params.percent = 0;

    const CCoins * coins = pcoinsTip->AccessCoins(cert.txid);
    if (!coins || !coins->IsAvailable(cert.vout))
    {
        // txout is spent
        LogPrintf("Cert tx out is spent <%s> <%s>\n", cert.txid.ToString(), __func__);
        return false;
    }

    const CTxOut & out = coins->vout[cert.vout];

    opcodetype op;
    std::vector<unsigned char> data;
    CScript::const_iterator pc = out.scriptPubKey.begin();
    if (!out.scriptPubKey.GetOp(pc, op, data))
    {
        LogPrintf("GetOp failed <%s>\n", __func__);
        return false;
    }

    uint256  streamHash;

    try
    {
        CDataStream stream(data, SER_NETWORK, 0);
        streamHash = Hash(stream.begin(), stream.end());

        stream >> params.flags;
        uint32_t countOfKeys = (params.flags & pubkeyCountMask) >> 12;
        if (countOfKeys == 0)
        {
            // 0 interpreted as single key
            countOfKeys = 1;
        }
        for (size_t i = 0; i < countOfKeys; ++i)
        {
            params.pubkeyHashes.emplace_back(uint160());
            stream >> params.pubkeyHashes.back();
        }

        params.requiredCountOfSigs = (params.flags & requireCountMask) >> 28;
        if (params.requiredCountOfSigs == 0)
        {
            // require all
            params.requiredCountOfSigs = countOfKeys;
            if (params.requiredCountOfSigs < pubkeysOrHash.size())
            {
                LogPrintf("%s: Invalid count of keys specified, need %d vs %d\n",
                          __func__, params.requiredCountOfSigs, pubkeysOrHash.size());
                return false;
            }
        }

        if (params.flags & hasDeviceKey)
        {
            stream >> params.deviceKeyHash;
        }
        if (params.flags & hasBeneficiaryKey)
        {
            stream >> params.beneficiaryKeyHash;
        }
        if (params.flags & hasExpirationDate)
        {
            stream >> params.expirationDate;
        }
        if (params.flags & hasMintingLimit)
        {
            stream >> params.mintingLimit;
        }
    }
    catch (const std::exception & e)
    {
        LogPrintf("Exception <%s> <%s>\n", e.what(), __func__);
        return false;
    }

    std::set<uint160> toSearch;
    std::copy(params.pubkeyHashes.begin(), params.pubkeyHashes.end(), std::inserter(toSearch, toSearch.end()));

    for (uint32_t i = 0; i < pubkeysOrHash.size(); ++i)
    {
        const std::vector<unsigned char> & pubkeyOrHash = pubkeysOrHash[i];
        // check pubkey or hash
        uint160 hash;
        if (pubkeysOrHash[i].size() == sizeof(uint160))
        {
            // this is hash of key
            hash = uint160(pubkeysOrHash[i]);
        }
        else
        {
            // this is a full publick key
            hash = Hash160(pubkeyOrHash.begin(),
                           pubkeyOrHash.begin() + pubkeyOrHash.size());
        }

        if (toSearch.count(hash) == 0)
        {
            LogPrintf("%s: specified key not found in certificate: <%s>\n", __func__, hash.ToString());
            return false;
        }
    }

    // get signature
    std::vector<unsigned char> signature;
    if (!out.scriptPubKey.GetOp(pc, op, signature))
    {
        LogPrintf("GetOp failed (get signature error) <%s>\n", __func__);
        return false;
    }

    // skip all from begin to OP_2DROP
    for (; out.scriptPubKey.GetOp(pc, op) && op != OP_2DROP; );
    if (pc == out.scriptPubKey.end() || op != OP_2DROP)
    {
        // bad script?
        LogPrintf("Incorrect script <%s>\n", __func__);
        return false;
    }

    CScript copy;
    std::copy(pc, out.scriptPubKey.end(), std::back_inserter(copy));

    // extract up adress or public key
    CTxDestination dest;
    if (!ExtractDestination(copy, dest))
    {
        LogPrintf("Destination not extracted <%s>\n", __func__);
        return false;
    }

    CKeyID * keyid = boost::get<CKeyID>(&dest);
    if (!keyid)
    {
        LogPrintf("Invalid destination <%s>\n", __func__);
        return false;
    }

    // recover pubkey from signature
    CPubKey recoveredPubKey;
    if (!recoveredPubKey.RecoverCompact(streamHash, signature))
    {
        LogPrintf("Pubkey recovery error <%s>\n", __func__);
        return false;
    }

    // check pubkey
    if (recoveredPubKey.GetID() != *keyid)
    {
        // wrong signature
        LogPrintf("Wrong signature <%s>\n", __func__);
        return false;
    }

    pubkeysOrHash.resize(1);
    pubkeysOrHash.front().resize(keyid->size());
    std::copy(keyid->begin(), keyid->end(), pubkeysOrHash.front().begin());

    // block age
    params.blockTimestamp = getBlockTimestamp(coins->nHeight);

    // amount (percent)
    params.percent = out.nValue;

    if (params.flags & hasMintingLimit)
    {
        // minting limits
        uint32_t version   = 0;
        uint32_t timestamp = 0;
        CAmount  amount    = 0;
        if (coins->getMintedAmount(cert.vout, version, timestamp, amount))
        {
            params.mintingCurrent = amount;
        }
    }

    return true;
}

//******************************************************************************
// reqire cs_main!!!
// copied from fn above
//******************************************************************************
bool Validator::Impl::getCertParams(const Certificate & cert,
                                    CertParameters    & params) const
{
    const CCoins * coins = pcoinsTip->AccessCoins(cert.txid);
    if (!coins || !coins->IsAvailable(cert.vout))
    {
        // txout is spent
        LogPrintf("Cert tx out is spent <%s> <%s>\n", cert.txid.ToString(), __func__);
        return false;
    }

    const CTxOut & out = coins->vout[cert.vout];

    opcodetype op;
    std::vector<unsigned char> data;
    CScript::const_iterator pc = out.scriptPubKey.begin();
    if (!out.scriptPubKey.GetOp(pc, op, data))
    {
        LogPrintf("GetOp failed <%s>\n", __func__);
        return false;
    }

    uint256  streamHash;

    try
    {
        CDataStream stream(data, SER_NETWORK, 0);
        streamHash = Hash(stream.begin(), stream.end());

        stream >> params.flags;
        uint32_t countOfKeys = (params.flags & pubkeyCountMask) >> 12;
        if (countOfKeys == 0)
        {
            // 0 interpreted as single key
            countOfKeys = 1;
        }
        for (size_t i = 0; i < countOfKeys; ++i)
        {
            params.pubkeyHashes.emplace_back(uint160());
            stream >> params.pubkeyHashes.back();
        }

        params.requiredCountOfSigs = (params.flags & requireCountMask) >> 28;
        if (params.requiredCountOfSigs == 0)
        {
            // require all
            params.requiredCountOfSigs = countOfKeys;
        }

        if (params.flags & hasDeviceKey)
        {
            stream >> params.deviceKeyHash;
        }
        if (params.flags & hasBeneficiaryKey)
        {
            stream >> params.beneficiaryKeyHash;
        }
        if (params.flags & hasExpirationDate)
        {
            stream >> params.expirationDate;
        }
        if (params.flags & hasMintingLimit)
        {
            stream >> params.mintingLimit;
        }
    }
    catch (const std::exception & e)
    {
        LogPrintf("Exception <%s> <%s>\n", e.what(), __func__);
        return false;
    }

    return true;
}

//******************************************************************************
//******************************************************************************
Validator::Validator()
    : m_p(new Impl)
{

}

//******************************************************************************
// reqire cs_main!!!
//******************************************************************************
bool Validator::validateChainOfCerts(const std::vector<Certificate>                 & certs,
                                     const std::vector<std::vector<unsigned char> > & pubkeys,
                                     CertParameters                                 & params) const
{
    assert(certs.size() == 2 && "wrong size, need review");
    CertParameters paramsInternal[2];

    std::vector<std::vector<unsigned char> > pubkeysOrHashUp = pubkeys;

    int64_t amount = std::numeric_limits<int64_t>::max();
    for (size_t i = certs.size(); i > 0; --i)
    {
        size_t idx = i-1;
        const Certificate & cert = certs[idx];
        if (!m_p->verifyCert(cert, pubkeysOrHashUp, paramsInternal[idx]))
        {
            LogPrintf("%s: Invalid certificate <%s:%d>\n", __func__, cert.txid.ToString(), cert.vout);
            return false;
        }
        amount = std::min(amount, paramsInternal[idx].percent);
        if (amount == 0)
        {
            LogPrintf("%s: Zero percent for reward <%s:%d>\n", __func__, cert.txid.ToString(), cert.vout);
            return false;
        }
    }

    // at this point pubkeyOrHashUp must be eq one of pubkeys from coinbase
    // temporary used only first key
    const CScript & tmp = Params().GenesisBlock().vtx[0]->vout[0].scriptPubKey;

    opcodetype op;
    std::vector<unsigned char> data;
    CScript::const_iterator pc = tmp.begin();
    if (!tmp.GetOp(pc, op, data) || op != OP_RETURN)
    {
        LogPrintf("GetOp failed or OP_RETURN <%s>\n", __func__);
        return false;
    }
    if (!tmp.GetOp(pc, op, data))
    {
        LogPrintf("GetOp failed <%s>\n", __func__);
        return false;
    }

    if (pubkeysOrHashUp.front().size() != sizeof(uint160))
    {
        assert(!"wrong size");
        return false;
    }

    // check pubkey hash
    uint160 hash = Hash160(data.begin(), data.begin() + data.size());
    if (!std::equal(hash.begin(), hash.end(), pubkeysOrHashUp.front().begin()))
    // eif (hash != pubkeyOrHashUp)
    {
        LogPrintf("Pubkey hash not eq <%s>\n", __func__);
        return false;
    }

    params.percent = amount;

    // timestamp from last cert
    params.blockTimestamp     = paramsInternal[certs.size()-1].blockTimestamp;

    // endpoint, beneficiary and device from last cert
    params.requiredCountOfSigs = paramsInternal[certs.size()-1].requiredCountOfSigs;
    params.pubkeyHashes        = paramsInternal[certs.size()-1].pubkeyHashes;
    params.beneficiaryKeyHash  = paramsInternal[certs.size()-1].beneficiaryKeyHash;
    params.deviceKeyHash       = paramsInternal[certs.size()-1].deviceKeyHash;
    params.expirationDate      = paramsInternal[certs.size()-1].expirationDate;
    params.mintingLimit        = paramsInternal[certs.size()-1].mintingLimit;
    params.mintingCurrent      = paramsInternal[certs.size()-1].mintingCurrent;

    // flags from first
    params.flags               = paramsInternal[0].flags & generalFlags;

    if (params.deviceKeyHash.IsNull())
    {
        LogPrintf("%s: No device h(key) found\n", __func__);
        return false;
    }
    return true;
}

//******************************************************************************
// reqire cs_main!!!
//******************************************************************************
bool Validator::getCertParams(const Certificate & cert,
                              CertParameters    & params) const
{
    return m_p->getCertParams(cert, params);
}

//******************************************************************************
//******************************************************************************
bool Validator::verify(const uint256 & hash,
                 const std::vector<unsigned char> & signature,
                 const std::vector<unsigned char> & pubkey) const
{
    CPubKey pub(pubkey);
    return pub.Verify(hash, signature);
}

} // namespace plc
