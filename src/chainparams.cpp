// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "consensus/merkle.h"
#include "script/standard.h"

#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"
#include "base58.h"
#include "chainparamsseeds.h"

#include <assert.h>
#include <memory>

#include <boost/assign/list_of.hpp>

static CBlock CreateGenesisBlock(const char * pszTimestamp,
                                 const std::vector<CScript> & genesisOutputScripts,
                                 const uint32_t nTime,
                                 const uint32_t nNonce,
                                 const uint32_t nBits,
                                 const int32_t nVersion,
                                 const CAmount & genesisReward,
                                 const Consensus::Params & /*params*/)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;

    txNew.vin.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));

    for (const CScript & script : genesisOutputScripts)
    {
        txNew.vout.emplace_back(genesisReward, script);
    }

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        consensus.BIP34Height                    = 710000;
        consensus.BIP34Hash                      = uint256S("fa09d204a83a768ed5a7c8d441fa62f2043abf420cff1226c7b4329aeb9d51cf");
        consensus.BIP65Height                    = 918684; // bab3041e8977e0dc3eeff63fe707b92bde1dd449d8efafb248c27c8264cc311a
        consensus.BIP66Height                    = 811879; // 7aceee012833fa8952f8835d8b1b3ae233cd6ab08fdb27a771d2bd7bdc491894
        consensus.powLimit                       = uint256S("007fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan             = 2.1 * 24 * 60 * 60; // 3.5 days
        consensus.nPowTargetSpacing              = 1.5 * 60;
        consensus.fPowAllowMinDifficultyBlocks   = false;
        consensus.fPowNoRetargeting              = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% of 8064
        consensus.nMinerConfirmationWindow       = 2016; // nPowTargetTimespan / nPowTargetSpacing * 4

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1485561600; // January 28, 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1517356801; // January 31st, 2018

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1485561600; // January 28, 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1517356801; // January 31st, 2018

        // The best chain should have at least this much work.
        // consensus.nMinimumChainWork = uint256S("0x000000000000000000000000000000000000000000000006805c7318ce2736c0");
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x1673fa904a93848eca83d5ca82c7af974511a7e640e22edc2976420744f2e56a"); //1155631

        consensus.countOfInitialAmountBlocks = 100;
        consensus.countOfInitialAwardBlocks  = 100;
        consensus.awardGranularity           = 10*COIN;

        // fixed mining address
        // TODO update
        consensus.miningAddress = std::string("P4uXta1UHmvuQ3RZg7aeYSxvRmhQGNBtYKNs");

        // reward depth, in blocks. approximately 30 days
        consensus.rewardDepth = 4320;

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xfb;
        pchMessageStart[1] = 0xc0;
        pchMessageStart[2] = 0xb6;
        pchMessageStart[3] = 0xdb;

        nDefaultPort       = 9335;
        nPruneAfterHeight  = 100000;

        // Note that of those with the service bits flag, most only support a subset of possible options
        vSeeds.push_back(CDNSSeedData("bc00-a8.platincoin.info", "bc00-a8.platincoin.info"));
        vSeeds.push_back(CDNSSeedData("bc01-a8.platincoin.info", "bc00-a8.platincoin.info"));
        vSeeds.push_back(CDNSSeedData("bc02-a8.platincoin.info", "bc00-a8.platincoin.info"));

        base58Prefixes[PUBKEY_ADDRESS] = boost::assign::list_of(0x02)(0xD0)(0xA8).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[SCRIPT_ADDRESS] = boost::assign::list_of(0x02)(0xD0)(0xA9).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[SECRET_KEY]     = boost::assign::list_of(0x02)(0xD0)(0xB0).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >();

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers            = true;
        fDefaultConsistencyChecks       = false;
        fRequireStandard                = true;
        fMineBlocksOnDemand             = false;
        consensus.fSkipProofOfWorkCheck = false;

        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            (  330, uint256S("0xcbbc7c2b5b94c19bb3d56325ea5c98920fba163dc2fa5e80857ff46d39aa3a48"))
        };

        chainTxData = ChainTxData{
            // Data as of block b44bc5ae41d1be67227ba9ad875d7268aa86c965b1d64b47c35be6e8d5c352f4 (height 1155626).
            1487715936, // * UNIX timestamp of last known number of transactions
            9243806,  // * total number of transactions between genesis and that timestamp
                    //   (the tx=... number in the SetBestChain debug.log lines)
            0.06     // * estimated number of transactions per second after that timestamp
        };
    }

    void init()
    {
        const char * pszTimestamp = "01/Mar/2018 The Time Is Now!\n"
                                    "BTC 511430  0000000000000000005063cc99101e14d80826d638a18b5afdf568a46be79e89\n"
                                    "LTC 1377195 5b4f340767d71bd88d477c5e3f56c93a20e1dcc08731a6131dd7f0737fc75a5a";

        std::vector<CScript> scripts(10);
        scripts[0] << OP_RETURN << ParseHex("0325750caefa4ae0835342f504af720635f4a499e10aa3ee469d3f5e75fa27f4c5");
        scripts[1] << OP_RETURN << ParseHex("038e579f403222a5ba0f18f181d6e31b9ed9d194db3b59bd880b25b3ec1b5edde6");
        scripts[2] << OP_RETURN << ParseHex("0399c91dac350aa97e9b4dcfa1650839219264a9017d70de227075a72516176273");
        scripts[3] << OP_RETURN << ParseHex("0274671fd4ea0109308aca2817cf107afda6071e353b5f86043193c9c9088e6de5");
        scripts[4] << OP_RETURN << ParseHex("03228489db7836fca1e0cc487964ef280bec43a56456d4a1bceaebe0d86b09d28e");
        scripts[5] << OP_RETURN << ParseHex("03e1b4e1b2195f1dd593d5db7098225460eb8d0cb82959e4c00416131d0b49903f");
        scripts[6] << OP_RETURN << ParseHex("0317e363496844e7ee1e1faa65637311275ab832e133b78f827216fad0cdac64fe");
        scripts[7] << OP_RETURN << ParseHex("021aec6101ea0801d11659c57c10929b3e99b9246bd863ff3528a88fbb68db2781");
        scripts[8] << OP_RETURN << ParseHex("0364ba5affed3b4d499c0b377243366a3455089b7004471266a8e12e59a5868544");
        scripts[9] << OP_RETURN << ParseHex("0213b2afe2e6813b7bf0162e917bc2ba54f173648a72767610b1f3826207a10cb2");

        genesis = CreateGenesisBlock(pszTimestamp, scripts, 1519862400, 0x12d, 0x1f7fffff, 1, 1 * COIN, consensus);
        consensus.hashGenesisBlock = genesis.GetHash();

        assert(consensus.hashGenesisBlock == uint256S("4769e9264d0c9214e2bd1c741a22dad2bc099d989441dccc2a31a7a8dee2ac9c"));
        assert(genesis.hashMerkleRoot == uint256S("54390b89b55a7730af67355e881090b5dd6cf12d546c7b43b58448ba3427e551"));
    }
};

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.BIP34Height                    = 76;
        consensus.BIP34Hash                      = uint256S("8075c771ed8b495ffd943980a95f702ab34fce3c8c54e379548bda33cc8c0573");
        consensus.BIP65Height                    = 76; // 8075c771ed8b495ffd943980a95f702ab34fce3c8c54e379548bda33cc8c0573
        consensus.BIP66Height                    = 76; // 8075c771ed8b495ffd943980a95f702ab34fce3c8c54e379548bda33cc8c0573
        consensus.powLimit                       = uint256S("007fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan             = 2.1 * 24 * 60 * 60;
        consensus.nPowTargetSpacing              = 1.5 * 60;
        consensus.fPowAllowMinDifficultyBlocks   = true;
        consensus.fPowNoRetargeting              = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow       = 2016; // nPowTargetTimespan / nPowTargetSpacing

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1483228800; // January 1, 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1517356801; // January 31st, 2018

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1483228800; // January 1, 2017
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1517356801; // January 31st, 2018

        // The best chain should have at least this much work.
        // consensus.nMinimumChainWork = uint256S("0x000000000000000000000000000000000000000000000000000000054cb9e7a0");
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x43a16a626ef2ffdbe928f2bc26dcd5475c6a1a04f9542dfc6a0a88e5fcf9bd4c"); //8711

        consensus.countOfInitialAmountBlocks = 100;
        consensus.countOfInitialAwardBlocks  = 100;
        consensus.awardGranularity           = 10*COIN;

        // fixed mining address
        consensus.miningAddress = std::string("P4svYA536d6BYY9q7mUyDB2RLdBPEbNRTmrj");

        // reward depth, in blocks. approximately 30 hours
        consensus.rewardDepth = 180;

        pchMessageStart[0] = 0xfd;
        pchMessageStart[1] = 0xd2;
        pchMessageStart[2] = 0xc8;
        pchMessageStart[3] = 0xf1;

        nDefaultPort       = 19335;
        nPruneAfterHeight  = 1000;

        vFixedSeeds.clear();
        vSeeds.clear();

        // nodes with support for servicebits filtering should be at the top
        vSeeds.push_back(CDNSSeedData("testnet node 1", "node1.plc-test.com"));
        vSeeds.push_back(CDNSSeedData("testnet node 2", "node2.plc-test.com"));

        base58Prefixes[PUBKEY_ADDRESS] = boost::assign::list_of(0x02)(0xD0)(0xA4).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[SCRIPT_ADDRESS] = boost::assign::list_of(0x02)(0xD0)(0xA5).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[SECRET_KEY]     = boost::assign::list_of(0x02)(0xD0)(0xEF).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fMiningRequiresPeers            = false;
        fDefaultConsistencyChecks       = false;
        fRequireStandard                = false;
        fMineBlocksOnDemand             = false;
        consensus.fSkipProofOfWorkCheck = false;

//        checkpointData = (CCheckpointData) {
//            boost::assign::map_list_of
//            ( 2056, uint256S("0x17748a31ba97afdc9a4f86837a39d287e3e7c7290a08a1d816c5969c78a83289")),
//        };

        chainTxData = ChainTxData{
            1516631301,
            1238,
            0.011
        };
    }

    void init()
    {
        const char * pszTimestamp = "01/Mar/2018 testnet";

        std::vector<CScript> scripts(10);
        scripts[0] << OP_RETURN << ParseHex("020cdefcaee3e1ee1d7dae3de8d5db4b0a807323f2931afcf02d13a942aa8af2d0");
        scripts[1] << OP_RETURN << ParseHex("02566349286a2b6194add337db46b41d9e3e36b944ff54eb608ebe3bd6d69cf8c5");
        scripts[2] << OP_RETURN << ParseHex("0226af24a60efa18926aa654b9e342b573f71c0377d5087fb607095240b78850bb");
        scripts[3] << OP_RETURN << ParseHex("03f0becaa39bbe72b473cecd7150f2fa880bde9035d07fa05a5382be46e3bf7a66");
        scripts[4] << OP_RETURN << ParseHex("02edbaad1358a5b42e04685b7ea689c7551839b2896d75c3f820079e8252d2add6");
        scripts[5] << OP_RETURN << ParseHex("02cf9f1942ca5169c8f5ee0cddadca0e5958c5a08bc7ae8ada9880f8a95895c735");
        scripts[6] << OP_RETURN << ParseHex("030df6ecad559e4263e49e1cf20252b366997a21da98df030d9bbc699f868fe2ad");
        scripts[7] << OP_RETURN << ParseHex("03be34b942dddb1da429a19797b1baedd2f4d5764bf7ac009ebef2703d6d8774ba");
        scripts[8] << OP_RETURN << ParseHex("02177734e87e30491517e3f167aceb9fdff9398375414aaddc318795a7e26445a7");
        scripts[9] << OP_RETURN << ParseHex("0222c9c158806ab1e4bbf7b87fe01ad4ff7cada0fe7939984ef0741cd1b714c16d");

        genesis = CreateGenesisBlock(pszTimestamp, scripts, 1519862400, 0x3b6, 0x1f7fffff, 1, 1 * COIN, consensus);
        consensus.hashGenesisBlock = genesis.GetHash();

        assert(consensus.hashGenesisBlock == uint256S("6c940048f723be718cf0977046424cd7baea90f009463d436489f439225f19a0"));
        assert(genesis.hashMerkleRoot == uint256S("7579ad30ac4679e632683b3c4200817fad62bf4fd6983b653458913d34035fff"));
    }
};

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        consensus.BIP34Height                    = 100000000; // BIP34 has not activated on regtest (far in the future so block v1 are not rejected in tests)
        consensus.BIP34Hash                      = uint256();
        consensus.BIP65Height                    = 1351; // BIP65 activated on regtest (Used in rpc activation tests)
        consensus.BIP66Height                    = 1251; // BIP66 activated on regtest (Used in rpc activation tests)
        consensus.powLimit                       = uint256S("007fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan             = 2.1 * 24 * 60 * 60;
        consensus.nPowTargetSpacing              = 1.5 * 60;
        consensus.fPowAllowMinDifficultyBlocks   = true;
        consensus.fPowNoRetargeting              = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow       = 144; // Faster than normal for regtest (144 instead of 2016)

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 999999999999ULL;

        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 999999999999ULL;

        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 999999999999ULL;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        consensus.countOfInitialAmountBlocks = 100;
        consensus.countOfInitialAwardBlocks  = 100;
        consensus.awardGranularity           = 10*COIN;

        // fixed mining address
        consensus.miningAddress = std::string("P4svYA536d6BYY9q7mUyDB2RLdBPEbNRTmrj");

        // reward depth, in blocks. approximately 30 days
        consensus.rewardDepth = 4320;

        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda;

        nDefaultPort       = 19445;
        nPruneAfterHeight  = 1000;

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fMiningRequiresPeers            = false;
        fDefaultConsistencyChecks       = true;
        fRequireStandard                = false;
        fMineBlocksOnDemand             = true;
        consensus.fSkipProofOfWorkCheck = true;

        checkpointData = (CCheckpointData){
            boost::assign::map_list_of
            ( 0, uint256S("0x530827f38f93b43ed12af0b3ad25a288dc02ed74d6d7857862df51fc56c416f9"))
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        base58Prefixes[PUBKEY_ADDRESS] = boost::assign::list_of(0x02)(0xD0)(0xA4).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[SCRIPT_ADDRESS] = boost::assign::list_of(0x02)(0xD0)(0xA5).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[SECRET_KEY]     = boost::assign::list_of(0x02)(0xD0)(0xEF).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();
    }

    void init()
    {
        const char * pszTimestamp = "01/Mar/2018 regtest";

        std::vector<CScript> scripts(10);
        scripts[0] << OP_RETURN << ParseHex("020cdefcaee3e1ee1d7dae3de8d5db4b0a807323f2931afcf02d13a942aa8af2d0");
        scripts[1] << OP_RETURN << ParseHex("02566349286a2b6194add337db46b41d9e3e36b944ff54eb608ebe3bd6d69cf8c5");
        scripts[2] << OP_RETURN << ParseHex("0226af24a60efa18926aa654b9e342b573f71c0377d5087fb607095240b78850bb");
        scripts[3] << OP_RETURN << ParseHex("03f0becaa39bbe72b473cecd7150f2fa880bde9035d07fa05a5382be46e3bf7a66");
        scripts[4] << OP_RETURN << ParseHex("02edbaad1358a5b42e04685b7ea689c7551839b2896d75c3f820079e8252d2add6");
        scripts[5] << OP_RETURN << ParseHex("02cf9f1942ca5169c8f5ee0cddadca0e5958c5a08bc7ae8ada9880f8a95895c735");
        scripts[6] << OP_RETURN << ParseHex("030df6ecad559e4263e49e1cf20252b366997a21da98df030d9bbc699f868fe2ad");
        scripts[7] << OP_RETURN << ParseHex("03be34b942dddb1da429a19797b1baedd2f4d5764bf7ac009ebef2703d6d8774ba");
        scripts[8] << OP_RETURN << ParseHex("02177734e87e30491517e3f167aceb9fdff9398375414aaddc318795a7e26445a7");
        scripts[9] << OP_RETURN << ParseHex("0222c9c158806ab1e4bbf7b87fe01ad4ff7cada0fe7939984ef0741cd1b714c16d");

        genesis = CreateGenesisBlock(pszTimestamp, scripts, 1519862400, 0, 0x1f7fffff, 1, 1 * COIN, consensus);
        consensus.hashGenesisBlock = genesis.GetHash();

        assert(consensus.hashGenesisBlock == uint256S("7f2a21c8712757b2ff75b9b60d5b7491b6b94dc38f4b8b4cdc8067f79713a45b"));
        assert(genesis.hashMerkleRoot == uint256S("323a9cb94e222b22620c31e72b314fe2f73ba349a7e7ba57d0a651d8f16eba39"));
    }

    void UpdateBIP9Parameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
    {
        consensus.vDeployments[d].nStartTime = nStartTime;
        consensus.vDeployments[d].nTimeout = nTimeout;
    }
};

CChainParamsPtr mainParams;
CChainParamsPtr testNetParams;
CChainParamsPtr regTestParams;
CChainParamsPtr currentParams;

const CChainParams & Params()
{
    assert(currentParams);
    return *currentParams;
}

CChainParamsPtr ParamsPtr(const std::string & chain)
{
    if (chain == CBaseChainParams::MAIN)
    {
        if (!mainParams)
        {
            mainParams.reset(new CMainParams);
            mainParams->init();
        }
        return mainParams;
    }
    else if (chain == CBaseChainParams::TESTNET)
    {
        if (!testNetParams)
        {
            testNetParams.reset(new CTestNetParams);
            testNetParams->init();
        }
        return testNetParams;
    }
    else if (chain == CBaseChainParams::REGTEST)
    {
        if (!regTestParams)
        {
            regTestParams.reset(new CRegTestParams);
            regTestParams->init();
        }
        return regTestParams;
    }

    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

CChainParams & Params(const std::string & chain)
{
    return *ParamsPtr(chain);
}

void SelectParams(const std::string & network)
{
    SelectBaseParams(network);
    currentParams = ParamsPtr(network);
}

void UpdateRegtestBIP9Parameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    std::shared_ptr<CRegTestParams> regtestparams = std::dynamic_pointer_cast<CRegTestParams>(regTestParams);
    regtestparams->UpdateBIP9Parameters(d, nStartTime, nTimeout);
}
