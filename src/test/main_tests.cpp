// Copyright (c) 2014-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "validation.h"
#include "net.h"

#include "test/test_bitcoin.h"

#include <boost/signals2/signal.hpp>
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(main_tests, TestingSetup)

BOOST_AUTO_TEST_CASE(subsidy_limit_test)
{
    const Consensus::Params & consensusParams = Params(CBaseChainParams::MAIN).GetConsensus();
    CAmount nSum = 0;
    int nHeight = 1; // skip genesis block
    // countOfInitialAmountBlocks blocks = 56kk*COIN
    for (; nHeight <= consensusParams.countOfInitialAmountBlocks; ++nHeight) {
        CAmount nSubsidy = GetBlockSubsidy(nHeight, consensusParams);
        BOOST_CHECK(nSubsidy == 6000000 * COIN);
        nSum += nSubsidy;
        BOOST_CHECK(MoneyRange(nSubsidy));
    }

    BOOST_CHECK_EQUAL(nSum, 600000000LL*COIN);

    // next blocks - 0
    BOOST_CHECK(GetBlockSubsidy(101, consensusParams) == 0);
    BOOST_CHECK(GetBlockSubsidy(1001, consensusParams) == 0);
    BOOST_CHECK(GetBlockSubsidy(10001, consensusParams) == 0);
    BOOST_CHECK(GetBlockSubsidy(100001, consensusParams) == 0);
}

bool ReturnFalse() { return false; }
bool ReturnTrue() { return true; }

BOOST_AUTO_TEST_CASE(test_combiner_all)
{
    boost::signals2::signal<bool (), CombinerAll> Test;
    BOOST_CHECK(Test());
    Test.connect(&ReturnFalse);
    BOOST_CHECK(!Test());
    Test.connect(&ReturnTrue);
    BOOST_CHECK(!Test());
    Test.disconnect(&ReturnFalse);
    BOOST_CHECK(Test());
    Test.disconnect(&ReturnTrue);
    BOOST_CHECK(Test());
}
BOOST_AUTO_TEST_SUITE_END()
