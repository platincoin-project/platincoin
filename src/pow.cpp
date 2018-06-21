// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "pow.h"

#include "arith_uint256.h"
#include "chain.h"
#include "primitives/block.h"
#include "uint256.h"
#include "util.h"

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();

    // Genesis block
    if (pindexLast == NULL)
        return nProofOfWorkLimit;

    // Only change once per difficulty adjustment interval
    if ((pindexLast->nHeight+1) % params.DifficultyAdjustmentInterval() != 0)
    {
        if (params.fPowAllowMinDifficultyBlocks)
        {
            // Special difficulty rule for testnet:
            // If the new block's timestamp is more than 2* 10 minutes
            // then allow mining of a min-difficulty block.
            if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing*2)
                return nProofOfWorkLimit;
            else
            {
                // Return the last non-special-min-difficulty-rules-block
                const CBlockIndex* pindex = pindexLast;
                while (pindex->pprev && pindex->nHeight % params.DifficultyAdjustmentInterval() != 0 && pindex->nBits == nProofOfWorkLimit)
                    pindex = pindex->pprev;
                return pindex->nBits;
            }
        }
        return pindexLast->nBits;
    }

    // Go back by what we want to be 14 days worth of blocks
    // Platincoin: This fixes an issue where a 51% attack can change difficulty at will.
    // Go back the full period unless it's the first retarget after genesis. Code courtesy of Art Forz
    int blockstogoback = params.DifficultyAdjustmentInterval()-1;
    if ((pindexLast->nHeight+1) != params.DifficultyAdjustmentInterval())
        blockstogoback = params.DifficultyAdjustmentInterval();

    // Go back by what we want to be 14 days worth of blocks
    const CBlockIndex* pindexFirst = pindexLast;
    for (int i = 0; pindexFirst && i < blockstogoback; i++)
        pindexFirst = pindexFirst->pprev;

    assert(pindexFirst);

    return CalculateNextWorkRequired(pindexLast, pindexFirst->GetBlockTime(), params);
}

constexpr int bits(uint32_t value)
{
  return
    (value >= 0x00000001) +
    (value >= 0x00000002) +
    (value >= 0x00000004) +
    (value >= 0x00000008) +
    (value >= 0x00000010) +
    (value >= 0x00000020) +
    (value >= 0x00000040) +
    (value >= 0x00000080) +
    (value >= 0x00000100) +
    (value >= 0x00000200) +
    (value >= 0x00000400) +
    (value >= 0x00000800) +
    (value >= 0x00001000) +
    (value >= 0x00002000) +
    (value >= 0x00004000) +
    (value >= 0x00008000) +
    (value >= 0x00010000) +
    (value >= 0x00020000) +
    (value >= 0x00040000) +
    (value >= 0x00080000) +
    (value >= 0x00100000) +
    (value >= 0x00200000) +
    (value >= 0x00400000) +
    (value >= 0x00800000) +
    (value >= 0x01000000) +
    (value >= 0x02000000) +
    (value >= 0x04000000) +
    (value >= 0x08000000) +
    (value >= 0x10000000) +
    (value >= 0x20000000) +
    (value >= 0x40000000) +
    (value >= 0x80000000);
}

unsigned int CalculateNextWorkRequired(const CBlockIndex * pindexLast,
                                       int64_t nFirstBlockTime,
                                       const Consensus::Params & params)
{
    if (params.fPowNoRetargeting)
    {
        return pindexLast->nBits;
    }

    // Limit adjustment step
    int64_t nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime;
    if (nActualTimespan < params.nPowTargetTimespan/4)
    {
        nActualTimespan = params.nPowTargetTimespan/4;
    }
    if (nActualTimespan > params.nPowTargetTimespan*4)
    {
        nActualTimespan = params.nPowTargetTimespan*4;
    }

    // Retarget
    arith_uint256 bnNew;
    arith_uint256 bnOld;
    bnNew.SetCompact(pindexLast->nBits);
    bnOld = bnNew;

    int len1 = 255 - bnNew.bits();
    int len2 = bits(nActualTimespan);

    int reserve = (len2 > len1) * (len2 - len1);

    bnNew >>= reserve;
    bnNew *= nActualTimespan;
    bnNew /= params.nPowTargetTimespan;

    int len3 = 255 - bnNew.bits();

    bnNew <<= reserve;

    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    if (bnNew > bnPowLimit || len3 < reserve)
    {
        bnNew = bnPowLimit;
    }

    // debug print
    LogPrintf("GetNextWorkRequired RETARGET\n");
    LogPrintf("params.nPowTargetTimespan = %d    nActualTimespan = %d\n", params.nPowTargetTimespan, nActualTimespan);
    LogPrintf("Before: %08x  %s\n", pindexLast->nBits, bnOld.ToString());
    LogPrintf("After:  %08x  %s\n", bnNew.GetCompact(), bnNew.ToString());

    return bnNew.GetCompact();
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    if (params.fSkipProofOfWorkCheck)
    {
       return true;
    }

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit))
        return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}
