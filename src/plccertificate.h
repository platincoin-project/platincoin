//******************************************************************************
//******************************************************************************

#ifndef PLCCERTIFICATE_H
#define PLCCERTIFICATE_H

#include "uint256.h"

#include <stdint.h>
#include <vector>

//******************************************************************************
//******************************************************************************
namespace plc
{

enum
{
    privateKeySize  = 32,
    publicKeySize   = 33,
    signatureSize   = 64
};

//******************************************************************************
//******************************************************************************
struct Certificate
{
    uint256  txid;
    uint32_t vout;
    uint32_t height;

    Certificate()
        : vout(0)
        , height(0)
    {
    }

    Certificate(const uint256 & _txid, const uint32_t & _vout)
        : txid(_txid)
        , vout(_vout)
        , height(0)
    {
    }
};

} // namespace plc

#endif // PLCCERTIFICATE_H
