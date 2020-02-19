//******************************************************************************
//******************************************************************************

#ifndef PLCVALIDATOR_H
#define PLCVALIDATOR_H

#include "plccertificate.h"
#include "uint256.h"
#include "amount.h"

#include <vector>
#include <memory>

namespace plc
{

//******************************************************************************
//******************************************************************************
class Validator
{
    class Impl;

public:
    // misk flags
    enum
    {
        hasDeviceKey      = 0x00000001,
        hasBeneficiaryKey = 0x00000002,
        hasExpirationDate = 0x00000004,
        hasMintingLimit   = 0x00000008,
        hasOtherData      = 0x00000800,
        fastMinting       = 0x00010000,
        generalFlags      = 0x00ff0000,
        localFlags        = 0x0000ffff,
        pubkeyCountMask   = 0x0000f000,
        requireCountMask  = 0xf0000000,
    };

    struct CertParameters
    {
        int64_t              percent;
        uint32_t             flags;
        std::vector<uint160> pubkeyHashes;
        uint32_t             requiredCountOfSigs;
        uint160              deviceKeyHash;
        uint160              beneficiaryKeyHash;
        unsigned int         blockTimestamp;
        unsigned int         expirationDate;
        CAmount              mintingLimit;
        CAmount              mintingCurrent;

        CertParameters()
            : percent(0)
            , flags(0)
            , requiredCountOfSigs(0)
            , blockTimestamp(0)
            , expirationDate(std::numeric_limits<unsigned int>::max())
            , mintingLimit(std::numeric_limits<CAmount>::max())
            , mintingCurrent(0)
        {}
    };

public:
    Validator();

public:
    // reqire cs_main!!!
    bool validateChainOfCerts(const std::vector<Certificate> & certs,
                              const std::vector<std::vector<unsigned char> > & pubkey,
                              CertParameters & params) const;

    bool getCertParams(const Certificate & cert,
                       CertParameters    & params) const;

    // verify signature
    bool verify(const uint256 & hash,
                const std::vector<unsigned char> & signature,
                const std::vector<unsigned char> & pubkey) const;

private:
    std::shared_ptr<Impl> m_p;
};

} // namespace plc

#endif // PLCVALIDATOR_H
