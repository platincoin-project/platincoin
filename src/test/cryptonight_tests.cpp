#include <boost/test/unit_test.hpp>

#include "uint256.h"
#include "util.h"
#include "utilstrencodings.h"
#include "crypto/CryptoNight.h"

BOOST_AUTO_TEST_SUITE(cryptonight_tests)

BOOST_AUTO_TEST_CASE(cryptonight_hashtest)
{
    // Test Cryptonight hash with known inputs against expected outputs
    const char* input[] =
    {
        "",
        "This is a test",
        "Nonce: D",
        "Nonce: G",
        "Nonce: A",
        "Nonce: B",
    };
    const char* expected[] =
    {
        "117e38147b60200724528486f293fe6fc48967337bb5439afec6fa33a8e814eb",
        "0566bec0493625b3a9d8f5c5025810ae5435d4601b4085699ca037141df084a0",
        "99f50eb0c0e2409a1fa52c44305a5332023d18180380b776cf21943eca189924",
        "58c59fec73cedd273bd91ff4c95e2cac3d428711e281d469b944e23510596195",
        "5994c6621e6599d5aa49cb82e6479a5c78338a0866d72e5cc0b34464e4bcb10f",
        "55fa860af683c8fab74b1d60d8b48598a4b14d8e0006a83c72c13594c9af8ec0",
    };
    const size_t HASHCOUNT = (sizeof(input) / sizeof(input[0]));
    uint256 hash;
    std::vector<unsigned char> inputbytes;
    scratchpad_memory scratchpad;

    for (size_t i = 0; i < HASHCOUNT; i++)
    {
        scratchpad.hash(input[i], strlen(input[i]), &hash);
        BOOST_CHECK_EQUAL(hash.ToString().c_str(), expected[i]);
    }
}

BOOST_AUTO_TEST_SUITE_END()
