#ifndef CHAINPARAMSCHECKPOINTSMAINNET_H
#define CHAINPARAMSCHECKPOINTSMAINNET_H

static std::pair<int, uint256> checkpointsMainnet[] = {
    {  330, uint256S("cbbc7c2b5b94c19bb3d56325ea5c98920fba163dc2fa5e80857ff46d39aa3a48")},
    {16208, uint256S("dd3ecab48df95bbd3a3c2d9e9d3487d2a0e8274e2e32e9229725fb970a6e412c")},
    {40320, uint256S("fe057ca6a22a2f4bb77d8848b5d3dcc346c956d8a76da6dee7ef45bdc96b5306")},
    {68544, uint256S("852b0cfc8b82243f46e347525b679343c566a40c31529c4122cef5da62910497")},
    {76608, uint256S("042fc1da1b23697f2794f3cdedd96e6921a6c7bb6fbed8b0c15fa5e05a239239")},
    {84672, uint256S("6bd79c2052536f6395864243b7647a9f87cdba54b6b66121e58ebe7ec31c513a")},
    {92736, uint256S("2c1db43581493e656550c77c62dc7435fc9bfd9acebc17da9d5301011e319b16")}
};

static std::pair<int, uint256> checkpointsTestnet[] = {
    {0, uint256S("6c940048f723be718cf0977046424cd7baea90f009463d436489f439225f19a0")}
};

static std::pair<int, uint256> checkpointsRegtest[] = {
    {0, uint256S("7f2a21c8712757b2ff75b9b60d5b7491b6b94dc38f4b8b4cdc8067f79713a45b")}
};

#endif // CHAINPARAMSCHECKPOINTSMAINNET_H
