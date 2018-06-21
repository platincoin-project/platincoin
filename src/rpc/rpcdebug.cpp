//******************************************************************************
//******************************************************************************

#include "rpc/rpcserver.h"
#include "utilstrencodings.h"
#include "primitives/block.h"
#include "validation.h"
#include "chainparams.h"
#include "primitives/transaction.h"
#include "base58.h"
#include "core_io.h"
#include "utilstrencodings.h"

#include <exception>

#include <boost/assign/list_of.hpp>


//******************************************************************************
//******************************************************************************
static const CRPCCommand commands[] =
{ //  category              name                      actor (function)         okSafeMode
  //  --------------------- ------------------------  -----------------------  ----------
};

//******************************************************************************
//******************************************************************************
void RegisterDebugRPCCommands(CRPCTable &t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
    {
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
    }
}
