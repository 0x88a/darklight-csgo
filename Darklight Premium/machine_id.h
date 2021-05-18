#pragma once

#include "common.h"

#include <IPTypes.h>
#include <iphlpapi.h>
#pragma comment (lib,"iphlpapi.lib")

namespace machineid {
	std::string machineHash();
}