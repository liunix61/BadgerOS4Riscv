
// SPDX-License-Identifier: MIT

#pragma once

#include "log.h"
#include "panic.h"



#define TODO()                                                                                                         \
    ({                                                                                                                 \
        logkf(LOG_FATAL, "TODO in function %{cs} at %{cs}:%{d}", __FUNCTION__, __FILE_NAME__, __LINE__);               \
        panic_abort();                                                                                                 \
        __builtin_unreachable();                                                                                       \
    })
