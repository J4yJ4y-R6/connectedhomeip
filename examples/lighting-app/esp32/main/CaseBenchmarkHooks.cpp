// CASE handshake benchmark instrumentation for the accessory (CASE responder)
// side. Bracket the responder's Sigma1-3 handshake with the same GPIO
// DONE/BUSY signaling and MEASURE_* serial protocol used by measure-esp's
// raw-crypto benchmarks, so measure/measure.py and measure-analysis can be
// reused unchanged. Compiles to an empty translation unit unless
// CHIP_CASE_BENCHMARK is set (see matter/examples/lighting-app/esp32/CMakeLists.txt).
#if CHIP_CASE_BENCHMARK

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_heap_caps.h"
#include "esp_system.h"
#include "esp_timer.h"

#include "measure_trigger.h"

// Generous headroom over the lighting-app's actual task count; verified at
// runtime via uxArraySize (logged in MEASURE_CPU's task_count field).
#define CASE_BENCHMARK_MAX_TASKS 24

namespace {

int64_t sSigma1StartUs;
size_t sHeapFreeBefore;
// Heap-allocated per run: a static array costs ~860 B of .dram0.bss, and the
// ESP32 lighting-app is within ~30 B of the static DRAM limit.
TaskStatus_t * sTasksBefore;
UBaseType_t sTaskCountBefore;

bool IsIdleTask(const char * name)
{
    return strncmp(name, "IDLE", 4) == 0;
}

} // namespace

extern "C" void MatterCaseBenchmarkOnResponderSigma1Start(void)
{
    measure_done_busy();

    // Allocate before the heap snapshot so it cancels out of before/after.
    sTasksBefore = static_cast<TaskStatus_t *>(malloc(sizeof(TaskStatus_t) * CASE_BENCHMARK_MAX_TASKS));

    sSigma1StartUs  = esp_timer_get_time();
    sHeapFreeBefore = esp_get_free_heap_size();

    sTaskCountBefore = 0;
    if (sTasksBefore != nullptr)
    {
        uint32_t totalRunTime;
        sTaskCountBefore = uxTaskGetSystemState(sTasksBefore, CASE_BENCHMARK_MAX_TASKS, &totalRunTime);
    }
}

extern "C" void MatterCaseBenchmarkOnResponderSessionEstablished(void)
{
    int64_t doneUs = esp_timer_get_time();
    measure_done_complete();

    size_t heapFreeAfter   = esp_get_free_heap_size();
    size_t heapLargestFree = heap_caps_get_largest_free_block(MALLOC_CAP_8BIT);
    size_t heapMinFree     = esp_get_minimum_free_heap_size();
    size_t mainStackFree   = (size_t) uxTaskGetStackHighWaterMark(nullptr) * sizeof(StackType_t);

    TaskStatus_t tasksAfter[CASE_BENCHMARK_MAX_TASKS];
    uint32_t totalRunTimeAfter;
    UBaseType_t taskCountAfter = uxTaskGetSystemState(tasksAfter, CASE_BENCHMARK_MAX_TASKS, &totalRunTimeAfter);

    uint32_t totalRuntimeDelta = 0;
    uint32_t idleRuntimeDelta  = 0;
    for (UBaseType_t i = 0; i < taskCountAfter; i++)
    {
        for (UBaseType_t j = 0; j < sTaskCountBefore; j++)
        {
            if (tasksAfter[i].xHandle != sTasksBefore[j].xHandle)
            {
                continue;
            }
            uint32_t delta = tasksAfter[i].ulRunTimeCounter - sTasksBefore[j].ulRunTimeCounter;
            totalRuntimeDelta += delta;
            if (IsIdleTask(tasksAfter[i].pcTaskName))
            {
                idleRuntimeDelta += delta;
            }
            break;
        }
    }

    free(sTasksBefore);
    sTasksBefore = nullptr;

    unsigned busyPct = 0;
    if (totalRuntimeDelta > 0)
    {
        busyPct = 100 - (idleRuntimeDelta * 100 / totalRuntimeDelta);
    }

#if CHIP_CRYPTO_PQC_DILITHIUM
    const char * parameter = "PQC-Kyber768-Dilithium3";
    int kyberK              = 768;
#elif CHIP_CRYPTO_PQC
    const char * parameter = "PQC-Kyber768";
    int kyberK              = 768;
#else
    const char * parameter = "Classical-P256";
    int kyberK              = 0;
#endif

    measure_printf("MEASURE_META algorithm=MATTER_CASE parameter=%s k=%d\n", parameter, kyberK);
    measure_printf("MEASURE_TIME start_us=%lld end_us=%lld duration_us=%lld\n",
           (long long) sSigma1StartUs,
           (long long) doneUs,
           (long long) (doneUs - sSigma1StartUs));
    measure_printf("MEASURE_RAM heap_free_before=%lu heap_free_after=%lu heap_used_after=%lu heap_largest_free=%lu heap_min_free=%lu main_stack_free=%lu\n",
           (unsigned long) sHeapFreeBefore,
           (unsigned long) heapFreeAfter,
           (unsigned long) (heap_caps_get_total_size(MALLOC_CAP_8BIT) - heapFreeAfter),
           (unsigned long) heapLargestFree,
           (unsigned long) heapMinFree,
           (unsigned long) mainStackFree);
    measure_printf("MEASURE_CPU window_us=%lld total_runtime_delta=%lu idle_runtime_delta=%lu busy_pct=%u task_count=%lu\n",
           (long long) (doneUs - sSigma1StartUs),
           (unsigned long) totalRuntimeDelta,
           (unsigned long) idleRuntimeDelta,
           busyPct,
           (unsigned long) taskCountAfter);
}

#endif // CHIP_CASE_BENCHMARK
