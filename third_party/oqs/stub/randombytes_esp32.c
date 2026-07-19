/* ESP32 randombytes implementation using hardware RNG via ESP-IDF. */
#include <stddef.h>
#include <stdint.h>
#include "esp_random.h"

int randombytes(uint8_t *x, size_t xlen)
{
    esp_fill_random(x, xlen);
    return 0;
}
