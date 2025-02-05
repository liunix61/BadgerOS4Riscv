
// SPDX-License-Identifier: MIT

#include <stdint.h>

// Output a byte to an I/O port
__attribute__((always_inline)) static inline void outb(uint16_t port, uint8_t value) {
    asm volatile("out dx, al" : : "d"(port), "a"(value));
}

// Input a byte from an I/O port
__attribute__((always_inline)) static inline uint8_t inb(uint16_t port) {
    uint8_t value;
    asm volatile("in al, dx" : "=a"(value) : "d"(port));
    return value;
}
