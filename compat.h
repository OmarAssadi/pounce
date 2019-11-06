/* Copyright (C) 2019  C. McEnroe <june@causal.agency>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <stdint.h>
#include <stdlib.h>

// libcrypto defines these functions if libc doesn't.
void explicit_bzero(void *b, size_t len);
size_t strlcpy(char *restrict dst, const char *restrict src, size_t dstsize);
size_t strlcat(char *restrict dst, const char *restrict src, size_t dstsize);
uint32_t arc4random(void);
void arc4random_buf(void *buf, size_t nbytes);
uint32_t arc4random_uniform(uint32_t upper_bound);

// The default value of SO_RCVLOWAT is 1 anyway...
#ifndef SO_NOSIGPIPE
#define SO_NOSIGPIPE SO_RCVLOWAT
#endif

#ifndef SIGINFO
#define SIGINFO SIGUSR2
#endif
