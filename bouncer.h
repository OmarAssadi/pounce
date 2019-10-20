/* Copyright (C) 2019  C. McEnroe <june@causal.agency>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include <tls.h>

#ifndef DEFAULT_CERT_PATH
#define DEFAULT_CERT_PATH "/usr/local/etc/letsencrypt/live/%s/fullchain.pem"
#endif

#ifndef DEFAULT_PRIV_PATH
#define DEFAULT_PRIV_PATH "/usr/local/etc/letsencrypt/live/%s/privkey.pem"
#endif

void listenConfig(const char *cert, const char *priv);
size_t listenBind(int fds[], size_t cap, const char *host, const char *port);
int listenAccept(struct tls **client, int fd);
