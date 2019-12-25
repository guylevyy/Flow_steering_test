#ifndef MAIN_H
#define MAIN_H

#include "types.h"

int send_info(const struct resources_t *resource, const void *buf, size_t size);
int recv_info(const struct resources_t *resource, void *buf, size_t size);
int init_socket(struct resources_t *resource);

#endif /* MAIN_H */
