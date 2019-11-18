#ifndef RESOURCE_H
#define RESOURCE_H

#include "types.h"

int alloc_resources(struct resources_t *resource);
int init_resources(struct resources_t *resource);
int destroy_resources(struct resources_t *resource);
int init_qps(struct resources_t *resource);

#endif /* RESOURCE_H */
