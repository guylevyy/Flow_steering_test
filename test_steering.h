#ifndef STEERING_H
#define STEERING_H

#include <stdbool.h>

int test_steering_control_path(struct resources_t *resource,
			       uint8_t num_matchers,
			       bool is_dup_rule);
int test_steering_data_path(struct resources_t *resource);
int destroy_steering_test(struct resources_t *resource);

#endif /* STEERING_H */
