/* SPDX-License-Identifier: GPL-2.0 */
#ifndef MARCH_POLICY_H
#define MARCH_POLICY_H

/* Inputs are sanitized by the caller: CPU0 must stay online. */
struct march_limits {
	unsigned int min[2];
	unsigned int max[2];
	unsigned int total_min;
	unsigned int total_max;
};

static inline void march_resolve_targets(unsigned int target[2],
		const struct march_limits *limits)
{
	unsigned int i, floor[2];

	for (i = 0; i < 2; i++) {
		floor[i] = limits->min[i] < limits->max[i] ?
			limits->min[i] : limits->max[i];
		if (target[i] < floor[i])
			target[i] = floor[i];
		if (target[i] > limits->max[i])
			target[i] = limits->max[i];
	}
	/* Shed demand above the per-cluster floors before resolving conflicts. */
	while (target[0] + target[1] > limits->total_max) {
		if (target[1] > floor[1])
			target[1]--;
		else if (target[0] > floor[0])
			target[0]--;
		else if (target[1])
			target[1]--;
		else if (target[0] > 1)
			target[0]--;
		else
			break;
	}
	while (target[0] + target[1] < limits->total_min &&
	       target[0] + target[1] < limits->total_max) {
		if (target[0] < limits->max[0])
			target[0]++;
		else if (target[1] < limits->max[1])
			target[1]++;
		else
			break;
	}
}
#endif
