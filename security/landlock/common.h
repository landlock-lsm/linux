/*
 * Landlock LSM - private headers
 *
 * Copyright © 2017 Mickaël Salaün <mic@digikod.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#ifndef _SECURITY_LANDLOCK_COMMON_H
#define _SECURITY_LANDLOCK_COMMON_H

/**
 * get_index - get an index for the rules of struct landlock_events
 *
 * @event: a Landlock event type
 */
static inline int get_index(enum landlock_subtype_event event)
{
	/* event ID > 0 for loaded programs */
	return event - 1;
}

#endif /* _SECURITY_LANDLOCK_COMMON_H */
