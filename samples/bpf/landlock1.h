/*
 * Landlock sample 1 - common header
 *
 * Copyright © 2018 Mickaël Salaün <mic@digikod.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 */

#define MAP_MARK_READ		(1ULL << 63)
#define MAP_MARK_WRITE		(1ULL << 62)
#define COOKIE_VALUE_FREEZED	(1ULL << 61)
#define _MAP_MARK_MASK		(MAP_MARK_READ | MAP_MARK_WRITE | COOKIE_VALUE_FREEZED)
