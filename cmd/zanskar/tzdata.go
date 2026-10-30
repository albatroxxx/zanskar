// SPDX-License-Identifier: Apache-2.0

package main

// The time zone database, in the binary: the console's time zone setting
// (display.time_zone) must load any zone on a host or image that ships
// none. About 450 KB.
import _ "time/tzdata"
