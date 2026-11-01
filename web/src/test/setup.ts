import { afterEach } from 'vitest'
import { forgetReads } from '../api/client'

// The api client shares a read still in flight with the same read asked for
// again; one a test left hanging must not answer the next test.
afterEach(() => forgetReads())
