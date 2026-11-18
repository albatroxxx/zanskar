// A cloud account's role as the console names it (ADR 0050); shared by the
// section, the drawer and the setup modal, apart from the components so fast
// refresh keeps working on them.

/** roleName is the role's own name: the last segment of its ARN. */
export function roleName(arn?: string | null): string {
  if (!arn) return ''
  const i = arn.lastIndexOf('/')
  return i < 0 ? arn : arn.slice(i + 1)
}

/** accountLabel reads "alias · id", or the id alone. */
export function accountLabel(t: { cloud_account_alias?: string; cloud_account_id?: string }): string {
  const id = t.cloud_account_id ?? ''
  return t.cloud_account_alias ? `${t.cloud_account_alias} · ${id}` : id
}
