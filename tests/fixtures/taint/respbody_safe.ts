// Regression guard: a RESPONSE's .body is not a request source, and a fetch of a
// bare/non-request URL must not fire. (Caught an over-broad $R.body source that
// matched response.body and flagged even literal-URL fetches.)
export async function fetchIt(url: string) {
  const r = await fetch(url)
  return r.body
}
