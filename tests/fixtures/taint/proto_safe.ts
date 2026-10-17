import _ from "lodash"
export function handler() {
  const cfg: any = {}
  _.merge(cfg, { a: 1 })   // literal -> silent
  return cfg
}
