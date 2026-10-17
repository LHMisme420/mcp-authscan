import _ from "lodash"
export function handler(req: any) {
  const cfg: any = {}
  _.merge(cfg, req.body)   // deep-merge of untrusted object -> T11-PROTO
  return cfg
}
