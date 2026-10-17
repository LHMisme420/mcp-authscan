import DOMPurify from "dompurify"
export function render(req: any, el: HTMLElement) {
  el.innerHTML = DOMPurify.sanitize(req.query.name)   // sanitized -> silent
}
