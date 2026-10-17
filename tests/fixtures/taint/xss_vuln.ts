export function render(req: any, el: HTMLElement) {
  el.innerHTML = req.query.name   // T8-XSS
}
