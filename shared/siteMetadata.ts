// Verified with the publishing service before this commercial-site update.
// This is the public site origin, not the workspace Preview URL.
export const PUBLIC_SITE_ORIGIN = 'https://mcp-authscan.replit.app';
export const BRAND_NAME = 'VATA';
export const HOME_DESCRIPTION = 'VATA is a hosted MCP security workspace for authorized scanning, organization-scoped findings and scan history. Independent MCP AuthScan assessments are available separately.';

export function metadataForPath(pathname: string) {
  const path = pathname.split(/[?#]/, 1)[0].replace(/\/+$/, '') || '/';
  if (path === '/assessments') {
    return {
      title: 'Independent MCP Security Assessments | MCP AuthScan',
      description: 'Evidence-backed independent MCP security verification: $1,750 for one authorized server or $3,500 for an expanded assessment with one remediation retest. Agreed scope and written permission required.',
      canonical: `${PUBLIC_SITE_ORIGIN}/assessments`,
      robots: 'index, follow',
    };
  }
  if (path === '/request-assessment') {
    return {
      title: 'Request an MCP Security Assessment | MCP AuthScan',
      description: 'Discuss an independent MCP security assessment with MCP AuthScan. Share your company, desired package and brief scope—not credentials. An inquiry does not authorize scanning.',
      canonical: `${PUBLIC_SITE_ORIGIN}/request-assessment`,
      robots: 'index, follow',
    };
  }
  if (path === '/sample-assessment') {
    return {
      title: 'Synthetic Sample Assessment | MCP AuthScan',
      description: 'An explicitly synthetic MCP security assessment example showing scope, illustrative evidence, limitations, remediation, and retest criteria. Not a customer engagement.',
      canonical: `${PUBLIC_SITE_ORIGIN}/sample-assessment`,
      robots: 'index, follow',
    };
  }
  const privatePage = [
    ['/sign-in', 'Sign in'],
    ['/sign-up', 'Create account'],
    ['/user-portal', 'Security workspace'],
    ['/join-team', 'Join your team'],
    ['/success', 'Workspace'],
    ['/cancel', 'Workspace'],
  ].find(([prefix]) => path === prefix || path.startsWith(`${prefix}/`));
  if (privatePage) {
    return {
      title: `${privatePage[1]} | VATA`,
      description: 'Access your organization-scoped VATA MCP security workspace.',
      canonical: `${PUBLIC_SITE_ORIGIN}${privatePage[0]}`,
      robots: 'noindex, follow',
    };
  }
  return {
    title: 'VATA | MCP Security Workspace',
    description: HOME_DESCRIPTION,
    canonical: `${PUBLIC_SITE_ORIGIN}/`,
    robots: 'index, follow',
  };
}

function escapeAttribute(value: string) {
  return value.replace(/[&<>"']/g, char => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  })[char]!);
}

// All values come from the route allowlist above, never a request host or query.
export function renderPageMetadata(html: string, pathname: string) {
  const meta = metadataForPath(pathname);
  return html
    .replace(/<title>[\s\S]*?<\/title>/i, `<title>${escapeAttribute(meta.title)}</title>`)
    .replace(/(<meta name="description" content=")[^"]*(")/i, (_, start, end) => `${start}${escapeAttribute(meta.description)}${end}`)
    .replace(/(<meta name="robots" content=")[^"]*(")/i, `$1${meta.robots}$2`)
    .replace(/(<link rel="canonical" href=")[^"]*(")/i, `$1${meta.canonical}$2`)
    .replace(/(<meta property="og:title" content=")[^"]*(")/i, `$1${escapeAttribute(meta.title)}$2`)
    .replace(/(<meta property="og:description" content=")[^"]*(")/i, (_, start, end) => `${start}${escapeAttribute(meta.description)}${end}`)
    .replace(/(<meta property="og:url" content=")[^"]*(")/i, `$1${meta.canonical}$2`)
    .replace(/(<meta name="twitter:title" content=")[^"]*(")/i, `$1${escapeAttribute(meta.title)}$2`)
    .replace(/(<meta name="twitter:description" content=")[^"]*(")/i, (_, start, end) => `${start}${escapeAttribute(meta.description)}${end}`);
}
