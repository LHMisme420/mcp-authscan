import { emailPattern } from './assessmentInquiry';

export type ScopeRequest = {
  endpoint: string; name: string; email: string; authority: string; buyerNeeds: string;
};

export function validateScopeRequest(input: unknown) {
  const data = input && typeof input === 'object' && !Array.isArray(input)
    ? input as Record<string, unknown> : {};
  const errors: Record<string, string> = {};
  const text = (key: string, max: number, required = true) => {
    const value = typeof data[key] === 'string' ? (data[key] as string).trim() : '';
    if ((required && !value) || value.length > max || /[\u0000-\u001f\u007f]/.test(value)) {
      errors[key] = `Enter ${required ? '1' : '0'}–${max} characters on one line.`;
    }
    return value;
  };
  const value: ScopeRequest = {
    endpoint: text('endpoint', 2000), name: text('name', 100),
    email: text('email', 254), authority: text('authority', 2000),
    buyerNeeds: text('buyerNeeds', 2000, false),
  };
  if (!emailPattern.test(value.email)) errors.email = 'Enter a valid email address.';
  try {
    const url = new URL(value.endpoint);
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) throw new Error();
  } catch {
    errors.endpoint = 'Enter an HTTP or HTTPS MCP server URL without credentials.';
  }
  return Object.keys(errors).length ? { errors } : { value, errors };
}

export function scopeRequestEmail(value: ScopeRequest, timestamp: string) {
  return [
    'Written scope request — not authorization to test',
    `Submitted at: ${timestamp}`, `MCP server URL: ${value.endpoint}`,
    `Name: ${value.name}`, `Email: ${value.email}`,
    `Who authorizes the test: ${value.authority}`,
    `What the buyer needs the report to prove: ${value.buyerNeeds || 'Not supplied'}`,
    '', 'Written scope and authorization must be confirmed before anything is tested.',
  ].join('\n');
}
