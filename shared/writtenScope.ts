import { emailPattern } from './assessmentInquiry';

export const scopeOptions = {
  verification: 'Single server, 1,750 dollars',
  comprehensive: 'Full assessment, 3,500 dollars',
} as const;
export const scopeAuthorization = 'I confirm I own this endpoint, or am authorized to approve testing of it, and I will confirm the scope in writing before any test runs.';
export type WrittenScope = {
  name: string; email: string; company: string; endpoints: string;
  service: keyof typeof scopeOptions; authority: string; environment: string; authorized: true;
  buyerContext: string; publicationPermission: boolean;
};

export function validateWrittenScope(input: unknown) {
  const data = input && typeof input === 'object' && !Array.isArray(input) ? input as Record<string, unknown> : {};
  const errors: Record<string, string> = {};
  const text = (key: string, min: number, max: number) => {
    const value = typeof data[key] === 'string' ? (data[key] as string).trim() : '';
    if (value.length < min || value.length > max || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(value)) errors[key] = `Enter ${min}–${max} characters.`;
    return value;
  };
  const name = text('name', 1, 100), email = text('email', 3, 254), company = text('company', 1, 160);
  if (!emailPattern.test(email)) errors.email = 'Enter a valid work email address.';
  const endpoints = text('endpoints', 1, 3000);
  const lines = endpoints.split(/\r?\n/);
  // Intake only: never connect to, resolve, or scan submitted endpoints.
  if (lines.length > 50 || lines.some(line => !line.trim())) errors.endpoints = 'Enter up to 50 endpoints, one per line.';
  const authority = text('authority', 1, 3000), environment = text('environment', 0, 2000);
  const buyerContext = text('buyerContext', 1, 2000);
  if (data.publicationPermission !== undefined && typeof data.publicationPermission !== 'boolean') {
    errors.publicationPermission = 'Publication permission must be a checkbox choice.';
  }
  const publicationPermission = data.publicationPermission === true;
  const service = data.service as WrittenScope['service'];
  if (!Object.hasOwn(scopeOptions, service)) errors.service = 'Select an assessment option.';
  if (data.authorized !== true) errors.authorized = 'Confirm your authority and written scope before submitting.';
  const value: WrittenScope = { name, email, company, endpoints, service, authority, environment, authorized: true, buyerContext, publicationPermission };
  return Object.keys(errors).length ? { errors } : { value, errors };
}

export function scopeEmailText(value: WrittenScope, timestamp: string) {
  return [
    'Written assessment scope request — not authorization to test',
    `Submitted at: ${timestamp}`, `Name: ${value.name}`, `Work email: ${value.email}`,
    `Company: ${value.company}`, `Which option: ${scopeOptions[value.service]}`,
    '', 'Endpoint or endpoints to be tested:', value.endpoints,
    '', 'Who owns the endpoint and their authority to authorize testing:', value.authority,
    '', 'What buyer or review is waiting on it:', value.buyerContext,
    '', `Permission to publish a redacted result: ${value.publicationPermission ? 'Yes' : 'No'}`,
    '', 'Anything we should know about the environment:', value.environment || 'Not supplied',
    '', scopeAuthorization,
    '', 'A written scope will follow. No testing happens until the customer approves it. Invoicing happens after the scope is agreed.',
  ].join('\n');
}
