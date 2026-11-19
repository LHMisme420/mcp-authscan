export const assessmentPackages = {
  verification: 'MCP Server Security Verification — $1,750',
  comprehensive: 'Comprehensive MCP Security Assessment — $3,500',
  undecided: 'Help me choose an assessment',
} as const;

export type AssessmentInquiry = {
  name: string;
  email: string;
  company: string;
  website: string;
  service: keyof typeof assessmentPackages;
  servers: number;
  timeframe: string;
  scope: string;
};
export type InquiryErrors = Partial<Record<keyof AssessmentInquiry, string>>;
export const emailPattern = /^[^\s<>@\r\n]+@[^\s<>@\r\n]+\.[^\s<>@\r\n]+$/;

// Shared validation is for usability; the server always validates independently.
export function validateInquiry(input: unknown): { value?: AssessmentInquiry; errors: InquiryErrors } {
  const data = input && typeof input === 'object' && !Array.isArray(input)
    ? input as Record<string, unknown> : {};
  const errors: InquiryErrors = {};
  const text = (key: keyof AssessmentInquiry, min: number, max: number) => {
    const raw = data[key];
    const value = typeof raw === 'string' ? raw.trim() : '';
    if (value.length < min || value.length > max || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(value)) {
      errors[key] = `Enter ${min}–${max} characters.`;
    }
    return value;
  };
  const name = text('name', 1, 100);
  const email = text('email', 3, 254);
  if (!emailPattern.test(email)) errors.email = 'Enter a valid business email address.';
  const company = text('company', 1, 160);
  const website = text('website', 0, 500);
  if (website) {
    try {
      const url = new URL(website);
      if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || !url.hostname.includes('.')) throw new Error();
    } catch { errors.website = 'Enter a complete http:// or https:// website URL, or leave blank.'; }
  }
  const service = data.service as AssessmentInquiry['service'];
  if (!Object.prototype.hasOwnProperty.call(assessmentPackages, service)) errors.service = 'Select an assessment package.';
  const servers = data.servers;
  if (typeof servers !== 'number' || !Number.isInteger(servers) || servers < 1 || servers > 1000) errors.servers = 'Enter a whole number from 1 to 1,000.';
  const timeframe = text('timeframe', 2, 120);
  const scope = text('scope', 20, 3000);
  if (Object.keys(errors).length) return { errors };
  return { errors, value: { name, email, company, website, service, servers: servers as number, timeframe, scope } };
}
