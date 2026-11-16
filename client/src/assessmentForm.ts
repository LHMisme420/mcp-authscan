import { assessmentEmail } from './AssessmentSections';

export type AssessmentPackageChoice = 'private' | 'publication';

const packageNames: Record<AssessmentPackageChoice, string> = {
  private: 'Private assessment — $3,500',
  publication: 'Assessment with publication — $2,500',
};

export const assessmentHostnamePattern = '(?=^.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*\\.?';

export function isValidAssessmentHostname(host: string) {
  return new RegExp(`^${assessmentHostnamePattern}$`).test(host);
}

export function assessmentDraftUrl(
  choice: AssessmentPackageChoice,
  company: string,
  hostname: string,
  email: string,
) {
  const subject = `MCP AuthScan assessment inquiry — ${packageNames[choice]}`;
  const body = [
    'Hello, I would like to start an MCP AuthScan assessment.',
    '',
    `Selected option: ${packageNames[choice]}`,
    `Company: ${company}`,
    `Endpoint host: ${hostname}`,
    `Contact email: ${email}`,
    '',
    'I understand that scope will be confirmed in writing before anything runs.',
  ].join('\n');
  return `mailto:${assessmentEmail}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
}
