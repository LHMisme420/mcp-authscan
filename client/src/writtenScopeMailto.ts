const recipient = 'lhmisme2011@gmail.com';

export function writtenScopeMailto(data: FormData) {
  const answer = (name: string) => String(data.get(name) ?? '');
  const publicationPermission = data.get('publicationPermission') === 'on';
  const authorized = data.get('authorized') === 'on';
  const subject = 'Written assessment request — MCP security assessment';
  const body = [
    'Written assessment scope request',
    '',
    `Your name: ${answer('name')}`,
    `Work email: ${answer('email')}`,
    `Company: ${answer('company')}`,
    'Assessment option: Full assessment',
    `MCP endpoint or URL: ${answer('endpoints')}`,
    `Who authorizes the test and on what basis: ${answer('authority')}`,
    `What buyer or review is waiting on it: ${answer('buyerContext')}`,
    `Permission to publish a redacted result: ${publicationPermission ? 'Yes' : 'No'}`,
    `I confirm authority to approve testing: ${authorized ? 'Yes' : 'No'}`,
  ].join('\n');

  return `mailto:${recipient}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
}
