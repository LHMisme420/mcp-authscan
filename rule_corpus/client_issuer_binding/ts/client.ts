// Fixture: MCP TypeScript client M2M providers. Lines are pinned in ground_truth.json.
import { ClientCredentialsProvider, PrivateKeyJwtProvider } from '@modelcontextprotocol/client';

const unbound = new ClientCredentialsProvider({ clientId: 'svc', clientSecret: SECRET });

const bound = new ClientCredentialsProvider({
  clientId: 'svc', clientSecret: SECRET, expectedIssuer: 'https://auth.example.com',
});

const opts = { clientId: 'svc', privateKey: KEY, expectedIssuer: 'https://auth.example.com' };
const resolvedOk = new PrivateKeyJwtProvider(opts);

const info = await discoverOAuthServerInfo(url, { skipIssuerMetadataValidation: true });
