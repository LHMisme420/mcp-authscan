import { useCallback, useState, type ReactNode } from 'react';
import { ClerkProvider, SignIn, SignUp, useAuth, useClerk, useUser } from '@clerk/react';
import { publishableKeyFromHost } from '@clerk/react/internal';
import { shadcn } from '@clerk/themes';
import { Redirect, Route, Router as WouterRouter, Switch, useLocation } from 'wouter';
import Dashboard from './Dashboard';
import Landing from './Landing';
import { AuthLoading } from './AuthLoading';
import { JoinTeamPage } from './PlanFeatures';

const clerkPubKey = publishableKeyFromHost(
  window.location.hostname,
  import.meta.env.VITE_CLERK_PUBLISHABLE_KEY,
);

const clerkProxyUrl = import.meta.env.VITE_CLERK_PROXY_URL;

const basePath = import.meta.env.BASE_URL.replace(/\/$/, '');

function stripBase(path: string): string {
  return basePath && path.startsWith(basePath)
    ? path.slice(basePath.length) || '/'
    : path;
}

function safeRedirectTarget(value: string | null, fallback: string) {
  if (!value || !value.startsWith('/') || value.startsWith('//') || value.includes('\\')) return fallback;
  try {
    const destination = new URL(value, window.location.origin);
    if (destination.origin !== window.location.origin) return fallback;
    return `${destination.pathname}${destination.search}${destination.hash}`;
  } catch {
    return fallback;
  }
}

if (!clerkPubKey) {
  throw new Error('Missing VITE_CLERK_PUBLISHABLE_KEY in .env file');
}

const clerkAppearance = {
  theme: shadcn,
  options: {
    logoPlacement: 'inside' as const,
    logoLinkUrl: basePath || '/',
    logoImageUrl: `${window.location.origin}${basePath}/logo.svg`,
  },
  variables: {
    colorPrimary: '#185d4d',
    colorForeground: '#202a28',
    colorMutedForeground: '#68746f',
    colorBackground: '#fbfaf6',
    colorInput: '#fffefa',
    colorInputForeground: '#202a28',
    colorDanger: '#a84e45',
    colorNeutral: '#c8cec4',
    fontFamily: 'DM Sans, sans-serif',
    borderRadius: '0.55rem',
  },
  elements: {
    rootBox: { width: '100%', display: 'flex', justifyContent: 'center' },
    cardBox: {
      width: 'min(440px, 100%)',
      overflow: 'hidden',
      borderRadius: '14px',
      backgroundColor: '#fbfaf6',
      boxShadow: '0 16px 50px rgba(32, 42, 40, .09)',
    },
    card: { backgroundColor: 'transparent', boxShadow: 'none', border: '0' },
    footer: { backgroundColor: 'transparent', boxShadow: 'none', border: '0' },
    headerTitle: { color: '#202a28', fontFamily: 'Manrope, sans-serif', fontWeight: '700' },
    headerSubtitle: { color: '#68746f' },
    socialButtonsBlockButtonText: { color: '#202a28', fontWeight: '600' },
    formFieldLabel: { color: '#34413b', fontWeight: '600' },
    footerActionLink: { color: '#185d4d', fontWeight: '700' },
    footerActionText: { color: '#68746f' },
    dividerText: { color: '#68746f' },
    identityPreviewEditButton: { color: '#185d4d' },
    formFieldSuccessText: { color: '#185d4d' },
    alertText: { color: '#202a28' },
    logoBox: { padding: '4px' },
    logoImage: { width: '34px', height: '34px', objectFit: 'contain' },
    socialButtonsBlockButton: { borderColor: '#dedfd5', color: '#202a28', backgroundColor: '#fffefa' },
    formButtonPrimary: { backgroundColor: '#185d4d', color: '#fffefa', boxShadow: 'none' },
    formFieldInput: { backgroundColor: '#fffefa', borderColor: '#c8cec4', color: '#202a28' },
    footerAction: { color: '#68746f' },
    dividerLine: { backgroundColor: '#dedfd5' },
    alert: { backgroundColor: '#f3e1dc', borderColor: '#ead5ce' },
    otpCodeFieldInput: { backgroundColor: '#fffefa', borderColor: '#c8cec4', color: '#202a28' },
    formFieldRow: { marginBottom: '16px' },
    main: { gap: '14px' },
  },
};

function HomeRoute() {
  const { isLoaded, isSignedIn } = useAuth();
  if (!isLoaded) return <AuthLoading />;
  return isSignedIn ? <Redirect to="/user-portal" /> : <Landing />;
}

function ProtectedRoute({ children }: { children: ReactNode }) {
  const { isLoaded, isSignedIn } = useAuth();
  if (!isLoaded) return <AuthLoading />;
  if (isSignedIn) return <>{children}</>;
  const callback = `${window.location.pathname}${window.location.search}${window.location.hash}`;
  return <Redirect to={`/sign-in?redirect_url=${encodeURIComponent(callback)}`} />;
}

function UserPortalRoute() {
  const { signOut } = useClerk();
  const { userId } = useAuth();
  const { user } = useUser();
  const [accountState, setAccountState] = useState<{ userId: string; account: {
    organization: { id: number | string; name: string };
    actorUserId: string;
    role?: 'owner' | 'member';
    usage?: { used: number; limit: 5 | null; remaining: number | null; month: string; resetsAt: string };
    capabilities?: { programmaticApi: boolean; scheduling: boolean; teamSeats: number; historyDays: 7 | null };
  } } | null>(null);
  const verifiedUserId = userId ?? '';
  const account = accountState?.userId === verifiedUserId ? accountState.account : null;
  const updateAccount = useCallback((nextAccount: typeof account) => {
    if (nextAccount) setAccountState({ userId: verifiedUserId, account: nextAccount });
  }, [verifiedUserId]);
  return (
    <ProtectedRoute>
      <Dashboard
        key={`${verifiedUserId}:${String(account?.organization.id ?? 'loading')}`}
        account={account}
        setAccount={updateAccount}
        userEmail={user?.primaryEmailAddress?.emailAddress}
        userId={verifiedUserId}
        onSignOut={() => void signOut({ redirectUrl: basePath || '/' })}
      />
    </ProtectedRoute>
  );
}

function SignInPage() {
  const target = new URLSearchParams(window.location.search).get('redirect_url');
  const fallback = safeRedirectTarget(target, `${basePath}/`);
  const signUpTarget = `${basePath}/sign-up?redirect_url=${encodeURIComponent(fallback)}`;
  return (
    <div className="auth-page">
      <a className="brand" href={basePath || '/'} aria-label="VATA home">
        <img src={`${basePath}/logo.svg`} alt="" /><span className="brand-word">VATA</span>
      </a>
      <SignIn
        routing="path"
        path={`${basePath}/sign-in`}
        signUpUrl={signUpTarget}
        forceRedirectUrl={fallback}
      />
    </div>
  );
}

function SignUpPage() {
  const target = new URLSearchParams(window.location.search).get('redirect_url');
  const fallback = safeRedirectTarget(target, `${basePath}/user-portal`);
  const signInTarget = `${basePath}/sign-in?redirect_url=${encodeURIComponent(fallback)}`;
  return (
    <div className="auth-page">
      <a className="brand" href={basePath || '/'} aria-label="VATA home">
        <img src={`${basePath}/logo.svg`} alt="" /><span className="brand-word">VATA</span>
      </a>
      <SignUp
        routing="path"
        path={`${basePath}/sign-up`}
        signInUrl={signInTarget}
        forceRedirectUrl={fallback}
      />
    </div>
  );
}

function JoinTeamRoute() {
  const { isLoaded, isSignedIn } = useAuth();
  if (!isLoaded) return <AuthLoading />;
  const token = new URLSearchParams(window.location.search).get('token');
  if (isSignedIn && token) return <Redirect to={`/user-portal?token=${encodeURIComponent(token)}`} />;
  return <JoinTeamPage />;
}

function ClerkRoutes() {
  const [, setLocation] = useLocation();
  return (
    <ClerkProvider
      publishableKey={clerkPubKey}
      proxyUrl={clerkProxyUrl}
      appearance={clerkAppearance}
      signInUrl={`${basePath}/sign-in`}
      signUpUrl={`${basePath}/sign-up`}
      localization={{
        signIn: { start: { title: 'Welcome back', subtitle: 'Sign in to your VATA security workspace' } },
        signUp: { start: { title: 'Create your VATA account', subtitle: 'Set up an account for your security workspace' } },
      }}
      routerPush={(to) => setLocation(stripBase(to))}
      routerReplace={(to) => setLocation(stripBase(to), { replace: true })}
    >
      <Switch>
        <Route path="/" component={HomeRoute} />
        <Route path="/user-portal" component={UserPortalRoute} />
        <Route path="/join-team" component={JoinTeamRoute} />
        <Route path="/success"><Redirect to="/user-portal" /></Route>
        <Route path="/cancel"><Redirect to="/user-portal" /></Route>
        <Route path="/sign-in/*?" component={SignInPage} />
        <Route path="/sign-up/*?" component={SignUpPage} />
        <Route><Redirect to="/" /></Route>
      </Switch>
    </ClerkProvider>
  );
}

function App() {
  return (
    <WouterRouter base={basePath}>
      <ClerkRoutes />
    </WouterRouter>
  );
}

export default App;
