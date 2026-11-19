import { Link } from 'wouter';
import type { ReactNode } from 'react';
import './commercial.css';

type PublicSiteLayoutProps = {
  children: ReactNode;
  className?: string;
  footerNote?: string;
};

const pypiUrl = 'https://pypi.org/project/mcp-authscan/';
const githubUrl = 'https://github.com/LHMisme420/mcp-authscan';

export default function PublicSiteLayout({ children, className = '', footerNote }: PublicSiteLayoutProps) {
  return (
    <div className={`app-shell public-site ${className}`}>
      <header className="wrap landing-nav">
        <Link href="/" className="brand public-site-brand" aria-label="VATA home">
          <img src="/logo.svg" alt="" />
          <span className="public-brand-stack">
            <span className="commercial-brand-name">VATA</span>
            <span className="commercial-brand-subtitle">Hosted MCP security workspace</span>
          </span>
        </Link>
        <nav className="public-site-nav" aria-label="Public site navigation">
          <Link href="/assessments">Assessments</Link>
          <Link href="/sample-assessment">Sample report</Link>
          <Link href="/request-assessment">Request assessment</Link>
          <a href={pypiUrl} target="_blank" rel="noopener noreferrer">PyPI</a>
          <a href={githubUrl} target="_blank" rel="noopener noreferrer">GitHub</a>
        </nav>
        <nav className="nav-actions" aria-label="Workspace account">
          <Link href="/sign-in" className="button quiet">Sign in</Link>
          <Link href="/sign-up" className="button small">Create account</Link>
        </nav>
      </header>
      <main className="public-site-main">{children}</main>
      <footer className="wrap public-site-footer">
        <div className="public-footer-brands">
          <span><strong>VATA</strong> — Hosted MCP security workspace.</span>
          <span><strong>MCP AuthScan</strong> — Open-source scanner and independent assessment services.</span>
          {footerNote && <span>{footerNote}</span>}
        </div>
        <nav className="public-footer-links" aria-label="Footer links">
          <Link href="/assessments">Assessments</Link>
          <Link href="/sample-assessment">Sample report</Link>
          <Link href="/request-assessment">Request assessment</Link>
          <a href={pypiUrl} target="_blank" rel="noopener noreferrer">PyPI package</a>
          <a href={githubUrl} target="_blank" rel="noopener noreferrer">GitHub source</a>
        </nav>
      </footer>
    </div>
  );
}
