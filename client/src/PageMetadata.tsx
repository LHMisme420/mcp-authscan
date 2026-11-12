import { useEffect } from 'react';
import { useLocation } from 'wouter';
import { metadataForPath } from '../../shared/siteMetadata';

export function PageMetadata() {
  const [pathname] = useLocation();
  useEffect(() => {
    const metadata = metadataForPath(pathname);
    document.title = metadata.title;
    const setContent = (selector: string, content: string) =>
      document.querySelector(selector)?.setAttribute('content', content);
    setContent('meta[name="description"]', metadata.description);
    setContent('meta[name="robots"]', metadata.robots);
    setContent('meta[property="og:title"]', metadata.title);
    setContent('meta[property="og:description"]', metadata.description);
    setContent('meta[property="og:url"]', metadata.canonical);
    setContent('meta[name="twitter:title"]', metadata.title);
    setContent('meta[name="twitter:description"]', metadata.description);
    document.querySelector('link[rel="canonical"]')?.setAttribute('href', metadata.canonical);
  }, [pathname]);
  return null;
}
