import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { Router } from 'wouter';
import Landing from '../client/src/Landing';

// Public homepage only. Never render authentication or workspace data here.
// The browser still mounts the existing app; plain anchors work before JS.
export default function homepageMarkup() {
  return renderToStaticMarkup(
    <Router ssrPath="/">
      <Landing homepageVariant />
    </Router>,
  );
}
