# Security Policy

## Reporting a vulnerability

Report through the private advisory form on this repository: https://github.com/LHMisme420/mcp-authscan/security/advisories/new

If you cannot use it, email lhmisme2011@gmail.com. Do not open a public issue for a suspected vulnerability.

What to expect:
- an initial response within 7 days
- an assessment saying whether the report is accepted, with a reason either way
- a fix on the latest release, or a written decision not to fix
- credit in the published advisory unless you ask to stay anonymous

Coordinated disclosure. Nothing is published before a fix is available, or before 90 days from acknowledgement, whichever comes first.

## Supported versions

The latest release on PyPI is supported. Fixes are not backported to earlier versions unless the issue is severe and the older version is still in wide use, and when that happens the advisory says so.

## What this tool does and does not do

Every report stamps the probe set version next to the tool version. That stamp, not this page, is the authoritative list of what was tested, and each report names every probe that returned no verdict and why. This page deliberately does not enumerate probes, because that list has already drifted once.

Two modes, both covered here:
- repository review, which reads a target's source tree and configuration without executing its code
- live scanning, which sends HTTP requests to the host the operator names: an MCP initialize, the RFC 9728 discovery chain, and OAuth endpoint probes

Live scanning is network facing by design and is only legitimate against systems you operate or are explicitly authorised in writing to test. Obtaining that authorisation is the operator's responsibility.

mcp-authscan checks preconditions. It never attempts exploitation, command execution or credential capture.

## In scope for reports about this tool

- a false pass: a property reported as demonstrated where the evidence does not support it
- unsafe request handling during a live scan, including requests to hosts outside the named scope
- unsafe file handling during a repository review
- crashes, hangs or resource exhaustion caused by a malformed or hostile target

## Out of scope

- findings about someone else's MCP server. Those belong to that server's operator, not here
- requests to scan a host you do not control
- reports against a version no longer supported, unless the issue reproduces on the latest release

## Publication

Advisories are published on this repository with credit. A scan report is not a disclosure: it records what one run observed, and a run with no findings is not a statement that a server is safe.
