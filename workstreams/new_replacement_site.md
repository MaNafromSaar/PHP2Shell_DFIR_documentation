# Replacement site — requirements-led reduction of attack surface

> Sanitized workstream summary. Client and provider identifiers, hostnames, addresses, paths, and raw evidence are intentionally omitted.

## Design objective

The recovery goal was not to reproduce the legacy platform feature for feature. The old CMS, framework, PHP runtime, and extensions were substantially outdated. A like-for-like upgrade would have required significant compatibility work before it was clear which capabilities the site owner still needed. That path risked spending time and introducing change in features that might not be used.

The design decision therefore started with the user's needs: identify the public content and workflows that were actually required, distinguish them from capabilities inherited from the old CMS, and decide which dynamic features could be retired or handled separately. This requirements review made it possible to choose a simpler operating model rather than carry forward the old application by default.

## Chosen architecture

The public site was rebuilt as a static site. Pages and assets are generated locally, then the built output is deployed to a minimal Linux virtual server configured to serve files over HTTPS. The production web server does not need the site generator, PHP, an application runtime, or a database to serve the site.

This removes several classes of exposure from the public request path:

- no CMS administration or authentication endpoint;
- no server-side application code or PHP interpreter for website requests;
- no database connection or database-backed content processing;
- no visitor-submitted form or account data handled by the site application;
- no build dependencies or source toolchain required on the serving host.

The architecture is deliberately aligned with an informational website. If the owner later needs an editorial workflow, event registration, accounts, or other interactive features, assess each requirement separately before adding a service. Prefer a proportionate, separately managed service over reintroducing a broad dynamic stack without a clear need.

## Data handling and boundaries

The static site application does not accept or persist user-submitted content, account records, or form data. It therefore avoids collecting such data in an application database as part of normal site use. This is narrower than saying the website processes no visitor data at all: requests necessarily reach the web server, and operational server logs may contain request metadata. In this deployment, a separate page-count log stores monthly counts without IP address, URL, referrer, or browser data; the ordinary Nginx access log is retained separately for a limited period. See the deployment record for the configured retention details.

This design statement is not a complete privacy audit of DNS, hosting, TLS, browser behavior, or any future third-party integrations. Those components still require their own configuration and review.

## Security properties and residual risk

Serving static output from a minimal host materially reduces the site's application-layer attack surface and ongoing patch burden. It is not a guarantee of immunity or availability. The operating system, Nginx, TLS configuration, SSH/deployment credentials, build workstation, DNS control, and deployment process still require maintenance and protection. A compromised build pipeline or stolen deployment credential could still alter published content.

The website's DNS cutover and owner-reported availability established that the replacement went live. They did not prove that the legacy CMS backend or hosting account was disabled, nor do they establish the historical compromise status of the old host.

## Follow-up decisions

- Confirm full DNS/domain control and the long-term hosting arrangement.
- Define how the “Aktuelles” (news) section will be updated without introducing unnecessary public write access or an application database.
- Keep any future interactive service outside the static serving path where practical, with its own scope, data-flow review, and security ownership.
- Verify legacy-host decommissioning separately and complete the outstanding forensic review if necessary based on the findings from the legacy environment logs and backups.
