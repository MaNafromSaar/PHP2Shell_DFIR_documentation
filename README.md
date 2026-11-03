# PHP2Shell response — anonymized case overview

> **Status: private review draft; not approved for publication.** Written client approval for publication has not been recorded. This package contains no raw evidence or client-identifying information.

## Executive summary

Over one intensive week in October 2026, an organization requested an authorized assessment of two public websites and a related self-hosted mail service following disclosure of the PHP2Shell vulnerabilities (CVE-2026-109618 and CVE-2026-109619). The responder served as the coordination hub for the site owner and hosting providers, rapidly validating the immediate patch status, keeping decisions and open risks documented, and driving the response from assessment into recovery. Testing was non-invasive; no exploit attempts were made.

The assessment identified an obsolete application stack on Website A. Its PHP 7.2 package carried an Ubuntu 18.04 backport for the reported vulnerabilities, but this was not an upgrade to a supported upstream PHP release and did not remediate the obsolete CMS/framework stack or provide acceptable long-term assurance. Despite repeated requests to take the site offline, the legacy backend remained accessible during the subsequent assessment. Together with the hosting provider's inability to offer the requested isolated minimal server profile, these conditions drove the decision to migrate and replace the site. A separate provider temporarily took Website B offline to verify its patch status; the patch was already installed, its review found no unusual log activity, and service was promptly restored. PHP applicability on the mail service could not be established through external checks alone.

For Website A, a like-for-like upgrade was not considered the most efficient or maintainable route: reviewing and migrating a heavily outdated CMS and its extensions would have required substantial compatibility work. Through focused stakeholder discussions, the team identified which features were actually needed and made a fast decision to replace the legacy site rather than extend its life with a costly upgrade. A requirements-led redesign and static replacement followed as part of the incident response, and the new site was brought into production on a minimal Linux virtual server. This restored public availability while materially reducing the server-side attack surface: PHP and a database are not required to serve the site.

The website cutover did **not** close the investigation of the legacy host. Its current backend status and historical compromise status remain undetermined because the necessary legacy logs and complete backups were not available for review.

## Response coordination

The responder acted as the communication hub between the site owner and hosting providers throughout the response week: maintaining the timeline and action register, translating technical findings into decision options, arranging rapid provider checks, recording commitments, and coordinating containment and recovery. Regular, focused communication enabled prompt decisions—including a full redesign and replacement—while keeping unresolved forensic and handover actions visible. The records distinguish provider-reported results from independently reviewed evidence.

The assessment also refined an initial severity judgment after validating the exact distribution package against the Ubuntu security advisory and the provider's confirmation. The backport was evidence that the specified PHP2Shell issues had been patched in that Ubuntu package; it was not evidence that the end-of-life PHP branch or legacy application was supported or acceptably secured. Keeping those questions separate helped inform the migration decision.

## Workstream reports

- [Website A — legacy stack, redesign, and recovery](workstreams/website-a.md)
- [Replacement site — requirements-led attack-surface reduction](workstreams/new_replacement_site.md)
- [Website B — provider response and follow-up](workstreams/website-b.md)
- [Mail service — limited external assessment](workstreams/mail-service.md)
- [Helper tools and synthetic-data tests](tools/README.md)

## Findings, outcome, and limitations

- Website A's replacement is live; follow-up includes full DNS/domain control, confirming the long-term hosting arrangement, handling the “Aktuelles” (news) feature, and confirming safe retirement of the legacy service.
- Website B's provider reported that its logs showed no unusual activity during its check. That provider-reported review was not independently reproduced from a supplied log export.
- The mail-service checks did not determine whether an affected PHP runtime was present.
- No conclusion that either legacy web system was uncompromised is supported. The replacement site's operation is not evidence that the old backend has been disabled.
- The helper suite is included as reusable tooling. Its 50 automated tests pass against synthetic data only; the tools were not run against client backups or logs for this case.

## Method and disclosure

Evidence handling used a register recording source, collection time, storage reference, and SHA-256 hash where available. Sensitive session material in source diagnostic artifacts was identified and kept out of this package. The included tools operate on local copies; their findings are review leads, not proof.

AI assisted with analysis and documentation. The responder reviewed the assessment and cross-checked the patch-status correction against the relevant advisory and provider confirmation.

Before any public release, obtain written client approval, re-check for indirect identification, and confirm whether unresolved findings may be described. The separate workstream papers and helper tools remain part of this private review draft.
