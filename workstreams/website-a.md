# Website A — legacy stack and recovery

> Sanitized workstream summary. Client and provider identifiers, hostnames, addresses, paths, and raw evidence are intentionally omitted.

## Assessment

The public site used an end-of-life PHP branch with a substantially outdated CMS/framework stack and a development profiler exposed during assessment. Access to the shared hosting environment was limited, so key containment and forensic actions required provider cooperation.

The first severity assessment treated the old PHP build date as evidence that the emergency fix might be absent. Review of the exact package against the Ubuntu 18.04 security advisory, followed by provider confirmation, established that Ubuntu had backported a fix for the named PHP2Shell vulnerabilities to that package. The rating for those specific CVEs was revised accordingly. This was not an upgrade to a supported upstream PHP release, did not bring the end-of-life runtime or legacy CMS/framework back into a supported state, and did not determine whether earlier compromise had occurred. The backport therefore did not constitute adequate long-term remediation for the overall legacy environment.

Containment concerns reinforced that conclusion. Despite repeated requests to take the site offline, the legacy backend remained accessible during the subsequent assessment. Later front-end errors did not establish that the backend had been disabled. The provider also could not offer the requested separate minimal server without the legacy application stack. The site owner therefore chose to leave that hosting arrangement and migrate to a different hoster while replacing the site.

## Recovery decision

A like-for-like upgrade was not judged to be the shortest or lowest-risk route. Compatibility work across the obsolete CMS and its extensions would have required significant effort before the site’s actual feature requirements were clear. Through focused stakeholder discussions, the responder and site owner quickly identified which features were used and needed, then chose a requirements-led redesign rather than carrying the legacy stack forward. The move to a different hosting arrangement and the full replacement were risk-reduction decisions prompted by both the unsupported legacy stack and the unresolved containment concerns.

The replacement was rebuilt as a static site and deployed to a minimal Linux virtual server. The server-side serving path does not require PHP, a database, or build tools. The production domain was cut over in late October 2026, and the site owner confirmed availability. This delivered the full replacement as part of the response, materially reducing the public site's application attack surface without claiming that the legacy host or wider infrastructure was risk-free.

## Current status and limits

The replacement is live. DNS/domain control, the long-term hosting arrangement, and the replacement for the “Aktuelles” (news) workflow remain follow-up items. The status of the old backend and hosting account is not confirmed. It remains unclear whether the legacy environment has been properly decommissioned.

The legacy host's logs and complete backups are now available for review. No historical compromise conclusion is apparent, deeper analysis may still be required; the earlier certificate and availability symptoms also did not establish whether the backend was disabled. The review of the legacy environment will focus on identifying any signs of compromise and verifying proper decommissioning.
