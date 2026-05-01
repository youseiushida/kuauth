/**
 * Sanitizer model for the four legitimate credential-bearing HTTP POSTs
 * to the Kyoto-U IdPs and ECS CAS server.
 *
 * The library MUST send the password to:
 *   - ``auth.iimc.kyoto-u.ac.jp/pub/login.cgi``     (SimpleSAMLphp)
 *   - ``auth.iimc.kyoto-u.ac.jp/pub/otplogin.cgi``  (SimpleSAMLphp OTP)
 *   - ``authidp1.iimc.kyoto-u.ac.jp/.../j_security_check`` (Java Shib IdP)
 *   - ``panda.ecs.kyoto-u.ac.jp/cas/login``         (Apereo CAS)
 *
 * The destination URL is dynamically extracted from parsed HTML at runtime
 * (``form["action"]`` from ``_parsers.parse_*_form``) so we can't prove the
 * host statically. We therefore sanitize at the *callsite granularity*:
 * any ``httpx`` call whose enclosing function is one of the four named
 * submitters is considered legitimate.
 *
 * If a future maintainer adds a fifth IdP submitter, they must add it
 * here — preferring an explicit allowlist over a heuristic so the failure
 * mode is "CI flags the new submitter as a leak" (visible) rather than
 * "CI silently waves through a real exfiltration" (invisible).
 */

import python
import semmle.python.dataflow.new.DataFlow

module KuauthAllowedHosts {
  /**
   * The set of function names that legitimately POST credentials to a
   * trusted IdP/CAS endpoint. Matched against ``Function.getName()`` —
   * the surrounding class is checked separately for ``_submit_cas_login``
   * (PandA-only) to avoid masking a same-named helper added elsewhere.
   */
  predicate isLegitimateAuthSubmitter(Function f) {
    f.getName() in [
        "_submit_simplesaml_password",
        "_submit_simplesaml_otp",
        "_submit_shib_idp_login"
      ]
    or
    // ``_submit_cas_login`` is unique to PandA; pin on the class to keep
    // the allowlist narrow.
    f.getName() = "_submit_cas_login" and
    f.getScope().(Class).getName() = "PandA"
  }

  /**
   * Holds for nodes inside a function body that is on the allowlist of
   * legitimate credential submitters. Used as a barrier in the
   * UnknownHttp query — flows that terminate inside one of these
   * functions are treated as sanitized.
   */
  predicate isAllowedSubmitterContext(DataFlow::Node node) {
    exists(Function f |
      isLegitimateAuthSubmitter(f) and
      node.getScope() = f
    )
  }
}
