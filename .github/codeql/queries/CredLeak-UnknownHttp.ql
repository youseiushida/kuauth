/**
 * @name Credential value sent in an HTTP request outside the IdP allowlist
 * @description A credential read from ``KyotoUAuth`` flows into an
 *              outbound ``httpx`` request that is NOT inside one of the
 *              four legitimate auth-form-submit functions
 *              (``_submit_simplesaml_password``,
 *              ``_submit_simplesaml_otp``, ``_submit_shib_idp_login``,
 *              ``PandA._submit_cas_login``). Any other HTTP egress
 *              carrying a credential is treated as exfiltration.
 * @kind path-problem
 * @id python/kuauth/credential-leak-unknown-http
 * @problem.severity error
 * @security-severity 9.5
 * @precision medium
 * @tags security
 *       external/cwe/cwe-201
 *       external/cwe/cwe-200
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import KuauthSources
import KuauthSinks
import KuauthAllowedHosts

private module CredLeakUnknownHttpConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { KuauthSources::isSource(source) }

  predicate isSink(DataFlow::Node sink) {
    KuauthSinks::isHttpRequestSink(sink) and
    not KuauthAllowedHosts::isAllowedSubmitterContext(sink)
  }

  /**
   * Treat the body of any allowlisted submitter as a sanitization barrier
   * so that intermediate values within those functions don't propagate
   * into a flagged sink even via aliasing.
   */
  predicate isBarrier(DataFlow::Node node) {
    KuauthAllowedHosts::isAllowedSubmitterContext(node)
  }
}

module CredLeakUnknownHttpFlow = TaintTracking::Global<CredLeakUnknownHttpConfig>;

import CredLeakUnknownHttpFlow::PathGraph

from
  CredLeakUnknownHttpFlow::PathNode source, CredLeakUnknownHttpFlow::PathNode sink
where CredLeakUnknownHttpFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Credential value from $@ is sent in an HTTP request outside the IdP/CAS allowlist.",
  source.getNode(), "this credential read"
