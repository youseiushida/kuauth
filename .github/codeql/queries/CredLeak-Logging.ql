/**
 * @name Credential value reaches a logging sink
 * @description A credential read from ``KyotoUAuth`` (password, TOTP secret,
 *              one-time password, or the result of ``_resolve_otp``) flows
 *              into a logging-style call (``logging``, ``print``,
 *              ``warnings.warn``, ``sys.stdout/stderr.write``,
 *              ``traceback.print_*``). Logged credentials surface to
 *              operators and observability pipelines and must never appear
 *              there in cleartext.
 * @kind path-problem
 * @id python/kuauth/credential-leak-logging
 * @problem.severity error
 * @security-severity 9.0
 * @precision high
 * @tags security
 *       external/cwe/cwe-532
 *       external/cwe/cwe-359
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import KuauthSources
import KuauthSinks

private module CredLeakLoggingConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { KuauthSources::isSource(source) }

  predicate isSink(DataFlow::Node sink) { KuauthSinks::isLoggingSink(sink) }
}

module CredLeakLoggingFlow = TaintTracking::Global<CredLeakLoggingConfig>;

import CredLeakLoggingFlow::PathGraph

from CredLeakLoggingFlow::PathNode source, CredLeakLoggingFlow::PathNode sink
where CredLeakLoggingFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Credential value from $@ flows to a logging sink, exposing it to operators.",
  source.getNode(), "this credential read"
