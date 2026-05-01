/**
 * @name Credential value reaches an exception message
 * @description A credential read from ``KyotoUAuth`` flows into the
 *              argument of a ``raise`` statement or an exception
 *              constructor. Exception messages surface in stack traces
 *              and error reporting tools, both of which we treat as
 *              untrusted destinations for credential material.
 * @kind path-problem
 * @id python/kuauth/credential-leak-exception
 * @problem.severity error
 * @security-severity 9.0
 * @precision high
 * @tags security
 *       external/cwe/cwe-209
 *       external/cwe/cwe-532
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import KuauthSources
import KuauthSinks

private module CredLeakExceptionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { KuauthSources::isSource(source) }

  predicate isSink(DataFlow::Node sink) { KuauthSinks::isExceptionSink(sink) }
}

module CredLeakExceptionFlow = TaintTracking::Global<CredLeakExceptionConfig>;

import CredLeakExceptionFlow::PathGraph

from CredLeakExceptionFlow::PathNode source, CredLeakExceptionFlow::PathNode sink
where CredLeakExceptionFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Credential value from $@ flows into an exception message; it will surface in stack traces.",
  source.getNode(), "this credential read"
