/**
 * @name Credential value rendered by ``__repr__`` or ``__str__``
 * @description A credential read from ``KyotoUAuth`` flows into the return
 *              value of a ``__repr__`` or ``__str__`` method. Such methods
 *              are called implicitly by ``print``, f-strings, the
 *              interactive interpreter, debuggers, and frame-locals dumps
 *              in stack traces — so anything they return is effectively
 *              public.
 * @kind path-problem
 * @id python/kuauth/credential-leak-repr-str
 * @problem.severity error
 * @security-severity 8.5
 * @precision high
 * @tags security
 *       external/cwe/cwe-200
 *       external/cwe/cwe-532
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import KuauthSources
import KuauthSinks

private module CredLeakReprStrConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { KuauthSources::isSource(source) }

  predicate isSink(DataFlow::Node sink) { KuauthSinks::isReprStrSink(sink) }
}

module CredLeakReprStrFlow = TaintTracking::Global<CredLeakReprStrConfig>;

import CredLeakReprStrFlow::PathGraph

from CredLeakReprStrFlow::PathNode source, CredLeakReprStrFlow::PathNode sink
where CredLeakReprStrFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Credential value from $@ is rendered by ``__repr__`` / ``__str__``; it will leak via debug output.",
  source.getNode(), "this credential read"
