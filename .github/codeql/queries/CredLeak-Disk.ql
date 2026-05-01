/**
 * @name Credential value reaches a disk write
 * @description A credential read from ``KyotoUAuth`` flows into a file
 *              write or serialization sink (``open().write``,
 *              ``Path.write_text/write_bytes``, ``json.dump(s)``,
 *              ``pickle.dump(s)``, ``csv.writerow``). Cleartext storage
 *              of credentials is forbidden by this library's threat
 *              model.
 * @kind path-problem
 * @id python/kuauth/credential-leak-disk
 * @problem.severity error
 * @security-severity 9.5
 * @precision high
 * @tags security
 *       external/cwe/cwe-312
 *       external/cwe/cwe-313
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import KuauthSources
import KuauthSinks

private module CredLeakDiskConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { KuauthSources::isSource(source) }

  predicate isSink(DataFlow::Node sink) { KuauthSinks::isDiskSink(sink) }
}

module CredLeakDiskFlow = TaintTracking::Global<CredLeakDiskConfig>;

import CredLeakDiskFlow::PathGraph

from CredLeakDiskFlow::PathNode source, CredLeakDiskFlow::PathNode sink
where CredLeakDiskFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Credential value from $@ is written to disk in cleartext.",
  source.getNode(), "this credential read"
