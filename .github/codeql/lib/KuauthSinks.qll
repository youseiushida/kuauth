/**
 * Shared sink models for kuauth credential-leak queries.
 *
 * Each predicate names one egress channel through which a credential could
 * leave the library. The split is by channel rather than by query so that
 * a future query (e.g. ``CredLeak-Telemetry``) can compose existing sinks
 * without restating them.
 *
 * Sinks are typed via ``API`` graphs wherever possible — matching by bare
 * method name (e.g. any ``.info()`` call) would alert on unrelated objects
 * that happen to share the name. Receiver-typed matches sacrifice some
 * recall (a Logger passed in from outside the import graph won't be
 * recognized) for much higher precision, which is the right trade for a
 * library where the entire credential surface fits in a few hundred lines.
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.ApiGraphs

module KuauthSinks {
  /** API node for any ``logging.Logger`` instance. */
  private API::Node loggerInstance() {
    result = API::moduleImport("logging").getMember("getLogger").getReturn() or
    result = API::moduleImport("logging").getMember("Logger").getReturn() or
    result = loggerInstance().getMember("getChild").getReturn()
  }

  /**
   * Holds for arguments to logging-style calls that surface to humans:
   * the ``logging`` module, ``Logger`` instances, ``print``,
   * ``warnings.warn``, ``sys.stdout.write`` / ``sys.stderr.write`` and
   * the ``traceback.print_*`` family.
   *
   * For ``logger.<level>(msg, *args)`` we treat *every* positional
   * argument as a sink: arg 0 is the message template, args 1+ are
   * ``%`` substitutions that get rendered into the final log line.
   * ``logger.log(level, msg, *args)`` is handled identically except
   * arg 0 is the numeric level (skipped).
   */
  predicate isLoggingSink(DataFlow::Node node) {
    // logging.<level>(...) module-level shorthand and logger.<level>(...).
    exists(DataFlow::CallCfgNode call, string method |
      method in ["debug", "info", "warning", "warn", "error", "critical", "exception"] and
      (
        call = API::moduleImport("logging").getMember(method).getACall() or
        call = loggerInstance().getMember(method).getACall()
      ) and
      node = call.getArg(_)
    )
    or
    // logger.log(level, msg, *args) — skip arg 0 (the level).
    exists(DataFlow::CallCfgNode call, int i |
      (
        call = loggerInstance().getMember("log").getACall() or
        call = API::moduleImport("logging").getMember("log").getACall()
      ) and
      i >= 1 and
      node = call.getArg(i)
    )
    or
    // print(...) — every positional argument is potential leakage.
    exists(DataFlow::CallCfgNode call |
      call = API::moduleImport("builtins").getMember("print").getACall() and
      node = call.getArg(_)
    )
    or
    // warnings.warn(message, ...).
    exists(DataFlow::CallCfgNode call |
      call = API::moduleImport("warnings").getMember("warn").getACall() and
      node = call.getArg(0)
    )
    or
    // sys.stdout.write(...) / sys.stderr.write(...).
    exists(DataFlow::CallCfgNode call, string stream |
      stream in ["stdout", "stderr"] and
      call =
        API::moduleImport("sys").getMember(stream).getMember("write").getACall() and
      node = call.getArg(0)
    )
    or
    // traceback.print_exc / print_exception / print_stack — these dump
    // frame locals that may carry the password.
    exists(DataFlow::CallCfgNode call, string fn |
      fn in [
          "print_exc", "print_exception", "print_stack",
          "format_exc", "format_exception", "format_stack"
        ] and
      call = API::moduleImport("traceback").getMember(fn).getACall() and
      node = call.getArg(_)
    )
  }

  /**
   * Holds for arguments to a ``raise X(...)`` constructor.
   *
   * The kuauth codebase exclusively uses the inline form
   * (``raise AuthenticationError("msg")``) — we don't model the
   * less-common ``e = X(...); raise e`` because covering it would force
   * a name-suffix heuristic that produces false positives on unrelated
   * callables.
   */
  predicate isExceptionSink(DataFlow::Node node) {
    exists(Raise r, DataFlow::CallCfgNode call |
      call.asExpr() = r.getException() and
      node = call.getArg(_)
    )
  }

  /**
   * Holds for any expression that flows out of a ``__repr__`` or
   * ``__str__`` method as its return value. ``KyotoUAuth`` doesn't
   * currently define either, but if a future maintainer adds one that
   * embeds ``self._password`` we want to catch it.
   */
  predicate isReprStrSink(DataFlow::Node node) {
    exists(Function f, Return ret |
      f.getName() in ["__repr__", "__str__"] and
      ret.getScope() = f and
      node.asExpr() = ret.getValue()
    )
  }

  /**
   * Holds for arguments to file/serialization writes that persist data
   * to disk or to an in-process buffer that's typically flushed to disk.
   */
  predicate isDiskSink(DataFlow::Node node) {
    // open(...).write(...) — the file handle from open() is the only
    // ``write`` we want; matching ``.write`` on every object would
    // false-positive on httpx response writers, file-like wrappers, etc.
    exists(DataFlow::CallCfgNode call, string method |
      method in ["write", "writelines"] and
      call = API::moduleImport("builtins").getMember("open").getReturn().getMember(method).getACall() and
      node = call.getArg(0)
    )
    or
    // pathlib.Path(...).write_text/write_bytes(...).
    exists(DataFlow::CallCfgNode call, string method |
      method in ["write_text", "write_bytes"] and
      call = API::moduleImport("pathlib").getMember("Path").getReturn().getMember(method).getACall() and
      node = call.getArg(0)
    )
    or
    // json.dump/dumps and pickle.dump/dumps — first positional is the
    // object being serialized.
    exists(DataFlow::CallCfgNode call, string mod, string fn |
      mod in ["json", "pickle"] and
      fn in ["dump", "dumps"] and
      call = API::moduleImport(mod).getMember(fn).getACall() and
      node = call.getArg(0)
    )
    or
    // csv.writer(stream).writerow([...]) and writerows.
    exists(DataFlow::CallCfgNode call, string method |
      method in ["writerow", "writerows"] and
      call = API::moduleImport("csv").getMember("writer").getReturn().getMember(method).getACall() and
      node = call.getArg(0)
    )
    or
    // csv.DictWriter(stream).writerow({...}).
    exists(DataFlow::CallCfgNode call, string method |
      method in ["writerow", "writerows"] and
      call = API::moduleImport("csv").getMember("DictWriter").getReturn().getMember(method).getACall() and
      node = call.getArg(0)
    )
  }

  /**
   * Holds for arguments to outbound ``httpx`` HTTP requests. Used as the
   * sink for ``CredLeak-UnknownHttp``: any flow into one of these calls
   * that is NOT inside a known auth-form-submit function is treated as
   * exfiltration.
   *
   * We deliberately do NOT type-filter the receiver. ``httpx`` is a
   * third-party package and CodeQL's API graph cannot reliably follow
   * the standard kuauth pattern (``KyotoUAuth._http = httpx.Client()``
   * exposed via ``_SPService.http`` property → ``self.http.post(...)``)
   * end to end. The combination of method name (``get``/``post``/...)
   * AND argument shape (positional URL or one of the httpx-specific
   * keyword args ``params``/``data``/``json``/``headers``/``content``)
   * is specific enough that non-HTTP callees with the same method name
   * (``dict.get``, ``list.append`` patterns, etc.) almost never collide.
   * The query also gates on flow originating from a credential source
   * and applies the legitimate-submitter sanitizer, which together
   * push false positives well below the noise threshold.
   */
  predicate isHttpRequestSink(DataFlow::Node node) {
    // get/post/put/patch/delete: signature is ``(url, ...)`` — positional
    // 0 is the URL.
    exists(DataFlow::MethodCallNode call, string method |
      method in ["get", "post", "put", "patch", "delete"] and
      call.getMethodName() = method and
      (
        node = call.getArg(0)
        or
        node = call.getArgByName("url")
        or
        node = httpxBodySideArg(call)
      )
    )
    or
    // request/stream: signature is ``(method, url, ...)`` — positional 0
    // is the HTTP verb (NOT a credential sink), positional 1 is the URL.
    // Modeling arg 0 as the URL would (a) leave URL-borne credentials
    // unflagged when callers use the generic helpers and (b) over-flag
    // verbs like ``"GET"`` as ``url=...``.
    exists(DataFlow::MethodCallNode call, string method |
      method in ["request", "stream"] and
      call.getMethodName() = method and
      (
        node = call.getArg(1)
        or
        node = call.getArgByName("url")
        or
        node = httpxBodySideArg(call)
      )
    )
    or
    // send: signature is ``(request, ...)`` where ``request`` is a
    // ``httpx.Request`` carrying URL/headers/body. Flag arg 0
    // conservatively — any credential-tainted Request is exfiltration.
    exists(DataFlow::MethodCallNode call |
      call.getMethodName() = "send" and
      node = call.getArg(0)
    )
    or
    // Module-level ``httpx.get(url, ...)`` etc. ``stream`` and ``send``
    // are not module-level helpers in httpx, so they're not modeled here.
    exists(DataFlow::CallCfgNode call, string method |
      method in ["get", "post", "put", "patch", "delete"] and
      call = API::moduleImport("httpx").getMember(method).getACall() and
      (
        node = call.getArg(0)
        or
        node = call.getArgByName("url")
        or
        node = httpxBodySideArg(call)
      )
    )
    or
    // Module-level ``httpx.request(method, url, ...)`` — same off-by-one
    // as the instance method.
    exists(DataFlow::CallCfgNode call |
      call = API::moduleImport("httpx").getMember("request").getACall() and
      (
        node = call.getArg(1)
        or
        node = call.getArgByName("url")
        or
        node = httpxBodySideArg(call)
      )
    )
  }

  /**
   * The httpx-specific keyword arguments that carry user-supplied data
   * regardless of whether the call uses a verb-specific helper or the
   * generic ``request``/``stream`` form.
   *
   * - ``params``: querystring assembly
   * - ``data``: form body (legitimate IdP target also passes through
   *   here; the ``CredLeak-UnknownHttp`` query sanitizes via
   *   ``KuauthAllowedHosts`` rather than excluding ``data`` here)
   * - ``json``: JSON body
   * - ``headers``: header values can carry credentials (Bearer, Basic,
   *   custom ``X-`` headers) and reach proxy/server access logs
   * - ``content``: raw body bytes/str
   */
  private DataFlow::Node httpxBodySideArg(DataFlow::CallCfgNode call) {
    result = call.getArgByName("params") or
    result = call.getArgByName("data") or
    result = call.getArgByName("json") or
    result = call.getArgByName("headers") or
    result = call.getArgByName("content")
  }
}
