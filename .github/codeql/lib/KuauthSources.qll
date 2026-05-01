/**
 * Shared model of credential-bearing values inside the kuauth library.
 *
 * The ``KyotoUAuth`` class is the single root of trust: it stores
 * ``username`` / ``password`` / ``_totp_secret`` / ``_onetime_password`` /
 * ``_otp_callback`` and exposes the OTP resolution helper
 * ``_resolve_otp()``. Every other module reaches credentials via one of
 * these named accessors. Pinning the source set on these names keeps the
 * surface narrow and stable — adding a new source should require a
 * deliberate edit here, not a rename in another file.
 *
 * ``username`` is intentionally NOT a source. It's already shared with
 * the IdP in URL-resolvable form (EPPN), and treating it as taint would
 * dilute precision without adding meaningful protection.
 *
 * ``__init__`` parameter values are not modeled separately because every
 * realistic flow into a sink goes through ``self._password`` (etc.)
 * after construction, which is already covered by the attribute-read
 * source. Modeling the parameter directly would add complexity without
 * catching realistic leaks.
 */

import python
import semmle.python.dataflow.new.DataFlow

module KuauthSources {
  /**
   * Holds for nodes that read a credential-bearing attribute by name.
   *
   * Covers both the public read-only property (``auth.password``) and
   * the private backing attributes (``self._password``,
   * ``self._totp_secret``, ``self._onetime_password``). The
   * ``_otp_callback`` attribute is NOT itself a source — only the value
   * returned by *calling* it (handled by ``isOtpCallableInvocation``).
   *
   * The predicate matches the attribute *name* rather than the receiver
   * type. The names ``_password`` / ``_totp_secret`` /
   * ``_onetime_password`` are leading-underscore private attributes that
   * are extremely unlikely to collide with unrelated objects in normal
   * Python code; the unprefixed ``password`` is more common but in this
   * codebase it only resolves to ``KyotoUAuth.password``.
   */
  predicate isCredentialAttributeRead(DataFlow::Node node) {
    exists(string name |
      name in [
          "password", "_password",
          "_totp_secret",
          "_onetime_password"
        ] and
      node.(DataFlow::AttrRead).getAttributeName() = name
    )
  }

  /**
   * Holds for the result of calling ``_resolve_otp()`` on any object.
   *
   * The method only exists on ``KyotoUAuth`` and exclusively returns a
   * fresh OTP string (either pre-set, pyotp-derived, or callback-derived),
   * so its return value is always credential-grade.
   */
  predicate isResolveOtpCall(DataFlow::Node node) {
    node.(DataFlow::MethodCallNode).getMethodName() = "_resolve_otp"
  }

  /**
   * Holds for the result of invoking ``self._otp_callback()``.
   *
   * The callback's return is the live OTP code, indistinguishable in
   * sensitivity from ``_resolve_otp``'s return.
   */
  predicate isOtpCallableInvocation(DataFlow::Node node) {
    exists(DataFlow::CallCfgNode call, DataFlow::AttrRead attr |
      attr.getAttributeName() = "_otp_callback" and
      call.getFunction() = attr and
      node = call
    )
  }

  /** Holds for any node that originates a credential value. */
  predicate isSource(DataFlow::Node node) {
    isCredentialAttributeRead(node) or
    isResolveOtpCall(node) or
    isOtpCallableInvocation(node)
  }
}
