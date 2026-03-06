import { Rule } from "../types.js";
import { hardcodedSecretsRule } from "./hardcoded-secrets.js";
import { sqlInjectionRule } from "./sql-injection.js";
import { xssRule } from "./xss.js";
import { insecureCryptoRule } from "./insecure-crypto.js";
import { unsafeFileAccessRule } from "./unsafe-file-access.js";
import { openRedirectRule } from "./open-redirect.js";
import { jwtHardcodedSecretRule } from "./jwt-hardcoded-secret.js";
import { jwtNoneAlgorithmRule } from "./jwt-none-algorithm.js";
import { functionConstructorRule } from "./function-constructor.js";
import { prototypePollutionRule } from "./prototype-pollution.js";
import { nosqlInjectionRule } from "./nosql-injection.js";
import { ssrfRule } from "./ssrf.js";
import { insecureCookieRule } from "./insecure-cookie.js";
import { corsMisconfigurationRule } from "./cors-misconfiguration.js";
import { redosRule } from "./redos.js";
import { infoExposureRule } from "./info-exposure.js";
import { insecureTlsRule } from "./insecure-tls.js";
import { timingAttackRule } from "./timing-attack.js";
import { debuggerStatementRule } from "./debugger-statement.js";
import { unsafeDeserializationRule } from "./unsafe-deserialization.js";
import { pathTraversalRule } from "./path-traversal.js";
import { commandInjectionRule } from "./command-injection.js";
import { evalInjectionRule } from "./eval-injection.js";

export const allRules: Rule[] = [
  hardcodedSecretsRule,
  sqlInjectionRule,
  xssRule,
  insecureCryptoRule,
  // VEXLIT-005 deprecated — replaced by VEXLIT-021 (Path Traversal) + VEXLIT-022 (Command Injection)
  openRedirectRule,
  jwtHardcodedSecretRule,
  jwtNoneAlgorithmRule,
  functionConstructorRule,
  prototypePollutionRule,
  nosqlInjectionRule,
  ssrfRule,
  insecureCookieRule,
  corsMisconfigurationRule,
  redosRule,
  infoExposureRule,
  insecureTlsRule,
  timingAttackRule,
  debuggerStatementRule,
  unsafeDeserializationRule,
  pathTraversalRule,
  commandInjectionRule,
  evalInjectionRule,
  unsafeFileAccessRule,
];

export {
  hardcodedSecretsRule,
  sqlInjectionRule,
  xssRule,
  insecureCryptoRule,
  unsafeFileAccessRule,
  openRedirectRule,
  jwtHardcodedSecretRule,
  jwtNoneAlgorithmRule,
  functionConstructorRule,
  prototypePollutionRule,
  nosqlInjectionRule,
  ssrfRule,
  insecureCookieRule,
  corsMisconfigurationRule,
  redosRule,
  infoExposureRule,
  insecureTlsRule,
  timingAttackRule,
  debuggerStatementRule,
  unsafeDeserializationRule,
  pathTraversalRule,
  commandInjectionRule,
  evalInjectionRule,
};
