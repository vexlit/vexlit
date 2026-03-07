export { isDependencyFile, parseDependencies, DEPENDENCY_FILES } from "./parser.js";
export { queryOsv } from "./osv.js";
export { scaDependencies } from "./engine.js";
export type { ScaResult } from "./engine.js";
export type { Dependency, Advisory, ScaDependencyResult, DepGraph } from "./types.js";
export { generateCycloneDxSbom } from "./sbom.js";
export { analyzeLicenses, classifyLicense } from "./license.js";
export type { LicenseRisk } from "./license.js";
export { analyzeReachability } from "./reachability.js";
