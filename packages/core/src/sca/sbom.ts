import type { Dependency } from "./types.js";

interface CycloneDxComponent {
  type: "library";
  "bom-ref": string;
  name: string;
  version: string;
  purl: string;
  licenses?: { license: { id: string } }[];
  scope?: "required" | "optional" | "excluded";
}

interface CycloneDxBom {
  bomFormat: "CycloneDX";
  specVersion: "1.5";
  serialNumber: string;
  version: 1;
  metadata: {
    timestamp: string;
    tools: { vendor: string; name: string; version: string }[];
    component?: { type: "application"; name: string };
  };
  components: CycloneDxComponent[];
}

/** Build a PURL (Package URL) from a dependency */
function buildPurl(dep: Dependency): string {
  const { ecosystem, name, version } = dep;
  switch (ecosystem) {
    case "npm": {
      // Scoped packages: pkg:npm/%40scope/name@version
      const encoded = name.startsWith("@")
        ? `%40${name.slice(1)}`
        : name;
      return `pkg:npm/${encoded}@${version}`;
    }
    case "PyPI":
      return `pkg:pypi/${name.toLowerCase()}@${version}`;
    case "Go":
      return `pkg:golang/${name}@${version}`;
    case "crates.io":
      return `pkg:cargo/${name}@${version}`;
    default:
      return `pkg:generic/${name}@${version}`;
  }
}

/**
 * Generate a CycloneDX 1.5 SBOM JSON from parsed dependencies.
 */
export function generateCycloneDxSbom(
  dependencies: Dependency[],
  projectName?: string
): CycloneDxBom {
  const components: CycloneDxComponent[] = dependencies.map((dep) => {
    const purl = buildPurl(dep);
    const comp: CycloneDxComponent = {
      type: "library",
      "bom-ref": purl,
      name: dep.name,
      version: dep.version,
      purl,
    };
    if (dep.license) {
      comp.licenses = [{ license: { id: dep.license } }];
    }
    if (dep.dev) {
      comp.scope = "excluded";
    }
    return comp;
  });

  return {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    serialNumber: `urn:uuid:${crypto.randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [{ vendor: "Vexlit", name: "Vexlit SCA", version: "1.0.0" }],
      ...(projectName
        ? { component: { type: "application" as const, name: projectName } }
        : {}),
    },
    components,
  };
}
