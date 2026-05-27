import argparse
import json
import os

import verbose as verb
from verbose import vprint
from result import VerificationResult
from symbol_verifier import SymbolVerifier
from libdb_verifier import LibDBVerifier

def parse_gomod_direct_deps(gomod_path):
    direct = set()
    in_require = False
    with open(gomod_path) as f:
        for line in f:
            stripped = line.strip()
            if stripped.startswith("require ("):
                in_require = True
                continue
            if in_require and stripped == ")":
                in_require = False
                continue
            if in_require and stripped:
                parts = stripped.split()
                if len(parts) >= 2 and "// indirect" not in stripped:
                    direct.add(parts[0])
    return direct

def is_direct_dep(module_name, direct_deps):
    for dep in direct_deps:
        if module_name == dep or module_name.startswith(dep + "/") or dep.startswith(module_name + "/"):
            return True
    return False

def apply_direct_info(result, direct_deps):
    for m in result.modules:
        m.is_direct = is_direct_dep(m.name, direct_deps)

    direct_mods = [m for m in result.modules if m.is_direct]
    indirect_mods = [m for m in result.modules if not m.is_direct]

    result.total_direct = len(direct_mods)
    result.identified_direct = len([m for m in direct_mods if m.detected])
    result.percentage_direct = round(
        result.identified_direct / result.total_direct * 100, 1
    ) if result.total_direct > 0 else 0.0

    result.total_indirect = len(indirect_mods)
    result.identified_indirect = len([m for m in indirect_mods if m.detected])
    result.percentage_indirect = round(
        result.identified_indirect / result.total_indirect * 100, 1
    ) if result.total_indirect > 0 else 0.0

    result.has_direct_info = True

def print_result(result: VerificationResult):
    method_labels = {
        "symtab": "Symbol examination (ELF .symtab only)",
        "gopclntab": "Symbol examination (gopclntab only)",
        "symbol": "Symbol examination (symtab + gopclntab)",
        "libdb": "LibDB ML (GNN)",
    }
    method_label = method_labels.get(result.method, result.method)

    print()
    print("=" * 60)
    print(f"  Method:      {method_label}")
    print(f"  Mode:        {result.mode}")

    if result.mode == "discover":
        rule_label = (f"match_rate >= {result.match_threshold:g}%  "
                      f"AND name_matches >= {result.name_match_min}")
        if result.adaptive_fallback_used:
            rule_label += "   [ADAPTIVE FALLBACK \u2014 strict rule confirmed 0]"
        print(f"  Threshold:   {rule_label}")
        print(f"  Discovered:  {result.discovered_count}/{result.total_libs_in_db} "
              f"libraries (of those libdb knows)")
        if result.total_sbom_modules > 0:
            # Discovery + SBOM overlay
            print(f"  --- vs SBOM ({result.total_sbom_modules} declared modules, "
                  f"{result.sbom_outside_db} outside libdb's DB) ---")
            print(f"  TP={result.discovery_tp}  "
                  f"FP={result.discovery_fp}  "
                  f"FN={result.discovery_fn} (in-DB only)")
            print(f"  Precision:   {result.discovery_precision:.1%}")
            print(f"  Recall:      {result.discovery_recall:.1%}  "
                  f"(of in-DB SBOM modules)")
            print(f"  F1:          {result.discovery_f1:.1%}")
    else:
        # SBOM-iteration mode (legacy)
        print(f"  Threshold:   match_rate >= {result.match_threshold:g}%  "
              f"AND name_matches >= {result.name_match_min}")
        print(f"  Full SBOM:   {result.identified_count}/{result.total_sbom_modules} "
              f"({result.percentage}%)")
        if result.method == "libdb" and result.in_db_count > 0:
            print(f"  In-DB only:  {result.identified_count}/{result.in_db_count} "
                  f"({result.percentage_in_db}%)  "
                  f"[excludes {result.total_sbom_modules - result.in_db_count} "
                  f"libs not in DB]")

    if result.has_direct_info:
        print(f"  Direct only: {result.identified_direct}/{result.total_direct} "
              f"({result.percentage_direct}%)")
        print(f"  Indirect:    {result.identified_indirect}/{result.total_indirect} "
              f"({result.percentage_indirect}%)")
    print("=" * 60)

    # Per-module breakdown
    if result.mode == "discover":
        # Always show the discovered list (it IS the answer in discovery mode)
        if result.discovered:
            shown = result.discovered[:30] if not verb.VERBOSE else result.discovered
            print(f"\n  DISCOVERED ({len(result.discovered)}):")
            for d in shown:
                tag = "S" if d.in_sbom else " "   # S = also in SBOM
                print(f"    [{tag}] {d.name:50s} "
                      f"{d.match_rate:>5.1f}% "
                      f"({d.matched}/{d.total_lib_funcs}) "
                      f"name_matches={d.name_matches}")
            if not verb.VERBOSE and len(result.discovered) > 30:
                print(f"    ... and {len(result.discovered) - 30} more "
                      f"(use -v to show all)")
            print()

        # If SBOM provided, also show what we missed
        if verb.VERBOSE and result.total_sbom_modules > 0 and result.discovery_fn > 0:
            print(f"\n  MISSED \u2014 in SBOM, in-DB, but not discovered "
                  f"({result.discovery_fn}):")
            # In discovery mode, "missed" = SBOM libs we did NOT confirm.
            # We don't have them directly in `modules`, so we just note the count.
            print(f"    (run with --non-discovery-mode for the per-module list)")
        return

    # ---- SBOM-iteration mode rendering (legacy) ----
    if verb.VERBOSE:
        passed = [m for m in result.modules if m.detected]
        failed = [m for m in result.modules if not m.detected]

        if passed:
            print(f"\n  IDENTIFIED ({len(passed)}):")
            for m in passed:
                tag = "D" if m.is_direct else "I"
                vprint(f"    [{tag}] [PASS] {m.name}  \u2014 {m.detail}")

        if failed:
            print(f"\n  NOT IDENTIFIED ({len(failed)}):")
            for m in failed:
                tag = "D" if m.is_direct else "I"
                vprint(f"    [{tag}] [MISS] {m.name}  \u2014 {m.detail}")

        if result.unlisted:
            print(f"\n  UNLISTED \u2014 transitive dependencies ({len(result.unlisted)}):")
            for lib in result.unlisted[:20]:
                print(f"    [NEW]  {lib}")
            if len(result.unlisted) > 20:
                print(f"    ... and {len(result.unlisted) - 20} more")

        print()

def load_sbom(sbom_path):
    if not os.path.isfile(sbom_path):
        raise FileNotFoundError(f"SBOM file not found: {sbom_path}")

    with open(sbom_path) as f:
        data = json.load(f)

    # CycloneDX format: {"components": [{"name": "..."}, ...]}
    if isinstance(data, dict) and "components" in data:
        return [c.get("name", "") for c in data["components"] if c.get("name")]

    # SPDX JSON format: {"spdxVersion": "SPDX-2.x", "packages": [{"name": "...", ...}]}
    # Note: some vendors store SPDX JSON with a .cdx.json extension — detect by content.
    if isinstance(data, dict) and "spdxVersion" in data:
        packages = data.get("packages", [])
        return [p.get("name", "") for p in packages if p.get("name")]

    # Syft JSON format: {"artifacts": [{"name": "...", ...}]}
    if isinstance(data, dict) and "artifacts" in data:
        return [a.get("name", "") for a in data["artifacts"] if a.get("name")]

    # Simple JSON list: ["github_com_spf13_cobra", ...]
    if isinstance(data, list):
        return [str(item) for item in data if item]

    # Dict with library names as keys (last resort)
    if isinstance(data, dict):
        return list(data.keys())

    raise ValueError(f"Unrecognized SBOM format in {sbom_path}")

def main():
    parser = argparse.ArgumentParser(
        description="GoSBOMVerifier \u2014 SBOM verification for Go binaries",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--sbom",
                        help="Path to SBOM file (JSON). Required for --method symbol "
                             "and for --non-discovery-mode. Optional in libdb discovery "
                             "mode (enables a discovery-vs-SBOM overlay).")
    parser.add_argument("--method", required=True, choices=["symbol", "libdb"],
                        help="Verification method: 'symbol' or 'libdb'")
    parser.add_argument("--binary",
                        help="Path to Go binary (required for symbol method)")
    parser.add_argument("--symbol-source",
                        choices=["both", "symtab", "gopclntab"],
                        default="both",
                        help="Which source to examine when using --method symbol "
                             "(default: both). Use 'symtab' or 'gopclntab' to test "
                             "each extraction path individually.")
    parser.add_argument("--gomod",
                        help="Path to go.mod file to distinguish direct vs indirect "
                             "dependencies in results")
    parser.add_argument("--ghidra-json",
                        help="Path to Ghidra feature JSON (required for libdb method)")
    parser.add_argument("--model-path",
                        help="Path to LibDB model .pt file (optional, for libdb method)")
    parser.add_argument("--embeddings-dir",
                        help="Path to library embeddings directory (optional, for libdb method)")
    # libdb mode + tuning
    parser.add_argument("--non-discovery-mode", action="store_true",
                        help="(libdb only) Use legacy SBOM-iteration mode instead of "
                             "discovery mode. In SBOM mode each SBOM module is checked "
                             "individually; no false positives are possible.")
    parser.add_argument("--libdb-match-threshold", type=float, default=None,
                        help="(libdb only) Minimum match-rate %% to confirm a library. "
                             "Defaults: 65.0 in discovery mode, 30.0 in SBOM mode.")
    parser.add_argument("--libdb-name-match-min", type=int, default=None,
                        help="(libdb only) Minimum number of literal function-name "
                             "matches required to confirm a library. Defaults: 1 in "
                             "discovery mode, 0 in SBOM mode.")
    parser.add_argument("--libdb-no-adaptive", action="store_true",
                        help="(libdb discovery only) Disable the name-free "
                             "fallback that triggers when the primary rule "
                             "confirms 0 libraries (default: enabled).")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Enable verbose output (for testing)")
    parser.add_argument("--output", "-o",
                        help="Save results to JSON file")
    args = parser.parse_args()

    # Set verbose flag
    verb.VERBOSE = args.verbose

    # method-specific arguments
    if args.method == "symbol" and not args.binary:
        parser.error("--binary is required when using --method symbol")
    if args.method == "libdb" and not args.ghidra_json:
        parser.error("--ghidra-json is required when using --method libdb")
    if args.method == "symbol" and not args.sbom:
        parser.error("--sbom is required when using --method symbol")
    if args.method == "libdb" and args.non_discovery_mode and not args.sbom:
        parser.error("--sbom is required when using --non-discovery-mode")

    # Load SBOM (optional for libdb in discovery mode)
    print("GoSBOMVerifier")

    sbom_modules = None
    if args.sbom:
        sbom_modules = load_sbom(args.sbom)
        print(f"SBOM loaded: {len(sbom_modules)} modules")
        vprint(f"SBOM modules: {sbom_modules}")

    # Load direct deps from go.mod if provided
    direct_deps = None
    if args.gomod:
        if not os.path.isfile(args.gomod):
            parser.error(f"go.mod not found: {args.gomod}")
        direct_deps = parse_gomod_direct_deps(args.gomod)
        vprint(f"Direct deps from go.mod: {len(direct_deps)}")

    # Run selected method
    if args.method == "symbol":
        verifier = SymbolVerifier(args.binary, source=args.symbol_source)
        result = verifier.verify(sbom_modules)
    elif args.method == "libdb":
        verifier = LibDBVerifier(
            args.ghidra_json,
            model_path=args.model_path,
            embeddings_dir=args.embeddings_dir,
            match_threshold=args.libdb_match_threshold,
            name_match_min=args.libdb_name_match_min,
            adaptive=not args.libdb_no_adaptive,
        )
        if args.non_discovery_mode:
            # Legacy: iterate the SBOM, ask "is each module here?"
            result = verifier.verify(sbom_modules)
        else:
            # Default: discover everything libdb knows; overlay against SBOM if given.
            result = verifier.discover(sbom_modules)

    # Apply direct/indirect classification if go.mod was provided
    if direct_deps is not None:
        apply_direct_info(result, direct_deps)

    print_result(result)

    # Save JSON output
    if args.output:
        output = {
            "method": result.method,
            "mode":   result.mode,
            "sbom_file": args.sbom,
            "modules": [
                {
                    "name": m.name,
                    "detected": m.detected,
                    "confidence": m.confidence,
                    "detail": m.detail,
                    "is_direct": m.is_direct,
                }
                for m in result.modules
            ],
        }
        # Always write the SBOM-perspective summary fields if populated
        # (they ARE populated in discovery mode when an SBOM was provided).
        output["total_sbom_modules"] = result.total_sbom_modules
        output["identified_count"]   = result.identified_count
        output["percentage"]         = result.percentage
        output["not_identified"]     = result.not_identified
        output["unlisted"]           = result.unlisted
        if result.method == "libdb":
            output["in_db"] = {
                "total": result.in_db_count,
                "identified": result.identified_count,
                "percentage": result.percentage_in_db,
            }
            output["match_threshold"] = result.match_threshold
            output["name_match_min"]  = result.name_match_min

        # Discovery-mode-specific block (extra metadata, not strictly needed
        # for compile_results' TP/FP/FN math but useful for inspection).
        if result.mode == "discover":
            output["discovery"] = {
                "match_threshold":        result.match_threshold,
                "name_match_min":         result.name_match_min,
                "adaptive_fallback_used": result.adaptive_fallback_used,
                "total_libs_in_db":       result.total_libs_in_db,
                "discovered_count":       result.discovered_count,
                "discovered": [
                    {
                        "name": d.name,
                        "match_rate": d.match_rate,
                        "matched": d.matched,
                        "total_lib_funcs": d.total_lib_funcs,
                        "name_matches": d.name_matches,
                        "in_sbom": d.in_sbom,
                    }
                    for d in result.discovered
                ],
            }
            if result.total_sbom_modules > 0:
                output["discovery"]["vs_sbom"] = {
                    "total_sbom_modules": result.total_sbom_modules,
                    "sbom_outside_db":    result.sbom_outside_db,
                    "TP": result.discovery_tp,
                    "FP": result.discovery_fp,
                    "FN": result.discovery_fn,
                    "precision": result.discovery_precision,
                    "recall":    result.discovery_recall,
                    "f1":        result.discovery_f1,
                }
        if result.has_direct_info:
            output["direct"] = {
                "total": result.total_direct,
                "identified": result.identified_direct,
                "percentage": result.percentage_direct,
            }
            output["indirect"] = {
                "total": result.total_indirect,
                "identified": result.identified_indirect,
                "percentage": result.percentage_indirect,
            }
        with open(args.output, "w") as f:
            json.dump(output, f, indent=2)
        print(f"Results saved to: {args.output}")

if __name__ == "__main__":
    main()
