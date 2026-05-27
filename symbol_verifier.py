import os
import re
import sys

# Make lib/ importable
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))

from go_symbol_analysis import (
    extract_function_packages_from_symtab,
    extract_function_packages_from_gopclntab,
    extract_go_version,
    is_stdlib_package,
    packages_to_modules,
    verify_sbom,
)

from verifier_base import SBOMVerifier
from result import VerificationResult, ModuleResult
from verbose import vprint

VALID_SOURCES = ("both", "symtab", "gopclntab")

class SymbolVerifier(SBOMVerifier):
    def __init__(self, binary_path, source="both"):
        if not os.path.isfile(binary_path):
            raise FileNotFoundError(f"Binary not found: {binary_path}")
        if source not in VALID_SOURCES:
            raise ValueError(
                f"Invalid source {source!r}; expected one of {VALID_SOURCES}")
        self.binary_path = binary_path
        self.source = source
        self._data = None
        self._modules = None
        # Populated by _load() so callers can inspect each source separately.
        self._symtab_modules = None
        self._gopclntab_modules = None

    @staticmethod
    def _packages_to_filtered_modules(packages):
        third_party = [p for p in packages if not is_stdlib_package(p)]
        raw_modules = packages_to_modules(third_party)

        filtered = []
        for mod in raw_modules:
            if '%2f' in mod:
                continue
            if '.html' in mod or '.htm' in mod or '/docs/' in mod:
                continue
            if mod.startswith('www.'):
                continue
            if mod.startswith('gopkg.in/') and not re.search(r'\.v\d+$', mod):
                continue
            filtered.append(mod)
        return sorted(set(filtered))

    def examine_symtab(self):
        self._read_binary()
        packages = extract_function_packages_from_symtab(self._data)
        modules = self._packages_to_filtered_modules(packages)
        self._symtab_modules = modules
        vprint(f"  [symtab]    packages={len(packages)} modules={len(modules)}")
        return modules

    def examine_gopclntab(self):
        self._read_binary()
        packages = extract_function_packages_from_gopclntab(self._data)
        modules = self._packages_to_filtered_modules(packages)
        self._gopclntab_modules = modules
        vprint(f"  [gopclntab] packages={len(packages)} modules={len(modules)}")
        return modules

    def _read_binary(self):
        if self._data is not None:
            return
        vprint(f"Reading binary: {self.binary_path}")
        with open(self.binary_path, "rb") as f:
            self._data = f.read()
        size_mb = len(self._data) / (1024 * 1024)
        go_version = extract_go_version(self._data)
        vprint(f"Binary size: {size_mb:.1f} MB")
        vprint(f"Go version: {go_version or 'Unknown'}")

    def _load(self):
        if self._modules is not None:
            return
        self._read_binary()

        if self.source == "symtab":
            self._modules = self.examine_symtab()
        elif self.source == "gopclntab":
            self._modules = self.examine_gopclntab()
        else:  # "both"
            sym_mods = self.examine_symtab()
            pcl_mods = self.examine_gopclntab()
            self._modules = sorted(set(sym_mods) | set(pcl_mods))

        vprint(f"Modules detected ({self.source}): {len(self._modules)}")

    def verify(self, sbom_modules: list) -> VerificationResult:
        self._load()

        confirmed, not_detected, unlisted = verify_sbom(self._modules, sbom_modules)

        sym_set = set(self._symtab_modules or [])
        pcl_set = set(self._gopclntab_modules or [])

        def _source_for(mod):
            in_sym = mod in sym_set
            in_pcl = mod in pcl_set
            if in_sym and in_pcl:
                return "symtab + gopclntab"
            if in_sym:
                return "symtab"
            if in_pcl:
                return "gopclntab"
            return self.source  # fallback when only one source was consulted

        # Build per-module results
        modules = []
        for lib in confirmed:
            modules.append(ModuleResult(
                name=lib,
                detected=True,
                confidence=1.0,
                detail=f"Found in {_source_for(lib)}",
            ))
        for lib in not_detected:
            modules.append(ModuleResult(
                name=lib,
                detected=False,
                confidence=0.0,
                detail="No function names found",
            ))

        total = len(sbom_modules)
        identified = len(confirmed)
        pct = (identified / total * 100) if total > 0 else 0.0

        return VerificationResult(
            method="symbol",
            total_sbom_modules=total,
            identified_count=identified,
            not_identified=not_detected,
            percentage=round(pct, 1),
            modules=modules,
            unlisted=unlisted,
        )
