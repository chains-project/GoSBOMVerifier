import json
import os
import sys
import time

import numpy as np
import torch

from verifier_base import SBOMVerifier
from result import VerificationResult, ModuleResult, DiscoveredLib
from verbose import vprint

# Set up imports for LibDB dependencies
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "lib", "libdb"))

import importlib.util
_spec = importlib.util.spec_from_file_location(
    "verify_sbom_libdb",
    os.path.join(HERE, "lib", "verify_sbom_libdb.py")
)
_libdb = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_libdb)

DEFAULT_DISCOVERY_THRESHOLD = 65.0
DEFAULT_DISCOVERY_NAME_MIN  = 1
DEFAULT_SBOM_THRESHOLD      = _libdb.CONFIRM_THRESHOLD  
DEFAULT_SBOM_NAME_MIN       = 0

# Adaptive fallback: if the strict rule confirms ZERO libraries, retry with the same match-rate threshold but with the name-match requirement dropped.
ADAPTIVE_FALLBACK_THRESHOLD = 65.0
ADAPTIVE_FALLBACK_NAME_MIN  = 0


class LibDBVerifier(SBOMVerifier):
    def __init__(self, ghidra_json_path, model_path=None, embeddings_dir=None,
                 match_threshold=None, name_match_min=None,
                 adaptive=True):
        
        if not os.path.isfile(ghidra_json_path):
            raise FileNotFoundError(f"Ghidra JSON not found: {ghidra_json_path}")

        self.ghidra_json_path = ghidra_json_path

        self.model_path     = model_path     or _libdb.MODEL_PATH
        self.embeddings_dir = embeddings_dir or _libdb.EMBEDDINGS_DIR
        self.index_path     = os.path.join(self.embeddings_dir, "index.json")

        self._match_threshold_override = match_threshold
        self._name_match_min_override  = name_match_min
        self.adaptive = adaptive

        _libdb.MODEL_PATH     = self.model_path
        _libdb.EMBEDDINGS_DIR = self.embeddings_dir
        _libdb.INDEX_PATH     = self.index_path

        self._net           = None
        self._target_vecs   = None
        self._target_names  = None
        self._lib_index     = None

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    def _load(self):
        if self._net is not None:
            return

        if not os.path.isfile(self.index_path):
            raise FileNotFoundError(
                f"Library index not found at {self.index_path}. "
                f"Run 10_precompute_library_embeddings.py first."
            )

        with open(self.index_path) as f:
            self._lib_index = json.load(f)
        vprint(f"Library database: {len(self._lib_index)} libraries")

        vprint(f"Loading model from {self.model_path}")
        self._net = _libdb.func2vec(
            self.model_path, gpu=torch.cuda.is_available(), fea_dim=7
        )

        vprint(f"Loading target binary: {self.ghidra_json_path}")
        target_funcs = _libdb.load_binary_functions(self.ghidra_json_path)
        vprint(f"Total functions in binary: {len(target_funcs)}")

        stdlib_count = sum(1 for n in target_funcs if _libdb.is_stdlib_func(n))
        vprint(f"Stdlib/runtime functions: {stdlib_count}")
        vprint(f"Non-stdlib functions: {len(target_funcs) - stdlib_count}")

        vprint("Generating embeddings for target binary...")
        t0 = time.time()
        target_emb = _libdb.generate_embeddings(self._net, target_funcs)
        vprint(f"Generated {len(target_emb)} embeddings in {time.time()-t0:.1f}s")

        self._target_names = list(target_emb.keys())
        self._target_vecs = np.array(
            [target_emb[n] for n in self._target_names], dtype=np.float32
        )

    def _match_single_lib(self, lib_name):
        lib_vecs, lib_func_names, _ = _libdb.load_library_embeddings(lib_name)
        if lib_vecs is None:
            return None
        result = _libdb.match_library(
            lib_vecs, lib_func_names, self._target_vecs, self._target_names
        )
        result["library"] = lib_name
        result["readable_name"] = _libdb.format_lib_name(lib_name)
        return result

    @staticmethod
    def _sbom_to_libdb_name(sbom_name):
        if '/' in sbom_name or '.' in sbom_name:
            return sbom_name.replace('/', '_').replace('.', '_')
        return sbom_name

    @staticmethod
    def _libdb_to_sbom_name(libdb_name):
        return libdb_name

    def _resolve_thresholds(self, mode):
        if mode == "discover":
            t = (self._match_threshold_override
                 if self._match_threshold_override is not None
                 else DEFAULT_DISCOVERY_THRESHOLD)
            n = (self._name_match_min_override
                 if self._name_match_min_override is not None
                 else DEFAULT_DISCOVERY_NAME_MIN)
        else:   # "sbom"
            t = (self._match_threshold_override
                 if self._match_threshold_override is not None
                 else DEFAULT_SBOM_THRESHOLD)
            n = (self._name_match_min_override
                 if self._name_match_min_override is not None
                 else DEFAULT_SBOM_NAME_MIN)
        return float(t), int(n)

    # ------------------------------------------------------------------
    # Discovery mode (default)
    # -----------------------------------------------------------------

    def _scan_all_libs(self, sbom_libdb_keys):
        all_libs = list(self._lib_index.keys()
                        if isinstance(self._lib_index, dict)
                        else self._lib_index)
        raw = []
        for lib_name in all_libs:
            r = self._match_single_lib(lib_name)
            if r is None:
                continue
            raw.append({
                "lib":             lib_name,
                "match_rate":      float(r["match_rate"]),
                "name_matches":    int(r.get("name_matches", 0)),
                "matched":         int(r["matched"]),
                "total_lib_funcs": int(r["total_lib_funcs"]),
                "in_sbom":         lib_name in sbom_libdb_keys,
            })
        return raw, len(all_libs)

    @staticmethod
    def _apply_rule(raw, threshold, name_min):
        per_lib_raw = []
        discovered = []
        for x in raw:
            mr  = x["match_rate"]
            nm  = x["name_matches"]
            mt  = x["matched"]
            tot = x["total_lib_funcs"]
            in_sbom = x["in_sbom"]
            confirmed = (mr >= threshold) and (nm >= name_min)
            per_lib_raw.append((x["lib"], confirmed, in_sbom, mr, nm, mt, tot))
            if confirmed:
                discovered.append(DiscoveredLib(
                    name=x["lib"], match_rate=mr, matched=mt,
                    total_lib_funcs=tot, name_matches=nm, in_sbom=in_sbom,
                ))
        return per_lib_raw, discovered

    def discover(self, sbom_modules: list = None) -> VerificationResult:
        self._load()
        threshold, name_min = self._resolve_thresholds("discover")

        sbom_libdb_keys = (
            {self._sbom_to_libdb_name(m) for m in sbom_modules}
            if sbom_modules else set()
        )

        raw, total_libs = self._scan_all_libs(sbom_libdb_keys)
        vprint(f"Discovery sweep over {total_libs} libraries "
               f"(primary rule: threshold={threshold}%, name_min={name_min})")

        per_lib_raw, discovered = self._apply_rule(raw, threshold, name_min)

        # ---- Adaptive fallback (option C) ----
        adaptive_used = False
        if (self.adaptive
                and not discovered
                and (threshold > ADAPTIVE_FALLBACK_THRESHOLD
                     or name_min > ADAPTIVE_FALLBACK_NAME_MIN)):
            vprint(f"  [adaptive] primary rule confirmed 0 libs; falling back "
                   f"to threshold={ADAPTIVE_FALLBACK_THRESHOLD}%, "
                   f"name_min={ADAPTIVE_FALLBACK_NAME_MIN}")
            per_lib_raw, discovered = self._apply_rule(
                raw, ADAPTIVE_FALLBACK_THRESHOLD, ADAPTIVE_FALLBACK_NAME_MIN)
            threshold = ADAPTIVE_FALLBACK_THRESHOLD
            name_min  = ADAPTIVE_FALLBACK_NAME_MIN
            adaptive_used = True

        for d in discovered:
            vprint(f"  [FOUND] {d.name} \u2014 {d.matched}/{d.total_lib_funcs} "
                   f"({d.match_rate:.1f}%), {d.name_matches} name-confirmed")

        all_libs = [r["lib"] for r in raw]

        result = VerificationResult(
            method="libdb",
            mode="discover",
            total_libs_in_db=len(all_libs),
            discovered_count=len(discovered),
            discovered=discovered,
            match_threshold=threshold,
            name_match_min=name_min,
            adaptive_fallback_used=adaptive_used,
        )

        if sbom_modules is None:
            result.modules = [
                ModuleResult(
                    name=d.name,
                    detected=True,
                    confidence=d.match_rate / 100.0,
                    detail=(f"{d.matched}/{d.total_lib_funcs} funcs "
                            f"({d.match_rate:.1f}%), "
                            f"{d.name_matches} name-matches"),
                )
                for d in sorted(discovered, key=lambda x: -x.match_rate)
            ]
            return result

        discovered_by_name = {d.name: d for d in discovered}
        per_lib_keys = {ll for ll, *_ in per_lib_raw}

        modules = []
        for sbom_name in sbom_modules:
            lkey = self._sbom_to_libdb_name(sbom_name)
            if lkey not in per_lib_keys:
                modules.append(ModuleResult(
                    name=sbom_name,
                    detected=False,
                    confidence=0.0,
                    detail="Not in library database",
                ))
                continue
            d = discovered_by_name.get(lkey)
            if d is not None:
                # Confirmed (TP)
                modules.append(ModuleResult(
                    name=sbom_name,
                    detected=True,
                    confidence=d.match_rate / 100.0,
                    detail=(f"{d.matched}/{d.total_lib_funcs} funcs "
                            f"({d.match_rate:.1f}%), "
                            f"{d.name_matches} name-matches"),
                ))
            else:
                # In libdb's DB but not confirmed (FN)
                # Find the per-lib row to report the actual match-rate it got
                row = next((r for r in per_lib_raw if r[0] == lkey), None)
                if row:
                    _, _, _, mr, nm, mt, tot = row
                    modules.append(ModuleResult(
                        name=sbom_name,
                        detected=False,
                        confidence=mr / 100.0,
                        detail=(f"Below threshold: {mt}/{tot} funcs "
                                f"({mr:.1f}%), {nm} name-matches "
                                f"[need >= {threshold}% AND >= {name_min} names]"),
                    ))
                else:
                    modules.append(ModuleResult(
                        name=sbom_name,
                        detected=False,
                        confidence=0.0,
                        detail="Below threshold",
                    ))

        # FPs 
        unlisted = [d.name for d in discovered if not d.in_sbom]

        result.modules  = modules
        result.unlisted = unlisted

        in_db = sum(1 for k in sbom_libdb_keys if k in per_lib_keys)
        outside_db = len(sbom_libdb_keys) - in_db

        tp = sum(1 for _, conf, in_s, *_ in per_lib_raw if conf and in_s)
        fp = sum(1 for _, conf, in_s, *_ in per_lib_raw if conf and not in_s)
        fn = sum(1 for _, conf, in_s, *_ in per_lib_raw if not conf and in_s)
        prec = tp / (tp + fp) if (tp + fp) else 0.0
        rec  = tp / (tp + fn) if (tp + fn) else 0.0
        f1   = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0

        result.discovery_tp = tp
        result.discovery_fp = fp
        result.discovery_fn = fn
        result.discovery_precision = round(prec, 4)
        result.discovery_recall    = round(rec,  4)
        result.discovery_f1        = round(f1,   4)
        result.total_sbom_modules  = len(sbom_modules)
        result.sbom_outside_db     = outside_db
    
        result.identified_count    = sum(1 for m in modules if m.detected)
        result.percentage          = round(
            (result.identified_count / len(sbom_modules) * 100)
            if sbom_modules else 0.0, 1)
        in_db_count = sum(1 for m in modules
                          if m.detail != "Not in library database")
        result.in_db_count       = in_db_count
        result.percentage_in_db  = round(
            (result.identified_count / in_db_count * 100)
            if in_db_count else 0.0, 1)
        result.not_identified    = [m.name for m in modules if not m.detected]

        return result

    # ------------------------------------------------------------------
    # SBOM-iteration mode (legacy)
    # ------------------------------------------------------------------

    def verify(self, sbom_modules: list) -> VerificationResult:
        """Legacy SBOM-iteration mode (use --non-discovery-mode in the CLI).

        For each module in the SBOM, ask libdb whether it's present.
        Cannot produce false positives by construction.
        """
        self._load()
        threshold, name_min = self._resolve_thresholds("sbom")

        confirmed     = []
        not_confirmed = []
        not_in_db     = []
        per_module    = []

        for sbom_name in sbom_modules:
            lib_name = self._sbom_to_libdb_name(sbom_name)
            r = self._match_single_lib(lib_name)
            if r is None:
                not_in_db.append(sbom_name)
                vprint(f"  [????] {sbom_name} \u2014 not in library database")
                per_module.append((sbom_name, False, "Not in library database",
                                   0.0))
                continue

            mr  = float(r["match_rate"])
            nm  = int(r.get("name_matches", 0))
            mt  = int(r["matched"])
            tot = int(r["total_lib_funcs"])
            ok  = (mr >= threshold) and (nm >= name_min)

            detail = (f"{mt}/{tot} funcs ({mr:.1f}%), "
                      f"{nm} name-matches "
                      f"[threshold={threshold}%, name_min={name_min}]")
            per_module.append((sbom_name, ok, detail, mr / 100.0))

            if ok:
                confirmed.append(sbom_name)
                vprint(f"  [PASS] {sbom_name} \u2014 {detail}")
            else:
                not_confirmed.append(sbom_name)
                vprint(f"  [FAIL] {sbom_name} \u2014 {detail}")

        modules = [
            ModuleResult(name=name, detected=ok, confidence=conf, detail=detail)
            for name, ok, detail, conf in per_module
        ]

        total_sbom  = len(sbom_modules)
        in_db_count = len(confirmed) + len(not_confirmed)
        identified  = len(confirmed)
        pct_full = (identified / total_sbom  * 100) if total_sbom  else 0.0
        pct_indb = (identified / in_db_count * 100) if in_db_count else 0.0

        return VerificationResult(
            method="libdb",
            mode="sbom",
            total_sbom_modules=total_sbom,
            identified_count=identified,
            not_identified=not_confirmed + not_in_db,
            percentage=round(pct_full, 1),
            modules=modules,
            unlisted=[],
            in_db_count=in_db_count,
            percentage_in_db=round(pct_indb, 1),
            match_threshold=threshold,
            name_match_min=name_min,
        )
