import json
import os
import sys
import numpy as np
import torch

sys.path.insert(0, os.path.join(os.path.dirname(__file__),
    "..", "LibDB-main", "main", "torch"))

from func2vec import func2vec

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(SCRIPT_DIR, "go_model", "saved_model", "model-inter-best.pt")
EMBEDDINGS_DIR = os.path.join(SCRIPT_DIR, "library_embeddings")
INDEX_PATH = os.path.join(EMBEDDINGS_DIR, "index.json")

MIN_NODES = 5
MATCH_THRESHOLD = 0.85      # Cosine similarity for a function match
CONFIRM_THRESHOLD = 30.0    # % of library functions matched to confirm presence
# Go standard library, runtime, and extended stdlib prefixes to exclude.
GO_STDLIB_PREFIXES = [
    # Core runtime and compiler intrinsics
    "runtime.", "runtime/", "sync.", "sync/",
    "cmpbody", "memeq", "memcmp", "memhash",
    "indexbyte", "gogo", "aeshash", "duff",
    "type:",
    "go.buildid", "go.itab.", "go.info.", "go.shape.",  # Go compiler internals (NOT go.uber.org etc.)
    "go/",          # go/token, go/ast, etc. (stdlib)
    "FUN_",
    # Standard library packages
    "fmt.", "fmt/", "os.", "os/", "io.", "io/", "net.", "net/",
    "math.", "math/", "strings.", "strconv.", "bytes.", "bufio.",
    "sort.", "path.", "path/", "errors.", "context.", "time.",
    "reflect.", "unicode.", "unicode/",
    "encoding.", "encoding/",
    "crypto.", "crypto/",
    "hash.", "hash/",
    "compress.", "compress/",
    "archive.", "archive/",
    "regexp.", "regexp/",
    "log.", "log/",
    "flag.", "testing.", "debug.",
    "syscall.", "internal.", "internal/",
    # Extended stdlib (golang.org/x/*)
    "golang.org/x/",
    # Vendored stdlib copies
    "vendor/",
    # Other stdlib packages
    "text/", "text.",
    "html.", "html/",
    "image.", "image/",
    "mime.", "mime/",
    "database/", "database.",
    "slices.", "unique.", "weak.", "maps.",
]

GO_TRIVIAL_SUFFIXES = [
    ".init", ".init.0", ".init.1",
    ".deferwrap1", ".deferwrap2", ".deferwrap3",
]

def is_stdlib_func(name):
    for prefix in GO_STDLIB_PREFIXES:
        if name.startswith(prefix):
            return True
    for suffix in GO_TRIVIAL_SUFFIXES:
        if name.endswith(suffix):
            return True
    return False

def load_binary_functions(json_path):
    with open(json_path, "r", errors="ignore") as f:
        content = json.load(f)
    if isinstance(content, dict):
        content = [content]

    functions = {}
    for bf in content:
        if "binFileFeature" not in bf:
            continue
        for func in bf["binFileFeature"]["functions"]:
            if func.get("nodes", 0) < MIN_NODES:
                continue
            if func.get("isThunkFunction", False):
                continue
            if "text" not in func.get("memoryBlock", ""):
                continue
            name = func.get("functionName", "unknown")
            functions[name] = func
    return functions

def generate_embeddings(net, functions):
    embeddings = {}
    for name, func in functions.items():
        try:
            vec = net.get_embedding_from_func_fea(func, correct_edges=True)
            if isinstance(vec, torch.Tensor):
                vec = vec.cpu().detach().numpy()
            norm = np.linalg.norm(vec)
            if norm > 0:
                vec = vec / norm
            embeddings[name] = vec
        except Exception:
            pass
    return embeddings

def load_library_embeddings(lib_name):
    path = os.path.join(EMBEDDINGS_DIR, f"{lib_name}.npz")
    if not os.path.isfile(path):
        return None, None, None
    data = np.load(path, allow_pickle=True)
    embeddings = data["embeddings"]
    func_names = list(data["func_names"])
    metadata = json.loads(str(data["metadata"]))
    return embeddings, func_names, metadata

def match_library(lib_vecs, lib_names, target_vecs, target_names):
    matches = []
    for i, lib_name in enumerate(lib_names):
        sims = target_vecs @ lib_vecs[i]
        best_idx = np.argmax(sims)
        best_sim = sims[best_idx]
        best_target = target_names[best_idx]

        if best_sim >= MATCH_THRESHOLD:
            is_name_match = (lib_name == best_target or
                             lib_name in best_target or
                             best_target in lib_name)
            matches.append({
                "lib_func": lib_name,
                "target_func": best_target,
                "similarity": float(best_sim),
                "name_match": is_name_match,
            })

    match_rate = len(matches) / len(lib_names) * 100 if lib_names else 0
    name_matches = sum(1 for m in matches if m["name_match"])

    return {
        "total_lib_funcs": len(lib_names),
        "matched": len(matches),
        "match_rate": match_rate,
        "name_matches": name_matches,
        "matches": sorted(matches, key=lambda x: -x["similarity"]),
    }

def format_lib_name(name):
    # github_com_gin-gonic_gin -> github.com/gin-gonic/gin
    parts = name.split("_")
    if len(parts) >= 3 and parts[0] in ("github", "go", "golang", "google",
                                         "gopkg", "gorm", "gonum", "gorgonia",
                                         "k8s", "nhooyr"):
        # Reconstruct domain
        domain = parts[0] + "." + parts[1]
        rest = "/".join(parts[2:])
        return f"{domain}/{rest}"
    return name
