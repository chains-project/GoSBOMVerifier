# GoSBOMVerifier

A verifier that checks whether the third-party Go modules declared in an SBOM
are actually present in a compiled Go binary. Supports three complementary
detection methods and exposes them through a single CLI.

Corpora are available at: https://zenodo.org/records/20794562

## Methods

- **symtab** — parses module paths out of the binary's ELF `.symtab` section.
  Fast (<1 s/binary), near-perfect precision when symbols are present. Returns
  nothing on binaries stripped with `strip` or built with `-ldflags="-s"`,
  which removes the symbol table.

- **gopclntab** — parses module paths out of the binary's `.gopclntab` section.
  Same speed and precision profile as symtab, but **survives `strip`** because
  the Go runtime needs `.gopclntab` for stack traces and panics. Defeated only
  by name-obfuscation tools such as garble.

- **LibDB (GNN function-graph matching)** — fingerprints library functions by
  their control-flow graphs using a graph neural network trained on 208 Go
  libraries. Works on stripped and partially obfuscated binaries where the
  symbol-based methods fail. Requires a pre-extracted Ghidra feature JSON as
  input. The trained model and library embeddings are vendored under `lib/`.

## Requirements

- Python 3.10+
- `torch`, `numpy`
- Ghidra 9.1.2 (only for producing libdb input)

## Usage

### symtab / gopclntab

Both are exposed via `--method symbol`, with `--symbol-source` choosing which
section to read (`symtab`, `gopclntab`, or `both`, default `both`).

```bash
python main.py --method symbol \
    --symbol-source gopclntab \
    --binary path/to/binary \
    --sbom   path/to/sbom.cdx.json
```

Optional: `--gomod path/to/go.mod` (adds direct-vs-indirect breakdown),
`--output result.json`, `-v`.

### LibDB

```bash
python main.py --method libdb \
    --ghidra-json path/to/binary.json \
    --sbom        path/to/sbom.cdx.json
```

Optional:
`--libdb-match-threshold N` (default 65),
`--libdb-name-match-min N` (default 1),
`--libdb-no-adaptive` (disable the stripped-binary fallback).

The bundled model and library embeddings under `lib/` are used by default.
Override with `--model-path` / `--embeddings-dir` if needed.

## Output

Each run prints a short summary (precision / recall / F1 against the SBOM).
With `--output result.json`, a full per-module detection report is written for
downstream analysis. See `result.py` for the schema.
