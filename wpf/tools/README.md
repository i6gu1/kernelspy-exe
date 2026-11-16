# Bundled tools payload

The scanner is designed to run completely offline, but the prepared `tools`
payload is **not committed to Git**. It is roughly **1.04 GB across 21,385
files**, which is far beyond what GitHub can reasonably host in a source
repository.

The application resolves this folder relative to the executable (and its parent
folders), so placing it at `wpf/tools/` is enough for both `dotnet run` and a
published build.

## Required layout

```text
tools/
  node/
    node.exe
  eslint-10.13.0/
    eslint-10.13.0/
      bin/
        eslint.js
  semgrep-runtime/
    semgrep/
      bin/
        semgrep-core.exe
  semgrep-1.181.0/
    ... complete Semgrep source checkout ...
```

The current build was prepared with:

- **Node.js** v26.13.0
- **ESLint** 10.13.0
- **Semgrep** 1.181.0 (native `semgrep-core.exe` plus the source checkout)

`build-installer.ps1` checks for `node.exe`, `eslint.js`, and
`semgrep-core.exe` before compiling the installer. If a tool is unavailable at
runtime, the scan still completes and reports that analyser as skipped.

The Semgrep rules shipped with the application live in `Rules/`, not in this
folder.
