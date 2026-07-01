# Link42 Playwright E2E

This directory keeps lightweight helpers for browser-based manual/E2E testing.
The heavy dependencies are installed outside the repository so repeated test
runs do not re-download Playwright or Chromium.

## One-Time Setup

```bash
scripts/e2e/bootstrap-playwright.sh
```

Default persistent locations:

```text
Playwright npm runtime: ~/.cache/link42/e2e
Chromium browser cache: ~/.cache/ms-playwright
```

Override them when needed:

```bash
LINK42_E2E_HOME=/opt/link42-e2e \
PLAYWRIGHT_BROWSERS_PATH=/opt/link42-browsers \
scripts/e2e/bootstrap-playwright.sh
```

## Run A Test Script

```bash
scripts/e2e/run-playwright.sh /absolute/path/to/test.js
```

The runner injects `NODE_PATH` so scripts can use:

```js
const { chromium } = require("playwright");
```

## Recommended Test Layout

Keep throwaway test scripts, screenshots, temporary databases, and logs under
`/tmp/link42-*`. Do not remove `~/.cache/ms-playwright` or
`~/.cache/link42/e2e` during cleanup unless the browser/runtime cache is
intentionally being rebuilt.
