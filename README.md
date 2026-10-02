# Log Parser

Parse pasted log lines into a filterable table directly in the browser.

## Features

- Detects JSON, Docker key-value logs, syslog, access logs, ISO-prefixed, and generic lines
- Identifies error, warning, info, and debug levels
- Filters parsed entries and copies the visible entries as JSON
- English and Portuguese UI with light and dark themes

## Local development

```bash
npm install
npm run dev
```

Open the URL printed by Vite. Use `npm run lint` and `npm run build` before changes are submitted.

## Data and limits

Logs remain in the current browser session; the app has no upload, backend, account, or persistence. Format detection uses simple patterns and may classify proprietary or malformed logs as generic. Remove credentials, tokens, and other sensitive data before sharing copied output.

## License

[MIT](LICENSE)
