# Contributing

Thanks for your interest in contributing! Here's how to get started.

## Development

```bash
git clone https://github.com/gmowses/log-parser.git
cd log-parser
npm install
npm run dev
```

## Guidelines

- **Stack**: React 19 + TypeScript + Tailwind CSS v4 + Vite
- **i18n**: All user-facing text must support EN and PT-BR
- **Dark mode**: All UI must work in both dark and light mode
- **Client-side only**: No server calls, no analytics, no cookies
- **Accessibility**: Use semantic HTML and ARIA attributes where needed

## Submitting Changes

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Make your changes
4. Ensure `npm run build` passes
5. Commit with a clear message
6. Open a Pull Request

## Reporting Bugs

Use the [bug report template](../../issues/new?template=bug_report.yml) to report issues.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
