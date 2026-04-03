# Password Generator

Secure password generator with entropy analysis and crack-time estimation. Everything runs client-side -- no data is sent to any server.

**[Live Demo](https://gmowses.github.io/password-generator)**

## Features

- **Cryptographic randomness** -- uses `crypto.getRandomValues()` for true randomness
- **Entropy calculation** -- Shannon entropy in bits based on character pool
- **Crack-time estimation** -- time to brute-force at 4 billion guesses/second (GPU baseline)
- **Strength meter** -- 5-level visual indicator (Very Weak to Very Strong)
- **Configurable charsets** -- numbers, lowercase, uppercase, symbols (toggle independently)
- **Length control** -- 4 to 128 characters with slider and +/- buttons
- **Guaranteed charset inclusion** -- at least one character from each selected type
- **Dark / Light mode** -- toggle or auto-detect from system preference
- **i18n** -- English and Portuguese (auto-detect from browser language)
- **Copy to clipboard** -- one-click copy with visual feedback
- **Zero dependencies on backend** -- pure client-side, works offline

## Tech Stack

- React 19
- TypeScript
- Tailwind CSS v4
- Vite
- Lucide icons

## Getting Started

```bash
git clone https://github.com/gmowses/password-generator.git
cd password-generator
npm install
npm run dev
```

Open `http://localhost:5173` in your browser.

## Build

```bash
npm run build
```

Static files are generated in `dist/`.

## How It Works

### Entropy

Entropy is calculated as `log2(pool_size ^ password_length)`, where `pool_size` is the total number of possible characters based on selected charsets:

| Charset | Pool Size |
|---------|-----------|
| Numbers (0-9) | 10 |
| Lowercase (a-z) | 26 |
| Uppercase (A-Z) | 26 |
| Symbols | 30 |

### Crack Time

Estimated time to brute-force the password assuming:
- Offline attack with modern GPUs
- 4 billion guesses per second
- No password reuse or pattern detection

### Strength Levels

| Entropy | Level |
|---------|-------|
| < 28 bits | Very Weak |
| 28-35 bits | Weak |
| 36-59 bits | Fair |
| 60-127 bits | Strong |
| 128+ bits | Very Strong |

## License

[MIT](LICENSE) -- Gabriel Mowses
