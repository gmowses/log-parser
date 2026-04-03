import { useState, useEffect, useCallback, useMemo } from 'react'
import { Copy, Check, Sun, Moon, Languages, FileText, Trash2 } from 'lucide-react'

// ── i18n ─────────────────────────────────────────────────────────────────────
const translations = {
  en: {
    title: 'Log Parser',
    subtitle: 'Paste raw log lines. Auto-detects Apache/Nginx access, syslog, JSON, Docker. Parse into table, filter by level, copy as JSON.',
    input: 'Raw Logs',
    inputDesc: 'Paste your log lines here',
    inputPlaceholder: `# Paste any log lines here, for example:
192.168.1.1 - - [01/Apr/2026:12:00:00 +0000] "GET /api/health HTTP/1.1" 200 1234
Apr  1 12:00:01 myhost sshd[1234]: error: Connection reset by peer
{"time":"2026-04-01T12:00:02Z","level":"warn","msg":"High memory usage","pct":88}
2026-04-01T12:00:03Z [ERROR] Database connection failed`,
    table: 'Parsed Table',
    tableDesc: 'Structured log entries',
    format: 'Detected format',
    filterLevel: 'Filter by level',
    all: 'All',
    copyJson: 'Copy as JSON',
    copied: 'Copied!',
    clear: 'Clear',
    noLogs: 'No log entries parsed yet. Paste logs on the left.',
    lineNo: '#',
    timestamp: 'Timestamp',
    level: 'Level',
    host: 'Host / Source',
    message: 'Message',
    method: 'Method',
    status: 'Status',
    path: 'Path',
    ip: 'IP',
    builtBy: 'Built by',
    lines: 'lines',
    errors: 'errors',
    warnings: 'warnings',
  },
  pt: {
    title: 'Parser de Logs',
    subtitle: 'Cole linhas de log brutas. Detecta automaticamente Apache/Nginx, syslog, JSON, Docker. Exibe em tabela, filtra por nivel, copia como JSON.',
    input: 'Logs Brutos',
    inputDesc: 'Cole suas linhas de log aqui',
    inputPlaceholder: `# Cole qualquer linha de log aqui, por exemplo:
192.168.1.1 - - [01/Apr/2026:12:00:00 +0000] "GET /api/health HTTP/1.1" 200 1234
Apr  1 12:00:01 myhost sshd[1234]: error: Connection reset by peer
{"time":"2026-04-01T12:00:02Z","level":"warn","msg":"High memory usage","pct":88}
2026-04-01T12:00:03Z [ERROR] Database connection failed`,
    table: 'Tabela Parseada',
    tableDesc: 'Entradas de log estruturadas',
    format: 'Formato detectado',
    filterLevel: 'Filtrar por nivel',
    all: 'Todos',
    copyJson: 'Copiar como JSON',
    copied: 'Copiado!',
    clear: 'Limpar',
    noLogs: 'Nenhuma entrada de log parseada. Cole logs a esquerda.',
    lineNo: '#',
    timestamp: 'Timestamp',
    level: 'Nivel',
    host: 'Host / Origem',
    message: 'Mensagem',
    method: 'Metodo',
    status: 'Status',
    path: 'Caminho',
    ip: 'IP',
    builtBy: 'Criado por',
    lines: 'linhas',
    errors: 'erros',
    warnings: 'alertas',
  },
} as const

type Lang = keyof typeof translations

// ── Log parsing ───────────────────────────────────────────────────────────────
type LogLevel = 'error' | 'warn' | 'info' | 'debug' | 'unknown'
type LogFormat = 'nginx_access' | 'apache_access' | 'syslog' | 'json' | 'docker' | 'generic'

interface LogEntry {
  line: number
  raw: string
  format: LogFormat
  timestamp?: string
  level: LogLevel
  host?: string
  ip?: string
  method?: string
  path?: string
  status?: string
  message: string
}

// Nginx / Apache combined log: IP - - [timestamp] "METHOD path proto" status size
const NGINX_RE = /^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\w+)\s+(\S+)\s+\S+"\s+(\d+)\s+(\d+|-)(.*)$/

// syslog: Month DD HH:MM:SS host process[pid]: message
const SYSLOG_RE = /^(\w+\s+\d+\s+[\d:]+)\s+(\S+)\s+(\S+):\s+(.*)$/

// ISO timestamp prefix: 2026-04-01T12:00:00Z [LEVEL] message
const ISO_RE = /^([\d-T:.Z+]+)\s+(?:\[(\w+)\]\s+)?(.*)$/

// Docker / structured: time=... level=... msg=...
const DOCKER_KV_RE = /time="?([^"\s]+)"?\s+level=(\w+)\s+msg="?([^"]+)"?/

function detectLevel(s: string): LogLevel {
  const u = s.toLowerCase()
  if (/\b(error|err|fatal|crit|critical|exception|traceback|panic)\b/.test(u)) return 'error'
  if (/\b(warn|warning|caution)\b/.test(u)) return 'warn'
  if (/\b(info|information|notice)\b/.test(u)) return 'info'
  if (/\b(debug|trace|verbose)\b/.test(u)) return 'debug'
  return 'unknown'
}

function detectStatusLevel(status: string): LogLevel {
  const code = parseInt(status)
  if (code >= 500) return 'error'
  if (code >= 400) return 'warn'
  if (code >= 200) return 'info'
  return 'unknown'
}

function parseLine(raw: string, lineNo: number): LogEntry | null {
  const trimmed = raw.trim()
  if (!trimmed || trimmed.startsWith('#')) return null

  // Try JSON
  if (trimmed.startsWith('{')) {
    try {
      const obj = JSON.parse(trimmed) as Record<string, unknown>
      const ts = (obj.time ?? obj.timestamp ?? obj.ts ?? obj['@timestamp'] ?? '') as string
      const lvlRaw = (obj.level ?? obj.severity ?? obj.loglevel ?? '') as string
      const msg = (obj.msg ?? obj.message ?? obj.Message ?? JSON.stringify(obj)) as string
      const level = detectLevel(lvlRaw) || detectLevel(msg)
      return { line: lineNo, raw, format: 'json', timestamp: String(ts), level, message: String(msg) }
    } catch { /* fall through */ }
  }

  // Docker KV
  const dockerM = DOCKER_KV_RE.exec(trimmed)
  if (dockerM) {
    return { line: lineNo, raw, format: 'docker', timestamp: dockerM[1], level: detectLevel(dockerM[2]), message: dockerM[3] }
  }

  // Nginx/Apache
  const nginxM = NGINX_RE.exec(trimmed)
  if (nginxM) {
    return {
      line: lineNo, raw, format: 'nginx_access',
      ip: nginxM[1], timestamp: nginxM[2],
      method: nginxM[3], path: nginxM[4], status: nginxM[5],
      level: detectStatusLevel(nginxM[5]),
      message: `${nginxM[3]} ${nginxM[4]} ${nginxM[5]}`,
    }
  }

  // Syslog
  const syslogM = SYSLOG_RE.exec(trimmed)
  if (syslogM) {
    return { line: lineNo, raw, format: 'syslog', timestamp: syslogM[1], host: syslogM[2], level: detectLevel(syslogM[4]), message: `${syslogM[3]}: ${syslogM[4]}` }
  }

  // ISO prefix
  const isoM = ISO_RE.exec(trimmed)
  if (isoM && /^\d{4}-\d{2}/.test(isoM[1])) {
    const level = isoM[2] ? detectLevel(isoM[2]) : detectLevel(isoM[3])
    return { line: lineNo, raw, format: 'generic', timestamp: isoM[1], level, message: isoM[3] }
  }

  // Generic fallback
  return { line: lineNo, raw, format: 'generic', level: detectLevel(trimmed), message: trimmed }
}

function detectDominantFormat(entries: LogEntry[]): string {
  if (entries.length === 0) return 'unknown'
  const counts: Record<string, number> = {}
  for (const e of entries) counts[e.format] = (counts[e.format] ?? 0) + 1
  return Object.entries(counts).sort((a, b) => b[1] - a[1])[0][0]
}

const LEVEL_COLORS: Record<LogLevel, string> = {
  error: 'text-red-600 dark:text-red-400 bg-red-50 dark:bg-red-900/20',
  warn: 'text-yellow-600 dark:text-yellow-400 bg-yellow-50 dark:bg-yellow-900/20',
  info: 'text-blue-600 dark:text-blue-400 bg-blue-50 dark:bg-blue-900/20',
  debug: 'text-zinc-500 dark:text-zinc-400 bg-zinc-100 dark:bg-zinc-800',
  unknown: 'text-zinc-500 dark:text-zinc-400',
}

const ROW_HIGHLIGHT: Record<LogLevel, string> = {
  error: 'bg-red-50/50 dark:bg-red-950/10',
  warn: 'bg-yellow-50/50 dark:bg-yellow-950/10',
  info: '',
  debug: '',
  unknown: '',
}

// ── Component ─────────────────────────────────────────────────────────────────
export default function LogParser() {
  const [lang, setLang] = useState<Lang>(() => (navigator.language.startsWith('pt') ? 'pt' : 'en'))
  const [dark, setDark] = useState(() => window.matchMedia('(prefers-color-scheme: dark)').matches)
  const [rawInput, setRawInput] = useState('')
  const [filterLevel, setFilterLevel] = useState<LogLevel | 'all'>('all')
  const [copied, setCopied] = useState(false)

  const t = translations[lang]

  useEffect(() => { document.documentElement.classList.toggle('dark', dark) }, [dark])

  const allEntries = useMemo<LogEntry[]>(() => {
    if (!rawInput.trim()) return []
    return rawInput.split('\n').map((l, i) => parseLine(l, i + 1)).filter((e): e is LogEntry => e !== null)
  }, [rawInput])

  const filtered = useMemo(() => filterLevel === 'all' ? allEntries : allEntries.filter(e => e.level === filterLevel), [allEntries, filterLevel])

  const dominantFormat = useMemo(() => detectDominantFormat(allEntries), [allEntries])

  const errorCount = useMemo(() => allEntries.filter(e => e.level === 'error').length, [allEntries])
  const warnCount = useMemo(() => allEntries.filter(e => e.level === 'warn').length, [allEntries])

  const handleCopy = useCallback(() => {
    const json = JSON.stringify(filtered, null, 2)
    navigator.clipboard.writeText(json).then(() => { setCopied(true); setTimeout(() => setCopied(false), 2000) })
  }, [filtered])

  const isNginxOrApache = allEntries.some(e => e.format === 'nginx_access' || e.format === 'apache_access')

  const levelBadge = (level: LogLevel) => (
    <span className={`inline-block px-1.5 py-0.5 rounded text-[10px] font-bold uppercase tracking-wide ${LEVEL_COLORS[level]}`}>{level}</span>
  )

  const statusBadge = (status?: string) => {
    if (!status) return null
    const code = parseInt(status)
    const color = code >= 500 ? 'text-red-600 dark:text-red-400' : code >= 400 ? 'text-yellow-600 dark:text-yellow-400' : 'text-emerald-600 dark:text-emerald-400'
    return <span className={`font-mono font-bold ${color}`}>{status}</span>
  }

  const levels: Array<LogLevel | 'all'> = ['all', 'error', 'warn', 'info', 'debug']

  return (
    <div className="min-h-screen flex flex-col bg-white dark:bg-[#09090b] text-zinc-900 dark:text-zinc-100 transition-colors">
      {/* Header */}
      <header className="border-b border-zinc-200 dark:border-zinc-800 px-6 py-4">
        <div className="max-w-full mx-auto px-0 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 bg-yellow-500 rounded-lg flex items-center justify-center">
              <FileText size={18} className="text-white" />
            </div>
            <span className="font-semibold">Log Parser</span>
          </div>
          <div className="flex items-center gap-2">
            <button onClick={() => setLang(l => l === 'en' ? 'pt' : 'en')} className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium border border-zinc-200 dark:border-zinc-800 hover:bg-zinc-100 dark:hover:bg-zinc-800 transition-colors">
              <Languages size={14} />{lang.toUpperCase()}
            </button>
            <button onClick={() => setDark(d => !d)} className="p-2 rounded-lg border border-zinc-200 dark:border-zinc-800 hover:bg-zinc-100 dark:hover:bg-zinc-800 transition-colors">
              {dark ? <Sun size={16} /> : <Moon size={16} />}
            </button>
            <a href="https://github.com/gmowses/log-parser" target="_blank" rel="noopener noreferrer" className="p-2 rounded-lg border border-zinc-200 dark:border-zinc-800 hover:bg-zinc-100 dark:hover:bg-zinc-800 transition-colors">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/></svg>
            </a>
          </div>
        </div>
      </header>

      {/* Main */}
      <main className="flex-1 px-6 py-10 overflow-hidden">
        <div className="max-w-full space-y-6">
          <div>
            <h1 className="text-3xl font-bold">{t.title}</h1>
            <p className="mt-2 text-zinc-500 dark:text-zinc-400">{t.subtitle}</p>
          </div>

          {/* Two column layout */}
          <div className="grid gap-6 xl:grid-cols-2 h-full">
            {/* Input */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="font-semibold text-sm">{t.input}</h2>
                  <p className="text-xs text-zinc-500 dark:text-zinc-400">{t.inputDesc}</p>
                </div>
                {rawInput && (
                  <button onClick={() => setRawInput('')} className="flex items-center gap-1 text-xs text-zinc-400 hover:text-red-500 transition-colors">
                    <Trash2 size={12} />{t.clear}
                  </button>
                )}
              </div>
              <textarea
                className="w-full h-[calc(100vh-280px)] min-h-[400px] rounded-xl border border-zinc-200 dark:border-zinc-700 bg-zinc-50 dark:bg-zinc-900 p-4 font-mono text-xs text-zinc-700 dark:text-zinc-300 focus:outline-none focus:ring-2 focus:ring-yellow-500 resize-none leading-relaxed"
                value={rawInput}
                onChange={e => setRawInput(e.target.value)}
                placeholder={t.inputPlaceholder}
              />
            </div>

            {/* Table */}
            <div className="space-y-2">
              <div className="flex items-center justify-between flex-wrap gap-2">
                <div className="flex items-center gap-3">
                  <div>
                    <h2 className="font-semibold text-sm">{t.table}</h2>
                    <p className="text-xs text-zinc-500 dark:text-zinc-400">{t.tableDesc}</p>
                  </div>
                  {allEntries.length > 0 && (
                    <div className="flex items-center gap-2 text-xs text-zinc-400">
                      <span>{allEntries.length} {t.lines}</span>
                      {errorCount > 0 && <span className="text-red-500">{errorCount} {t.errors}</span>}
                      {warnCount > 0 && <span className="text-yellow-500">{warnCount} {t.warnings}</span>}
                      <span className="text-zinc-300 dark:text-zinc-600">|</span>
                      <span>{t.format}: <span className="font-mono">{dominantFormat}</span></span>
                    </div>
                  )}
                </div>
                <div className="flex items-center gap-2">
                  {/* Level filter */}
                  <div className="flex gap-1">
                    {levels.map(l => (
                      <button key={l} onClick={() => setFilterLevel(l)} className={`px-2 py-1 rounded text-[11px] font-medium transition-colors ${filterLevel === l ? 'bg-yellow-500 text-white' : 'border border-zinc-200 dark:border-zinc-700 hover:bg-zinc-100 dark:hover:bg-zinc-800 text-zinc-500'}`}>
                        {l === 'all' ? t.all : l}
                      </button>
                    ))}
                  </div>
                  <button onClick={handleCopy} disabled={filtered.length === 0} className="flex items-center gap-1.5 rounded-lg border border-zinc-200 dark:border-zinc-700 px-3 py-1.5 text-xs font-medium hover:bg-zinc-100 dark:hover:bg-zinc-800 transition-colors disabled:opacity-40">
                    {copied ? <Check size={12} className="text-green-500" /> : <Copy size={12} />}
                    {copied ? t.copied : t.copyJson}
                  </button>
                </div>
              </div>

              <div className="rounded-xl border border-zinc-200 dark:border-zinc-800 overflow-auto h-[calc(100vh-280px)] min-h-[400px]">
                {filtered.length === 0 ? (
                  <div className="flex items-center justify-center h-full text-sm text-zinc-400 p-8 text-center">{t.noLogs}</div>
                ) : (
                  <table className="w-full text-xs border-collapse">
                    <thead className="sticky top-0 bg-zinc-50 dark:bg-zinc-900 border-b border-zinc-200 dark:border-zinc-800">
                      <tr>
                        <th className="px-3 py-2 text-left font-medium text-zinc-500 w-8">{t.lineNo}</th>
                        <th className="px-3 py-2 text-left font-medium text-zinc-500">{t.level}</th>
                        {allEntries.some(e => e.timestamp) && <th className="px-3 py-2 text-left font-medium text-zinc-500 whitespace-nowrap">{t.timestamp}</th>}
                        {(allEntries.some(e => e.host)) && <th className="px-3 py-2 text-left font-medium text-zinc-500">{t.host}</th>}
                        {isNginxOrApache && <th className="px-3 py-2 text-left font-medium text-zinc-500">{t.ip}</th>}
                        {isNginxOrApache && <th className="px-3 py-2 text-left font-medium text-zinc-500">{t.method}</th>}
                        {isNginxOrApache && <th className="px-3 py-2 text-left font-medium text-zinc-500">{t.status}</th>}
                        {isNginxOrApache && <th className="px-3 py-2 text-left font-medium text-zinc-500">{t.path}</th>}
                        <th className="px-3 py-2 text-left font-medium text-zinc-500">{t.message}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filtered.map(entry => (
                        <tr key={`${entry.line}-${entry.raw}`} className={`border-b border-zinc-100 dark:border-zinc-800/50 hover:bg-zinc-50 dark:hover:bg-zinc-800/30 transition-colors ${ROW_HIGHLIGHT[entry.level]}`}>
                          <td className="px-3 py-1.5 font-mono text-zinc-400">{entry.line}</td>
                          <td className="px-3 py-1.5">{levelBadge(entry.level)}</td>
                          {allEntries.some(e => e.timestamp) && <td className="px-3 py-1.5 font-mono text-zinc-500 whitespace-nowrap">{entry.timestamp ?? ''}</td>}
                          {allEntries.some(e => e.host) && <td className="px-3 py-1.5 text-zinc-500">{entry.host ?? ''}</td>}
                          {isNginxOrApache && <td className="px-3 py-1.5 font-mono text-zinc-500">{entry.ip ?? ''}</td>}
                          {isNginxOrApache && <td className="px-3 py-1.5 font-mono font-medium text-blue-600 dark:text-blue-400">{entry.method ?? ''}</td>}
                          {isNginxOrApache && <td className="px-3 py-1.5">{statusBadge(entry.status)}</td>}
                          {isNginxOrApache && <td className="px-3 py-1.5 font-mono text-zinc-600 dark:text-zinc-300 max-w-[200px] truncate">{entry.path ?? ''}</td>}
                          <td className="px-3 py-1.5 text-zinc-700 dark:text-zinc-300 max-w-[400px] truncate" title={entry.message}>{entry.message}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            </div>
          </div>
        </div>
      </main>

      <footer className="border-t border-zinc-200 dark:border-zinc-800 px-6 py-4">
        <div className="max-w-full mx-auto flex items-center justify-between text-xs text-zinc-400">
          <span>{t.builtBy} <a href="https://github.com/gmowses" className="text-zinc-600 dark:text-zinc-300 hover:text-yellow-500 transition-colors">Gabriel Mowses</a></span>
          <span>MIT License</span>
        </div>
      </footer>
    </div>
  )
}
