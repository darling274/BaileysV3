import P from 'pino'

export interface ILogger {
	level: string
	child(obj: Record<string, unknown>): ILogger
	trace(obj: unknown, msg?: string): void
	debug(obj: unknown, msg?: string): void
	info(obj: unknown, msg?: string): void
	warn(obj: unknown, msg?: string): void
	error(obj: unknown, msg?: string): void
}


const NOISY_PATTERNS = [
	/bad mac/i,
	/failed to decrypt message/i,
	/stream errored? out/i,
	/mac verification failed/i,
	/session error/i,
	/no matching sessions/i,
	/no session (record|found)/i,
	/invalid prekey id/i,
	/prekey.*(missing|not found|corrupt)/i
]

const isNoisy = (msg?: string, obj?: unknown): boolean => {
	if (msg && NOISY_PATTERNS.some(p => p.test(msg))) return true
	if (obj && typeof obj === 'object') {
		const errMsg =
			(obj as { err?: { message?: string }; error?: { message?: string }; msg?: string }).err?.message ||
			(obj as { error?: { message?: string } }).error?.message ||
			''
		if (errMsg && NOISY_PATTERNS.some(p => p.test(errMsg))) return true
	}

	return false
}

/**
 * Wraps a logger so that known noisy-but-handled errors (Bad MAC, failed to decrypt,
 * stream error, missing/corrupt pre-keys, etc) are demoted to `trace` instead of
 * `warn`/`error`, keeping the console clean on long-running bots without hiding the
 * information from anyone who explicitly wants verbose logs (set level: 'trace').
 *
 * This NEVER changes control flow - it's purely a logging-level concern. The actual
 * recovery (session recreation, retry receipts, pre-key repair) happens elsewhere
 * and is completely unaffected by what gets printed to the console.
 */
export const makeQuietLogger = (base: ILogger): ILogger => {
	const wrap = (logger: ILogger): ILogger => ({
		level: logger.level,
		child: (obj: Record<string, unknown>) => wrap(logger.child(obj)),
		trace: (obj: unknown, msg?: string) => logger.trace(obj, msg),
		debug: (obj: unknown, msg?: string) => logger.debug(obj, msg),
		info: (obj: unknown, msg?: string) => logger.info(obj, msg),
		warn: (obj: unknown, msg?: string) => {
			if (isNoisy(msg, obj)) {
				logger.trace(obj, msg)
				return
			}

			logger.warn(obj, msg)
		},
		error: (obj: unknown, msg?: string) => {
			if (isNoisy(msg, obj)) {
				logger.trace(obj, msg)
				return
			}

			logger.error(obj, msg)
		}
	})

	return wrap(base)
}

const baseLogger: ILogger = P({ timestamp: () => `,"time":"${new Date().toJSON()}"` })

export default baseLogger
