import { Mutex } from 'async-mutex'
import { mkdir, readFile, rename, stat, unlink, writeFile } from 'fs/promises'
import { join } from 'path'
import { proto } from '../../WAProto/index.js'
import type { AuthenticationCreds, AuthenticationState, SignalDataTypeMap } from '../Types'
import { initAuthCreds } from './auth-utils'
import { BufferJSON } from './generics'

// Map of mutexes by file path (prevents concurrent writes)
const fileLocks = new Map<string, Mutex>()

const getFileLock = (path: string): Mutex => {
	let mutex = fileLocks.get(path)
	if (!mutex) {
		mutex = new Mutex()
		fileLocks.set(path, mutex)
	}
	return mutex
}

/**
 * Atomic write: first writes to a .tmp file and then
 * renames to the final destination. On POSIX systems, rename() is
 * atomic, so readers never see a partially written file.
 * Prevents corruption of creds.json if the process dies
 * during writing.
 */
const atomicWriteFile = async (filePath: string, content: string): Promise<void> => {
	const tmpPath = `${filePath}.tmp`
	await writeFile(tmpPath, content, { encoding: 'utf-8' })
	await rename(tmpPath, filePath)
}

const CREDS_FILE = 'creds.json'
const CREDS_BACKUP_FILE = 'creds.json.bak'

/**
 * Validates that a credentials object has the minimum required
 * fields to establish a WhatsApp session.
 */
const isValidCreds = (data: unknown): data is AuthenticationCreds => {
	if (!data || typeof data !== 'object') return false
	const d = data as Record<string, unknown>
	return (
		typeof d.noiseKey === 'object' &&
		d.noiseKey !== null &&
		typeof d.signedIdentityKey === 'object' &&
		d.signedIdentityKey !== null &&
		typeof d.registrationId === 'number'
	)
}

/**
 * Stores the complete authentication state in a folder.
 *
 * Improvements over the original version:
 * - Atomic writes via tmp + rename (prevents creds.json corruption on crash)
 * - Automatic backup of creds.json before each write + restoration on corruption
 * - Credential validation on read (fallback to initAuthCreds if JSON is corrupted)
 * - 300ms debounce on saveCreds to prevent redundant writes in rapid bursts
 */
export const useMultiFileAuthState = async (
	folder: string
): Promise<{ state: AuthenticationState; saveCreds: () => Promise<void> }> => {

	const fixFileName = (file?: string) => file?.replace(/\//g, '__')?.replace(/:/g, '-')

	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	const writeData = async (data: any, file: string): Promise<void> => {
		const filePath = join(folder, fixFileName(file)!)
		const mutex = getFileLock(filePath)

		return mutex.runExclusive(async () => {
			const serialized = JSON.stringify(data, BufferJSON.replacer)

			// For creds.json: save backup BEFORE overwriting.
			// If the process dies between the backup and the final write,
			// the backup will still have the previous valid version.
			if (file === CREDS_FILE) {
				const backupPath = join(folder, fixFileName(CREDS_BACKUP_FILE)!)
				try {
					await atomicWriteFile(backupPath, serialized)
				} catch {
					// Non-fatal: backup failed but main write continues
				}
			}

			await atomicWriteFile(filePath, serialized)
		})
	}

	const readData = async (file: string): Promise<unknown> => {
		const filePath = join(folder, fixFileName(file)!)
		const mutex = getFileLock(filePath)

		return mutex.runExclusive(async () => {
			// Primary read
			try {
				const raw = await readFile(filePath, { encoding: 'utf-8' })
				return JSON.parse(raw, BufferJSON.reviver)
			} catch {
				// For creds.json: attempt to restore from backup
				if (file === CREDS_FILE) {
					const backupPath = join(folder, fixFileName(CREDS_BACKUP_FILE)!)
					try {
						const backupRaw = await readFile(backupPath, { encoding: 'utf-8' })
						const parsed = JSON.parse(backupRaw, BufferJSON.reviver)
						// Restore the primary file from backup
						await atomicWriteFile(filePath, backupRaw)
						return parsed
					} catch {
						// Both primary and backup failed
					}
				}
				return null
			}
		})
	}

	const removeData = async (file: string): Promise<void> => {
		const filePath = join(folder, fixFileName(file)!)
		const mutex = getFileLock(filePath)

		return mutex.runExclusive(async () => {
			try {
				await unlink(filePath)
			} catch {
				// Ignore ENOENT and other unlink errors
			}
		})
	}

	const folderInfo = await stat(folder).catch(() => undefined)
	if (folderInfo) {
		if (!folderInfo.isDirectory()) {
			throw new Error(
				`found something that is not a directory at ${folder}, either delete it or specify a different location`
			)
		}
	} else {
		await mkdir(folder, { recursive: true })
	}

	// Read and validate credentials; fallback to fresh credentials if JSON is corrupted
	const rawCreds = await readData(CREDS_FILE)
	const creds: AuthenticationCreds = isValidCreds(rawCreds) ? rawCreds : initAuthCreds()

	// --- Debounce for saveCreds ---
	// WhatsApp emits many consecutive creds.update events (login, prekeys, etc.).
	// Without debounce, each event triggers a separate disk write.
	// A 300ms debounce collapses bursts into a single write.
	let saveCredsTimer: NodeJS.Timeout | undefined

	const flushCreds = async (): Promise<void> => {
		return writeData(creds, CREDS_FILE)
	}

	const saveCreds = (): Promise<void> => {
		return new Promise<void>((resolve, reject) => {
			if (saveCredsTimer) clearTimeout(saveCredsTimer)
			saveCredsTimer = setTimeout(async () => {
				saveCredsTimer = undefined
				try {
					await flushCreds()
					resolve()
				} catch (err) {
					reject(err)
				}
			}, 300)
		})
	}

	return {
		state: {
			creds,
			keys: {
				get: async (type, ids) => {
					const data: { [_: string]: SignalDataTypeMap[typeof type] } = {}
					await Promise.all(
						ids.map(async id => {
							let value = await readData(`${type}-${id}.json`)
							if (type === 'app-state-sync-key' && value) {
								value = proto.Message.AppStateSyncKeyData.fromObject(value)
							}
							data[id] = value as SignalDataTypeMap[typeof type]
						})
					)
					return data
				},
				set: async data => {
					const tasks: Promise<void>[] = []
					for (const category in data) {
						for (const id in data[category as keyof SignalDataTypeMap]) {
							const value = data[category as keyof SignalDataTypeMap]![id]
							const file = `${category}-${id}.json`
							tasks.push(value ? writeData(value, file) : removeData(file))
						}
					}
					await Promise.all(tasks)
				}
			}
		},
		saveCreds
	}
}
