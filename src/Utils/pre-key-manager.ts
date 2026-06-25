import PQueue from 'p-queue'
import type { SignalDataSet, SignalDataTypeMap, SignalKeyStore } from '../Types'
import type { ILogger } from './logger'

/** Minimum interval between validations of the same key type (ms) */
const MIN_VALIDATION_INTERVAL_MS = 60_000 // 1 minute

/** Maximum queue size per key type to prevent memory accumulation */
const MAX_QUEUE_SIZE = 50

/**
 * Manages prekey operations with concurrency control, rate-limiting,
 * and queue cleanup for long-running 24/7 sessions.
 */
export class PreKeyManager {
	private readonly queues = new Map<string, PQueue>()
	private readonly lastValidationTime = new Map<string, number>()
	private readonly lastDeletionCount = new Map<string, number>()

	constructor(
		private readonly store: SignalKeyStore,
		private readonly logger: ILogger
	) {}

	/**
	 * Gets or creates a queue for a specific key type.
	 * Includes size limit to prevent memory accumulation.
	 */
	private getQueue(keyType: string): PQueue {
		if (!this.queues.has(keyType)) {
			const q = new PQueue({ concurrency: 1 })
			// Clean up the queue from the map when it becomes empty to free memory
			q.on('idle', () => {
				// Only remove if the queue remains empty after a tick
				// (new tasks may be enqueued immediately)
				setTimeout(() => {
					if (q.size === 0 && q.pending === 0) {
						this.queues.delete(keyType)
					}
				}, 0)
			})
			this.queues.set(keyType, q)
		}

		const queue = this.queues.get(keyType)!

		// Protection against excessive task accumulation in queue
		if (queue.size >= MAX_QUEUE_SIZE) {
			this.logger.warn(
				{ keyType, queueSize: queue.size },
				'PreKeyManager queue size limit reached, skipping new task'
			)
		}

		return queue
	}

	/**
	 * Checks whether we should skip a validation due to rate-limiting.
	 * Prevents redundant store queries when called in bursts.
	 */
	private isThrottled(keyType: string): boolean {
		const last = this.lastValidationTime.get(keyType)
		if (!last) return false
		return Date.now() - last < MIN_VALIDATION_INTERVAL_MS
	}

	private touchValidationTime(keyType: string): void {
		this.lastValidationTime.set(keyType, Date.now())
	}

	/**
	 * Processes prekey operations (updates and deletions)
	 */
	async processOperations(
		data: SignalDataSet,
		keyType: keyof SignalDataTypeMap,
		transactionCache: SignalDataSet,
		mutations: SignalDataSet,
		isInTransaction: boolean
	): Promise<void> {
		const keyData = data[keyType]
		if (!keyData) return

		const queue = this.getQueue(keyType)
		if (queue.size >= MAX_QUEUE_SIZE) return

		return queue.add(async () => {
			// Ensure structures exist
			transactionCache[keyType] = transactionCache[keyType] || ({} as any)
			mutations[keyType] = mutations[keyType] || ({} as any)

			// Separate deletions from updates
			const deletions: string[] = []
			const updates: Record<string, any> = {}

			for (const keyId in keyData) {
				if (keyData[keyId] === null) {
					deletions.push(keyId)
				} else {
					updates[keyId] = keyData[keyId]
				}
			}

			// Process updates
			if (Object.keys(updates).length > 0) {
				Object.assign(transactionCache[keyType]!, updates)
				Object.assign(mutations[keyType]!, updates)
			}

			// Process deletions with validation
			if (deletions.length > 0) {
				await this.processDeletions(keyType, deletions, transactionCache, mutations, isInTransaction)
			}
		})
	}

	/**
	 * Processes deletions with validation to prevent deleting
	 * keys that don't exist (which would cause future decryption errors).
	 */
	private async processDeletions(
		keyType: keyof SignalDataTypeMap,
		ids: string[],
		transactionCache: SignalDataSet,
		mutations: SignalDataSet,
		isInTransaction: boolean
	): Promise<void> {
		if (isInTransaction) {
			// Within a transaction: only delete if the key exists in cache
			let skipped = 0
			for (const keyId of ids) {
				if (transactionCache[keyType]?.[keyId]) {
					transactionCache[keyType]![keyId] = null
					mutations[keyType]![keyId] = null
				} else {
					skipped++
				}
			}
			if (skipped > 0) {
				this.logger.debug(
					{ keyType, skipped, total: ids.length },
					'Skipped deletion of non-existent keys in transaction'
				)
			}
		} else {
			// Outside transaction: validate against the store
			const existingKeys = await this.store.get(keyType, ids)
			let deleted = 0
			let skipped = 0

			for (const keyId of ids) {
				if (existingKeys[keyId]) {
					transactionCache[keyType]![keyId] = null
					mutations[keyType]![keyId] = null
					deleted++
				} else {
					skipped++
				}
			}

			if (skipped > 0) {
				this.logger.debug(
					{ keyType, deleted, skipped, total: ids.length },
					'Prekey deletion: some keys were not found in store'
				)
			}

			// Record deletion statistics for diagnostics
			const prevCount = this.lastDeletionCount.get(keyType) ?? 0
			this.lastDeletionCount.set(keyType, prevCount + deleted)
		}
	}

	/**
	 * Validates and processes prekey deletions outside transactions.
	 * Includes rate-limiting to prevent redundant store queries.
	 */
	async validateDeletions(data: SignalDataSet, keyType: keyof SignalDataTypeMap): Promise<void> {
		const keyData = data[keyType]
		if (!keyData) return

		const deletionIds = Object.keys(keyData).filter(id => keyData[id] === null)
		if (deletionIds.length === 0) return

		// Rate-limiting: skip if recently validated for the same type
		if (this.isThrottled(keyType)) {
			this.logger.debug(
				{ keyType, count: deletionIds.length },
				'Skipping prekey deletion validation (rate-limited)'
			)
			return
		}

		const queue = this.getQueue(keyType)
		if (queue.size >= MAX_QUEUE_SIZE) return

		return queue.add(async () => {
			this.touchValidationTime(keyType)

			// Validate deletions against the store
			const existingKeys = await this.store.get(keyType, deletionIds)
			let invalidCount = 0

			for (const keyId of deletionIds) {
				if (!existingKeys[keyId]) {
					// Remove invalid deletion request to prevent propagating the error
					delete data[keyType]![keyId]
					invalidCount++
				}
			}

			if (invalidCount > 0) {
				this.logger.warn(
					{ keyType, invalidCount, total: deletionIds.length },
					'Removed invalid prekey deletion requests'
				)
			}
		})
	}

	/**
	 * Returns queue usage statistics for diagnostics.
	 */
	getStats() {
		const queues: Record<string, { size: number; pending: number }> = {}
		for (const [key, q] of this.queues) {
			queues[key] = { size: q.size, pending: q.pending }
		}
		return {
			activeQueues: this.queues.size,
			queues,
			totalDeletions: Object.fromEntries(this.lastDeletionCount),
			lastValidations: Object.fromEntries(this.lastValidationTime)
		}
	}
}
