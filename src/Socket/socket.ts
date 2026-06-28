import { Boom } from '@hapi/boom'
import { randomBytes } from 'crypto'
import { URL } from 'url'
import { promisify } from 'util'
import { proto } from '../../WAProto/index.js'
import {
	DEF_CALLBACK_PREFIX,
	DEF_TAG_PREFIX,
	INITIAL_PREKEY_COUNT,
	MIN_PREKEY_COUNT,
	NOISE_WA_HEADER,
	PROCESSABLE_HISTORY_TYPES,
	TimeMs,
	UNAUTHORIZED_CODES,
	UPLOAD_TIMEOUT
} from '../Defaults'
import {
	type LIDMapping,
	type NewChatMessageCapInfo,
	QueryIds,
	ReachoutTimelockEnforcementType,
	type ReachoutTimelockState,
	type SocketConfig
} from '../Types'
import { DisconnectReason, XWAPaths } from '../Types'
import {
	addTransactionCapability,
	aesEncryptCTR,
	bindWaitForConnectionUpdate,
	buildPairingQRData,
	bytesToCrockford,
	configureSuccessfulPairing,
	Curve,
	derivePairingCodeKey,
	generateLoginNode,
	generateMdTagPrefix,
	generateRegistrationNode,
	getCodeFromWSError,
	getCompanionPlatformId,
	getErrorCodeFromStreamError,
	getNextPreKeysNode,
	makeEventBuffer,
	makeNoiseHandler,
	promiseTimeout,
	signedKeyPair,
	xmppSignedPreKey
} from '../Utils'
import {
	assertNodeErrorFree,
	type BinaryNode,
	binaryNodeToString,
	encodeBinaryNode,
	getAllBinaryNodeChildren,
	getBinaryNodeChild,
	getBinaryNodeChildren,
	isLidUser,
	jidDecode,
	jidEncode,
	S_WHATSAPP_NET
} from '../WABinary'
import { BinaryInfo } from '../WAM/BinaryInfo.js'
import { USyncQuery, USyncUser } from '../WAUSync/'
import { WebSocketClient } from './Client'
import { executeWMexQuery } from './mex.js'

/**
 * Connects to WA servers and performs:
 * - simple queries (no retry mechanism, wait for connection establishment)
 * - listen to messages and emit events
 * - query phone connection
 *
 * Optimized for 24/7 operation:
 * - Prekey circuit breaker: backs off after repeated server failures
 * - Prekey cooldown: min 5 min between health checks to avoid hammering
 * - Prekey low notification handler: reacts immediately when WA reports low keys
 * - All async event handlers guarded with try/catch (no unhandled rejections)
 * - Keep-alive ping failures logged at debug (not error) — expected during hiccups
 * - Stream errors classified as fatal vs transient (only fatal ones log as error)
 */
export const makeSocket = (config: SocketConfig) => {
	const {
		waWebSocketUrl,
		connectTimeoutMs,
		logger,
		keepAliveIntervalMs,
		browser,
		auth: authState,
		printQRInTerminal,
		defaultQueryTimeoutMs,
		transactionOpts,
		qrTimeout,
		makeSignalRepository
	} = config

	const publicWAMBuffer = new BinaryInfo()

	let serverTimeOffsetMs = 0

	const uqTagId = generateMdTagPrefix()
	const generateMessageTag = () => `${uqTagId}${epoch++}`

	if (printQRInTerminal) {
		logger.warn(
			{},
			'⚠️ The printQRInTerminal option has been deprecated. You will no longer receive QR codes in the terminal automatically. Please listen to the connection.update event yourself and handle the QR your way. You can remove this message by removing this option. This message will be removed in a future version.'
		)
	}

	if (browser[1].toLocaleLowerCase().includes('android')) {
		logger.warn(
			'⚠️ Using the Android browser is experimental and may lead to unexpected behavior. Use at your own risk.'
		)
	}

	const syncDisabled =
		PROCESSABLE_HISTORY_TYPES.map(syncType => config.shouldSyncHistoryMessage({ syncType })).filter(x => x === false)
			.length === PROCESSABLE_HISTORY_TYPES.length
	if (syncDisabled) {
		logger.warn(
			'⚠️ DANGER: DISABLING ALL SYNC BY shouldSyncHistoryMsg PREVENTS BAILEYS FROM ACCESSING INITIAL LID MAPPINGS, LEADING TO INSTABILITY AND SESSION ERRORS'
		)
	}

	const url = typeof waWebSocketUrl === 'string' ? new URL(waWebSocketUrl) : waWebSocketUrl

	if (config.mobile || url.protocol === 'tcp:') {
		throw new Boom('Mobile API is not supported anymore', { statusCode: DisconnectReason.loggedOut })
	}

	if (url.protocol === 'wss' && authState?.creds?.routingInfo) {
		url.searchParams.append('ED', authState.creds.routingInfo.toString('base64url'))
	}

	/** ephemeral key pair used to encrypt/decrypt communication. Unique for each connection */
	const ephemeralKeyPair = Curve.generateKeyPair()
	/** WA noise protocol wrapper */
	const noise = makeNoiseHandler({
		keyPair: ephemeralKeyPair,
		NOISE_HEADER: NOISE_WA_HEADER,
		logger,
		routingInfo: authState?.creds?.routingInfo
	})

	const ws = new WebSocketClient(url, config)

	ws.connect()

	const sendPromise = promisify(ws.send)
	/** send a raw buffer */
	const sendRawMessage = async (data: Uint8Array | Buffer) => {
		if (!ws.isOpen) {
			throw new Boom('Connection Closed', { statusCode: DisconnectReason.connectionClosed })
		}

		const bytes = noise.encodeFrame(data)
		await promiseTimeout<void>(connectTimeoutMs, async (resolve, reject) => {
			try {
				await sendPromise.call(ws, bytes)
				resolve()
			} catch (error) {
				reject(error)
			}
		})
	}

	/** send a binary node */
	const sendNode = (frame: BinaryNode) => {
		if (logger.level === 'trace') {
			logger.trace({ xml: binaryNodeToString(frame), msg: 'xml send' })
		}

		const buff = encodeBinaryNode(frame)
		return sendRawMessage(buff)
	}

	/**
	 * Wait for a message with a certain tag to be received
	 * @param msgId the message tag to await
	 * @param timeoutMs timeout after which the promise will reject
	 */
	const waitForMessage = async <T>(msgId: string, timeoutMs = defaultQueryTimeoutMs) => {
		let onRecv: ((data: T) => void) | undefined
		let onErr: ((err: Error) => void) | undefined
		try {
			const result = await promiseTimeout<T>(timeoutMs, (resolve, reject) => {
				onRecv = data => {
					resolve(data)
				}

				onErr = err => {
					reject(
						err ||
							new Boom('Connection Closed', {
								statusCode: DisconnectReason.connectionClosed
							})
					)
				}

				ws.on(`TAG:${msgId}`, onRecv)
				ws.on('close', onErr)
				ws.on('error', onErr)

				return () => reject(new Boom('Query Cancelled'))
			})
			return result
		} catch (error) {
			if (error instanceof Boom && error.output?.statusCode === DisconnectReason.timedOut) {
				logger?.debug?.({ msgId }, 'timed out waiting for message')
				return undefined
			}

			throw error
		} finally {
			if (onRecv) ws.off(`TAG:${msgId}`, onRecv)
			if (onErr) {
				ws.off('close', onErr)
				ws.off('error', onErr)
			}
		}
	}

	/** send a query, and wait for its response. auto-generates message ID if not provided */
	const query = async (node: BinaryNode, timeoutMs?: number) => {
		if (!node.attrs.id) {
			node.attrs.id = generateMessageTag()
		}

		const msgId = node.attrs.id

		const result = await promiseTimeout<any>(timeoutMs, async (resolve, reject) => {
			const result = waitForMessage(msgId, timeoutMs).catch(reject)
			sendNode(node)
				.then(async () => resolve(await result))
				.catch(reject)
		})

		if (result && 'tag' in result) {
			assertNodeErrorFree(result)
		}

		return result
	}

	// Validate current key-bundle on server; on failure, trigger pre-key upload and rethrow
	const digestKeyBundle = async (): Promise<void> => {
		const res = await query({
			tag: 'iq',
			attrs: { to: S_WHATSAPP_NET, type: 'get', xmlns: 'encrypt' },
			content: [{ tag: 'digest', attrs: {} }]
		})
		const digestNode = getBinaryNodeChild(res, 'digest')
		if (!digestNode) {
			await uploadPreKeys()
			throw new Error('encrypt/get digest returned no digest node')
		}
	}

	// Rotate our signed pre-key on server
	const rotateSignedPreKey = async (): Promise<void> => {
		const newId = (creds.signedPreKey.keyId || 0) + 1
		const skey = await signedKeyPair(creds.signedIdentityKey, newId)
		await query({
			tag: 'iq',
			attrs: { to: S_WHATSAPP_NET, type: 'set', xmlns: 'encrypt' },
			content: [
				{
					tag: 'rotate',
					attrs: {},
					content: [xmppSignedPreKey(skey)]
				}
			]
		})
		ev.emit('creds.update', { signedPreKey: skey })
	}

	const executeUSyncQuery = async (usyncQuery: USyncQuery) => {
		if (usyncQuery.protocols.length === 0) {
			throw new Boom('USyncQuery must have at least one protocol')
		}

		const validUsers = usyncQuery.users

		const userNodes = validUsers.map(user => {
			return {
				tag: 'user',
				attrs: {
					jid: !user.phone ? user.id : undefined
				},
				content: usyncQuery.protocols.map(a => a.getUserElement(user)).filter(a => a !== null)
			} as BinaryNode
		})

		const listNode: BinaryNode = {
			tag: 'list',
			attrs: {},
			content: userNodes
		}

		const queryNode: BinaryNode = {
			tag: 'query',
			attrs: {},
			content: usyncQuery.protocols.map(a => a.getQueryElement())
		}

		const iq = {
			tag: 'iq',
			attrs: {
				to: S_WHATSAPP_NET,
				type: 'get',
				xmlns: 'usync'
			},
			content: [
				{
					tag: 'usync',
					attrs: {
						context: usyncQuery.context,
						mode: usyncQuery.mode,
						sid: generateMessageTag(),
						last: 'true',
						index: '0'
					},
					content: [queryNode, listNode]
				}
			]
		}

		const result = await query(iq)

		return usyncQuery.parseUSyncQueryResult(result)
	}

	const onWhatsApp = async (...phoneNumber: string[]) => {
		let usyncQuery = new USyncQuery()

		let contactEnabled = false
		for (const jid of phoneNumber) {
			if (isLidUser(jid)) {
				logger?.warn('LIDs are not supported with onWhatsApp')
				continue
			} else {
				if (!contactEnabled) {
					contactEnabled = true
					usyncQuery = usyncQuery.withContactProtocol()
				}

				const phone = `+${jid.replace('+', '').split('@')[0]?.split(':')[0]}`
				usyncQuery.withUser(new USyncUser().withPhone(phone))
			}
		}

		if (usyncQuery.users.length === 0) {
			return []
		}

		const results = await executeUSyncQuery(usyncQuery)

		if (results) {
			return results.list.filter(a => !!a.contact).map(({ contact, id }) => ({ jid: id, exists: contact as boolean }))
		}
	}

	const pnFromLIDUSync = async (jids: string[]): Promise<LIDMapping[] | undefined> => {
		const usyncQuery = new USyncQuery().withLIDProtocol().withContext('background')

		for (const jid of jids) {
			if (isLidUser(jid)) {
				logger?.warn('LID user found in LID fetch call')
				continue
			} else {
				usyncQuery.withUser(new USyncUser().withId(jid))
			}
		}

		if (usyncQuery.users.length === 0) {
			return []
		}

		const results = await executeUSyncQuery(usyncQuery)

		if (results) {
			return results.list.filter(a => !!a.lid).map(({ lid, id }) => ({ pn: id, lid: lid as string }))
		}

		return []
	}

	const ev = makeEventBuffer(logger)

	const { creds } = authState
	const keys = addTransactionCapability(authState.keys, logger, transactionOpts)
	const signalRepository = makeSignalRepository({ creds, keys }, logger, pnFromLIDUSync)

	let lastDateRecv: Date
	let epoch = 1
	let keepAliveReq: NodeJS.Timeout
	let qrTimer: NodeJS.Timeout
	let closed = false
	/** guards against the 'open' handler running the handshake twice on the same socket */
	let handshakeStarted = false

	/**
	 * Prekey health interval — runs every 6 h while the socket is alive so a 24/7
	 * bot can self-heal from exhausted/corrupted prekeys without a manual session wipe.
	 */
	let preKeyHealthInterval: NodeJS.Timeout | undefined
	const PRE_KEY_HEALTH_CHECK_INTERVAL_MS = 6 * 60 * 60 * 1000 // 6 hours

	/**
	 * Circuit-breaker state for prekey health checks.
	 * After PREKEY_MAX_CONSECUTIVE_FAILURES consecutive failures the checker backs off
	 * for PREKEY_FAILURE_BACKOFF_MS, preventing server hammering during outages.
	 */
	let preKeyConsecutiveFailures = 0
	let preKeyBackoffUntil = 0
	let preKeyLastCheckedAt = 0
	const PREKEY_CHECK_COOLDOWN_MS = 5 * 60 * 1000       // min 5 min between checks
	const PREKEY_MAX_CONSECUTIVE_FAILURES = 5
	const PREKEY_FAILURE_BACKOFF_MS = 30 * 60 * 1000     // 30 min backoff after max failures

	const socketEndHandlers: Array<(error: Error | undefined) => void | Promise<void>> = []

	/** log & process any unexpected errors */
	const onUnexpectedError = (err: Error | Boom, msg: string) => {
		logger.error({ err }, `unexpected error in '${msg}'`)
	}

	/** await the next incoming message */
	const awaitNextMessage = async <T>(sendMsg?: Uint8Array) => {
		if (!ws.isOpen) {
			throw new Boom('Connection Closed', {
				statusCode: DisconnectReason.connectionClosed
			})
		}

		let onOpen: (data: T) => void
		let onClose: (err: Error) => void

		const result = promiseTimeout<T>(connectTimeoutMs, (resolve, reject) => {
			onOpen = resolve
			onClose = mapWebSocketError(reject)
			ws.on('frame', onOpen)
			ws.on('close', onClose)
			ws.on('error', onClose)
		}).finally(() => {
			ws.off('frame', onOpen)
			ws.off('close', onClose)
			ws.off('error', onClose)
		})

		if (sendMsg) {
			sendRawMessage(sendMsg).catch(onClose!)
		}

		return result
	}

	/** connection handshake */
	const validateConnection = async () => {
		let helloMsg: proto.IHandshakeMessage = {
			clientHello: { ephemeral: ephemeralKeyPair.public }
		}
		helloMsg = proto.HandshakeMessage.fromObject(helloMsg)

		logger.info({ browser, helloMsg }, 'connected to WA')

		const init = proto.HandshakeMessage.encode(helloMsg).finish()

		const result = await awaitNextMessage<Uint8Array>(init)
		const handshake = proto.HandshakeMessage.decode(result)

		logger.trace({ handshake }, 'handshake recv from WA')

		const keyEnc = noise.processHandshake(handshake, creds.noiseKey)

		let node: proto.IClientPayload
		if (!creds.me) {
			node = generateRegistrationNode(creds, config)
			logger.info({ node }, 'not logged in, attempting registration...')
		} else {
			node = generateLoginNode(creds.me.id, config)
			logger.info({ node }, 'logging in...')
		}

		const payloadEnc = noise.encrypt(proto.ClientPayload.encode(node).finish())
		await sendRawMessage(
			proto.HandshakeMessage.encode({
				clientFinish: {
					static: keyEnc,
					payload: payloadEnc
				}
			}).finish()
		)
		await noise.finishInit()
		startKeepAliveRequest()
	}

	const getAvailablePreKeysOnServer = async () => {
		const result = await query({
			tag: 'iq',
			attrs: {
				id: generateMessageTag(),
				xmlns: 'encrypt',
				type: 'get',
				to: S_WHATSAPP_NET
			},
			content: [{ tag: 'count', attrs: {} }]
		})
		const countChild = getBinaryNodeChild(result, 'count')!
		return +countChild.attrs.value!
	}

	// WAWeb has no time throttle here; the server drives uploads via PreKeyLow notifications.
	let uploadPreKeysPromise: Promise<void> | null = null

	/** generates and uploads a set of pre-keys to the server */
	const uploadPreKeys = async (count = MIN_PREKEY_COUNT) => {
		if (uploadPreKeysPromise) {
			logger.debug('pre-key upload already in progress, waiting for completion')
			await uploadPreKeysPromise
			return
		}

		const uploadLogic = async (retryCount: number): Promise<void> => {
			logger.info({ count, retryCount }, 'uploading pre-keys')

			// Generate and save pre-keys atomically (prevents ID collisions on retry)
			const node = await keys.transaction(async () => {
				logger.debug({ requestedCount: count }, 'generating pre-keys with requested count')
				const { update, node } = await getNextPreKeysNode({ creds, keys }, count)
				// Update credentials immediately to prevent duplicate IDs on retry
				ev.emit('creds.update', update)
				return node
			}, creds?.me?.id || 'upload-pre-keys')

			// Upload to server (outside transaction — can fail without affecting local keys)
			try {
				await query(node)
				logger.info({ count }, 'uploaded pre-keys successfully')
			} catch (uploadError) {
				logger.warn(
					{ count, attempt: retryCount + 1, err: (uploadError as Error).message },
					'pre-key upload to server failed'
				)

				if (retryCount < 3) {
					const backoffDelay = Math.min(1000 * Math.pow(2, retryCount), 10000)
					logger.debug({ backoffDelay }, 'retrying pre-key upload')
					await new Promise(resolve => setTimeout(resolve, backoffDelay))
					return uploadLogic(retryCount + 1)
				}

				throw uploadError
			}
		}

		// Add timeout protection
		uploadPreKeysPromise = Promise.race([
			uploadLogic(0),
			new Promise<void>((_, reject) =>
				setTimeout(() => reject(new Boom('Pre-key upload timeout', { statusCode: 408 })), UPLOAD_TIMEOUT)
			)
		])

		try {
			await uploadPreKeysPromise
		} finally {
			uploadPreKeysPromise = null
		}
	}

	const verifyCurrentPreKeyExists = async () => {
		const currentPreKeyId = creds.nextPreKeyId - 1
		if (currentPreKeyId <= 0) {
			return { exists: false, currentPreKeyId: 0 }
		}

		const preKeys = await keys.get('pre-key', [currentPreKeyId.toString()])
		const exists = !!preKeys[currentPreKeyId.toString()]

		return { exists, currentPreKeyId }
	}

	/**
	 * Checks whether we need to upload prekeys to the server and uploads if so.
	 *
	 * Guards:
	 * - Cooldown gate  : skips if called within PREKEY_CHECK_COOLDOWN_MS of the last check
	 * - Circuit breaker: backs off for PREKEY_FAILURE_BACKOFF_MS after too many consecutive failures
	 *
	 * Both guards are bypassed when force=true (used on first login).
	 * Never throws — prekey failures must not disconnect the session.
	 */
	const uploadPreKeysToServerIfRequired = async (force = false) => {
		const now = Date.now()

		// Circuit breaker: in backoff window after repeated failures
		if (!force && now < preKeyBackoffUntil) {
			logger.debug(
				{ resumesIn: Math.round((preKeyBackoffUntil - now) / 1000) + 's' },
				'prekey check skipped (circuit breaker active)'
			)
			return
		}

		// Cooldown: avoid hammering the server on rapid reconnects
		if (!force && now - preKeyLastCheckedAt < PREKEY_CHECK_COOLDOWN_MS) {
			logger.debug('prekey check skipped (cooldown)')
			return
		}

		preKeyLastCheckedAt = now

		try {
			let count = 0
			const preKeyCount = await getAvailablePreKeysOnServer()
			if (preKeyCount === 0) count = INITIAL_PREKEY_COUNT
			else count = MIN_PREKEY_COUNT
			const { exists: currentPreKeyExists, currentPreKeyId } = await verifyCurrentPreKeyExists()

			const lowServerCount = preKeyCount <= count
			const missingCurrentPreKey = !currentPreKeyExists && currentPreKeyId > 0
			const shouldUpload = lowServerCount || missingCurrentPreKey

			if (shouldUpload) {
				const reasons: string[] = []
				if (lowServerCount) reasons.push(`server count low (${preKeyCount})`)
				if (missingCurrentPreKey) reasons.push(`prekey ${currentPreKeyId} missing from storage`)

				logger.info({ reasons }, 'uploading prekeys')
				await uploadPreKeys(count)
			} else {
				logger.debug(
					{ serverCount: preKeyCount, currentPreKeyId, currentPreKeyExists },
					'prekey health OK'
				)
			}

			// Success — reset circuit breaker
			preKeyConsecutiveFailures = 0
			preKeyBackoffUntil = 0
		} catch (error) {
			preKeyConsecutiveFailures++

			if (preKeyConsecutiveFailures >= PREKEY_MAX_CONSECUTIVE_FAILURES) {
				preKeyBackoffUntil = Date.now() + PREKEY_FAILURE_BACKOFF_MS
				logger.warn(
					{ failures: preKeyConsecutiveFailures, backoffMs: PREKEY_FAILURE_BACKOFF_MS },
					'prekey circuit breaker tripped — pausing checks'
				)
				preKeyConsecutiveFailures = 0 // reset counter for next window
			} else {
				logger.warn(
					{ err: (error as Error).message, failures: preKeyConsecutiveFailures },
					'prekey health check failed'
				)
			}
			// Never throw — prekey failures must not disconnect the session
		}
	}

	const onMessageReceived = async (data: Buffer) => {
		await noise.decodeFrame(data, frame => {
			// reset ping timeout
			lastDateRecv = new Date()

			let anyTriggered = false

			anyTriggered = ws.emit('frame', frame)
			// if it's a binary node
			if (!(frame instanceof Uint8Array)) {
				const msgId = frame.attrs.id

				if (logger.level === 'trace') {
					logger.trace({ xml: binaryNodeToString(frame), msg: 'recv xml' })
				}

				/* Check if this is a response to a message we sent */
				anyTriggered = ws.emit(`${DEF_TAG_PREFIX}${msgId}`, frame) || anyTriggered
				/* Check if this is a response to a message we are expecting */
				const l0 = frame.tag
				const l1 = frame.attrs || {}
				const l2 = Array.isArray(frame.content) ? frame.content[0]?.tag : ''

				for (const key of Object.keys(l1)) {
					anyTriggered = ws.emit(`${DEF_CALLBACK_PREFIX}${l0},${key}:${l1[key]},${l2}`, frame) || anyTriggered
					anyTriggered = ws.emit(`${DEF_CALLBACK_PREFIX}${l0},${key}:${l1[key]}`, frame) || anyTriggered
					anyTriggered = ws.emit(`${DEF_CALLBACK_PREFIX}${l0},${key}`, frame) || anyTriggered
				}

				anyTriggered = ws.emit(`${DEF_CALLBACK_PREFIX}${l0},,${l2}`, frame) || anyTriggered
				anyTriggered = ws.emit(`${DEF_CALLBACK_PREFIX}${l0}`, frame) || anyTriggered

				if (!anyTriggered && logger.level === 'debug') {
					logger.debug({ unhandled: true, msgId, fromMe: false, frame }, 'communication recv')
				}
			}
		})
	}

	const end = async (error: Error | undefined) => {
		if (closed) {
			logger.trace({ trace: error?.stack }, 'connection already closed')
			return
		}

		closed = true

		// Classify log level: auth/forbidden errors are expected terminal states,
		// not surprise failures
		const statusCode = (error as Boom)?.output?.statusCode
		const isFatalLogout = statusCode && UNAUTHORIZED_CODES.includes(statusCode)

		if (isFatalLogout) {
			logger.info({ statusCode, trace: error?.stack }, 'connection terminated (logged out)')
		} else {
			logger.info({ trace: error?.stack }, error ? 'connection errored' : 'connection closed')
		}

		clearInterval(keepAliveReq)
		clearTimeout(qrTimer)
		clearInterval(preKeyHealthInterval)
		handshakeStarted = false
		uploadPreKeysPromise = null

		// Detach every listener: prevents leaking closures if the caller holds a stale reference,
		// and guarantees a fresh makeSocket() call never ends up with two live sockets reacting
		// to the same underlying connection.
		ws.removeAllListeners()

		try {
			signalRepository.close?.()
		} catch (closeErr) {
			logger.trace({ closeErr }, 'error while closing signal repository')
		}

		if (!ws.isClosed && !ws.isClosing) {
			try {
				await ws.close()
			} catch (closeErr) {
				logger.trace({ closeErr }, 'error while closing websocket')
			}
		}

		for (const handler of socketEndHandlers) {
			try {
				await handler(error)
			} catch (err) {
				logger.warn({ err }, 'error in socket end handler')
			}
		}

		ev.emit('connection.update', {
			connection: 'close',
			lastDisconnect: {
				error,
				date: new Date()
			}
		})
		ev.removeAllListeners('connection.update')
		ev.destroy()
	}

	const waitForSocketOpen = async () => {
		if (ws.isOpen) {
			return
		}

		if (ws.isClosed || ws.isClosing) {
			throw new Boom('Connection Closed', { statusCode: DisconnectReason.connectionClosed })
		}

		let onOpen: () => void
		let onClose: (err: Error) => void
		await new Promise((resolve, reject) => {
			onOpen = () => resolve(undefined)
			onClose = mapWebSocketError(reject)
			ws.on('open', onOpen)
			ws.on('close', onClose)
			ws.on('error', onClose)
		}).finally(() => {
			ws.off('open', onOpen)
			ws.off('close', onClose)
			ws.off('error', onClose)
		})
	}

	const startKeepAliveRequest = () =>
		(keepAliveReq = setInterval(() => {
			if (!lastDateRecv) {
				lastDateRecv = new Date()
			}

			const diff = Date.now() - lastDateRecv.getTime()

			if (diff > keepAliveIntervalMs + 5000) {
				// Server has been silent longer than expected — network is likely down
				void end(new Boom('Connection was lost', { statusCode: DisconnectReason.connectionLost }))
			} else if (ws.isOpen) {
				// Send keep-alive ping. Log failures at debug — a single missed ping
				// is a transient hiccup; the diff check above handles sustained silence.
				query({
					tag: 'iq',
					attrs: {
						id: generateMessageTag(),
						to: S_WHATSAPP_NET,
						type: 'get',
						xmlns: 'w:p'
					},
					content: [{ tag: 'ping', attrs: {} }]
				}).catch(err => {
					logger.debug({ code: (err as Boom)?.output?.statusCode }, 'keep-alive ping missed')
				})
			} else {
				logger.debug('keep-alive skipped: WebSocket not open')
			}
		}, keepAliveIntervalMs))

	/** i have no idea why this exists. pls enlighten me */
	const sendPassiveIq = (tag: 'passive' | 'active') =>
		query({
			tag: 'iq',
			attrs: {
				to: S_WHATSAPP_NET,
				xmlns: 'passive',
				type: 'set'
			},
			content: [{ tag, attrs: {} }]
		})

	/** logout & invalidate connection */
	const logout = async (msg?: string) => {
		const jid = authState.creds.me?.id
		if (jid) {
			await sendNode({
				tag: 'iq',
				attrs: {
					to: S_WHATSAPP_NET,
					type: 'set',
					id: generateMessageTag(),
					xmlns: 'md'
				},
				content: [
					{
						tag: 'remove-companion-device',
						attrs: {
							jid,
							reason: 'user_initiated'
						}
					}
				]
			})
		}

		void end(new Boom(msg || 'Intentional Logout', { statusCode: DisconnectReason.loggedOut }))
	}

	const requestPairingCode = async (phoneNumber: string, customPairingCode?: string): Promise<string> => {
		const pairingCode = customPairingCode ?? bytesToCrockford(randomBytes(5))

		if (customPairingCode && customPairingCode?.length !== 8) {
			throw new Error('Custom pairing code must be exactly 8 chars')
		}

		authState.creds.pairingCode = pairingCode

		authState.creds.me = {
			id: jidEncode(phoneNumber, 's.whatsapp.net'),
			name: '~'
		}
		ev.emit('creds.update', authState.creds)
		await sendNode({
			tag: 'iq',
			attrs: {
				to: S_WHATSAPP_NET,
				type: 'set',
				id: generateMessageTag(),
				xmlns: 'md'
			},
			content: [
				{
					tag: 'link_code_companion_reg',
					attrs: {
						jid: authState.creds.me.id,
						stage: 'companion_hello',
						should_show_push_notification: 'true'
					},
					content: [
						{
							tag: 'link_code_pairing_wrapped_companion_ephemeral_pub',
							attrs: {},
							content: await generatePairingKey()
						},
						{
							tag: 'companion_server_auth_key_pub',
							attrs: {},
							content: authState.creds.noiseKey.public
						},
						{
							tag: 'companion_platform_id',
							attrs: {},
							content: getCompanionPlatformId(browser)
						},
						{
							tag: 'companion_platform_display',
							attrs: {},
							content: `${browser[1]} (${browser[0]})`
						},
						{
							tag: 'link_code_pairing_nonce',
							attrs: {},
							content: '0'
						}
					]
				}
			]
		})
		return authState.creds.pairingCode
	}

	async function generatePairingKey() {
		const salt = randomBytes(32)
		const randomIv = randomBytes(16)
		const key = await derivePairingCodeKey(authState.creds.pairingCode!, salt)
		const ciphered = aesEncryptCTR(authState.creds.pairingEphemeralKeyPair.public, key, randomIv)
		return Buffer.concat([salt, randomIv, ciphered])
	}

	const sendWAMBuffer = (wamBuffer: Buffer) => {
		return query({
			tag: 'iq',
			attrs: {
				to: S_WHATSAPP_NET,
				id: generateMessageTag(),
				xmlns: 'w:stats'
			},
			content: [
				{
					tag: 'add',
					attrs: { t: Math.round(Date.now() / 1000) + '' },
					content: wamBuffer
				}
			]
		})
	}

	// ─── WebSocket event handlers ────────────────────────────────────────────────
	// Every async handler is wrapped in try/catch so that a thrown exception never
	// becomes an unhandled rejection and never silently kills the socket.

	ws.on('message', onMessageReceived)

	ws.on('open', async () => {
		if (handshakeStarted) {
			logger.debug('ignoring duplicate "open" event — handshake already in progress')
			return
		}

		handshakeStarted = true

		try {
			await validateConnection()
		} catch (err: any) {
			logger.error({ err }, 'error in validating connection')
			void end(err)
		}
	})

	ws.on('error', mapWebSocketError(end))
	ws.on('close', () => void end(new Boom('Connection Terminated', { statusCode: DisconnectReason.connectionClosed })))

	// The server terminated the connection
	ws.on(
		'CB:xmlstreamend',
		() => void end(new Boom('Connection Terminated by Server', { statusCode: DisconnectReason.connectionClosed }))
	)

	// ─── QR generation ──────────────────────────────────────────────────────────
	ws.on('CB:iq,type:set,pair-device', async (stanza: BinaryNode) => {
		try {
			const iq: BinaryNode = {
				tag: 'iq',
				attrs: {
					to: S_WHATSAPP_NET,
					type: 'result',
					id: stanza.attrs.id!
				}
			}
			await sendNode(iq)

			const pairDeviceNode = getBinaryNodeChild(stanza, 'pair-device')
			const refNodes = getBinaryNodeChildren(pairDeviceNode, 'ref')
			const noiseKeyB64 = Buffer.from(creds.noiseKey.public).toString('base64')
			const identityKeyB64 = Buffer.from(creds.signedIdentityKey.public).toString('base64')
			const advB64 = creds.advSecretKey

			let qrMs = qrTimeout || 60_000
			const genPairQR = () => {
				if (!ws.isOpen) {
					return
				}

				const refNode = refNodes.shift()
				if (!refNode) {
					void end(new Boom('QR refs attempts ended', { statusCode: DisconnectReason.timedOut }))
					return
				}

				const ref = (refNode.content as Buffer).toString('utf-8')
				const qr = buildPairingQRData(ref, noiseKeyB64, identityKeyB64, advB64, browser)

				ev.emit('connection.update', { qr })

				qrTimer = setTimeout(genPairQR, qrMs)
				qrMs = qrTimeout || 20_000
			}

			genPairQR()
		} catch (err) {
			logger.error({ err }, 'error handling pair-device')
			void end(err as Error)
		}
	})

	// ─── Device paired for the first time ───────────────────────────────────────
	ws.on('CB:iq,,pair-success', async (stanza: BinaryNode) => {
		logger.debug('pair success recv')
		try {
			updateServerTimeOffset(stanza)
			const { reply, creds: updatedCreds } = configureSuccessfulPairing(stanza, creds)

			logger.info(
				{ me: updatedCreds.me, platform: updatedCreds.platform },
				'pairing configured successfully, expect to restart the connection...'
			)

			ev.emit('creds.update', updatedCreds)
			ev.emit('connection.update', { isNewLogin: true, qr: undefined })

			await sendNode(reply)
			void sendUnifiedSession()
		} catch (error: any) {
			logger.warn({ trace: error.stack }, 'error in pairing')
			void end(error)
		}
	})

	// ─── Login complete ──────────────────────────────────────────────────────────
	ws.on('CB:success', async (node: BinaryNode) => {
		try {
			updateServerTimeOffset(node)

			// force=true so the first check after login bypasses the cooldown gate
			await uploadPreKeysToServerIfRequired(true)
			await sendPassiveIq('active')

			// Validate key-bundle against server after login
			try {
				await digestKeyBundle()
			} catch (e) {
				logger.debug({ e }, 'digest check after login failed — will retry on next health cycle')
			}
		} catch (err) {
			logger.warn({ err }, 'failed to send initial passive iq')
		}

		logger.info('opened connection to WA')
		clearTimeout(qrTimer)

		// Start the recurring prekey health check.
		// This lets a 24/7 bot self-heal from exhausted/corrupted prekeys without
		// any manual intervention — the same logic that runs once at login now keeps
		// running for the lifetime of the socket.
		clearInterval(preKeyHealthInterval)
		preKeyHealthInterval = setInterval(() => {
			uploadPreKeysToServerIfRequired().catch(err => {
				// Already handled inside uploadPreKeysToServerIfRequired, but guard
				// again here so an unexpected throw never kills the interval
				logger.debug({ err }, 'prekey health interval: unexpected error (already handled)')
			})
		}, PRE_KEY_HEALTH_CHECK_INTERVAL_MS)

		ev.emit('creds.update', { me: { ...authState.creds.me!, lid: node.attrs.lid } })
		ev.emit('connection.update', { connection: 'open' })
		void sendUnifiedSession()

		if (node.attrs.lid && authState.creds.me?.id) {
			const myLID = node.attrs.lid
			process.nextTick(async () => {
				try {
					const myPN = authState.creds.me!.id

					await signalRepository.lidMapping.storeLIDPNMappings([{ lid: myLID, pn: myPN }])

					const { user, device } = jidDecode(myPN)!
					await authState.keys.set({
						'device-list': {
							[user]: [device?.toString() || '0']
						}
					})

					await signalRepository.migrateSession(myPN, myLID)

					logger.info({ myPN, myLID }, 'own LID session created successfully')
				} catch (error) {
					logger.warn({ error, lid: myLID }, 'failed to create own LID session')
				}
			})
		}
	})

	// ─── Server notifies prekey count is low — upload immediately ───────────────
	ws.on('CB:notification,,encrypt', (node: BinaryNode) => {
		try {
			const countNode = getBinaryNodeChild(node, 'count')
			if (countNode) {
				const serverCount = +countNode.attrs.value
				logger.debug({ serverCount }, 'server sent prekey count notification')

				if (serverCount <= MIN_PREKEY_COUNT) {
					logger.info({ serverCount }, 'server reports low prekey count — uploading now')
					uploadPreKeys(MIN_PREKEY_COUNT).catch(err => {
						logger.warn({ err }, 'failed to upload prekeys after server low-count notification')
					})
				}
			}
		} catch (err) {
			logger.debug({ err }, 'error handling encrypt notification')
		}
	})

	// ─── Stream errors ───────────────────────────────────────────────────────────
	ws.on('CB:stream:error', (node: BinaryNode) => {
		const [reasonNode] = getAllBinaryNodeChildren(node)
		const { reason, statusCode } = getErrorCodeFromStreamError(node)

		// Fatal auth errors are expected terminal states — log at warn, not error
		const isFatal = statusCode && UNAUTHORIZED_CODES.includes(statusCode)
		if (isFatal) {
			logger.warn({ reason, statusCode }, 'stream error (fatal — session terminated)')
		} else {
			logger.warn({ reason, statusCode, reasonNode }, 'stream error')
		}

		void end(new Boom(`Stream Errored (${reason})`, { statusCode, data: reasonNode || node }))
	})

	// Stream fail, possible logout
	ws.on('CB:failure', (node: BinaryNode) => {
		const reason = +(node.attrs.reason || 500)
		logger.warn({ reason, attrs: node.attrs }, 'connection failure')
		void end(new Boom('Connection Failure', { statusCode: reason, data: node.attrs }))
	})

	ws.on('CB:ib,,downgrade_webclient', () => {
		void end(new Boom('Multi-device beta not joined', { statusCode: DisconnectReason.multideviceMismatch }))
	})

	ws.on('CB:ib,,offline_preview', async (node: BinaryNode) => {
		logger.debug('offline preview received')
		try {
			await sendNode({
				tag: 'ib',
				attrs: {},
				content: [{ tag: 'offline_batch', attrs: { count: '100' } }]
			})
		} catch (err) {
			logger.debug({ err }, 'error sending offline_batch response')
		}
	})

	ws.on('CB:ib,,edge_routing', (node: BinaryNode) => {
		try {
			const edgeRoutingNode = getBinaryNodeChild(node, 'edge_routing')
			const routingInfo = getBinaryNodeChild(edgeRoutingNode, 'routing_info')
			if (routingInfo?.content) {
				authState.creds.routingInfo = Buffer.from(routingInfo?.content as Uint8Array)
				ev.emit('creds.update', authState.creds)
			}
		} catch (err) {
			logger.debug({ err }, 'error handling edge_routing')
		}
	})

	// ─── Offline notification flush ──────────────────────────────────────────────
	let didStartBuffer = false
	process.nextTick(() => {
		if (creds.me?.id) {
			ev.buffer()
			didStartBuffer = true
		}

		ev.emit('connection.update', { connection: 'connecting', receivedPendingNotifications: false, qr: undefined })
	})

	// Called when all offline notifications are processed
	ws.on('CB:ib,,offline', (node: BinaryNode) => {
		try {
			const child = getBinaryNodeChild(node, 'offline')
			const offlineNotifs = +(child?.attrs.count || 0)

			logger.info(`handled ${offlineNotifs} offline messages/notifications`)
			if (didStartBuffer) {
				ev.flush()
				logger.trace('flushed events for initial buffer')
			}

			ev.emit('connection.update', { receivedPendingNotifications: true })
		} catch (err) {
			logger.warn({ err }, 'error handling offline notification flush')
		}
	})

	// ─── Credential updates ──────────────────────────────────────────────────────
	ev.on('creds.update', update => {
		try {
			const name = update.me?.name
			if (creds.me?.name !== name) {
				logger.debug({ name }, 'updated pushName')
				sendNode({
					tag: 'presence',
					attrs: { name: name! }
				}).catch(err => {
					logger.debug({ err }, 'error sending presence update on name change')
				})
			}

			Object.assign(creds, update)
		} catch (err) {
			logger.warn({ err }, 'error in creds.update handler')
		}
	})

	// ─── Server time sync ────────────────────────────────────────────────────────
	const updateServerTimeOffset = ({ attrs }: BinaryNode) => {
		const tValue = attrs?.t
		if (!tValue) {
			return
		}

		const parsed = Number(tValue)
		if (Number.isNaN(parsed) || parsed <= 0) {
			return
		}

		const localMs = Date.now()
		serverTimeOffsetMs = parsed * 1000 - localMs
		logger.debug({ offset: serverTimeOffsetMs }, 'calculated server time offset')
	}

	const getUnifiedSessionId = () => {
		const offsetMs = 3 * TimeMs.Day
		const now = Date.now() + serverTimeOffsetMs
		const id = (now + offsetMs) % TimeMs.Week
		return id.toString()
	}

	const sendUnifiedSession = async () => {
		if (!ws.isOpen) {
			return
		}

		const node = {
			tag: 'ib',
			attrs: {},
			content: [
				{
					tag: 'unified_session',
					attrs: {
						id: getUnifiedSessionId()
					}
				}
			]
		}

		try {
			await sendNode(node)
		} catch (error) {
			logger.debug({ error }, 'failed to send unified_session telemetry')
		}
	}

	const registerSocketEndHandler = (handler: (error: Error | undefined) => void | Promise<void>) => {
		socketEndHandlers.push(handler)
	}

	/**
	 * Fetches your account's standing when it comes to restrictions.
	 * @returns Returns the state of the restrictions.
	 */
	const fetchAccountReachoutTimelock = async () => {
		const queryResult = await executeWMexQuery<{
			is_active?: boolean
			time_enforcement_ends?: string
			enforcement_type: ReachoutTimelockEnforcementType
		}>({}, QueryIds.REACHOUT_TIMELOCK, XWAPaths.xwa2_fetch_account_reachout_timelock, query, generateMessageTag)
		const result: ReachoutTimelockState = {
			isActive: !!queryResult?.is_active,
			timeEnforcementEnds:
				queryResult?.time_enforcement_ends && queryResult?.time_enforcement_ends !== '0'
					? new Date(parseInt(queryResult.time_enforcement_ends, 10) * 1000)
					: undefined,
			enforcementType: queryResult?.enforcement_type ?? ReachoutTimelockEnforcementType.DEFAULT
		}
		ev.emit('connection.update', { reachoutTimeLock: result })
		return result
	}

	/**
	 * Fetches your account's new chat limits.
	 * @returns Returns the quota and the usage.
	 */
	const fetchNewChatMessageCap = async () => {
		return executeWMexQuery<NewChatMessageCapInfo>(
			{ input: { type: 'INDIVIDUAL_NEW_CHAT_MSG' } },
			QueryIds.MESSAGE_CAPPING_INFO,
			XWAPaths.xwa2_message_capping_info,
			query,
			generateMessageTag
		)
	}

	return {
		type: 'md' as 'md',
		ws,
		ev,
		authState: { creds, keys },
		signalRepository,
		get user() {
			return authState.creds.me
		},
		generateMessageTag,
		query,
		waitForMessage,
		waitForSocketOpen,
		sendRawMessage,
		sendNode,
		logout,
		end,
		registerSocketEndHandler,
		onUnexpectedError,
		uploadPreKeys,
		uploadPreKeysToServerIfRequired,
		digestKeyBundle,
		rotateSignedPreKey,
		requestPairingCode,
		updateServerTimeOffset,
		sendUnifiedSession,
		wamBuffer: publicWAMBuffer,
		/** Waits for the connection to WA to reach a state */
		waitForConnectionUpdate: bindWaitForConnectionUpdate(ev),
		sendWAMBuffer,
		executeUSyncQuery,
		onWhatsApp,
		fetchAccountReachoutTimelock,
		fetchNewChatMessageCap
	}
}

/**
 * Map the websocket error to the right Boom type so the caller's
 * reconnection logic can inspect the status code.
 */
function mapWebSocketError(handler: (err: Error) => void) {
	return (error: Error) => {
		handler(new Boom(`WebSocket Error (${error?.message})`, { statusCode: getCodeFromWSError(error), data: error }))
	}
}
