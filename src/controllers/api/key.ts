import type { Request, Response } from 'express';
import { StatusCodes } from 'http-status-codes';
import { IdentityServiceStrategySetup } from '../../services/identity/index.js';
import { decryptPrivateKey } from '../../helpers/helpers.js';
import { toString } from 'uint8arrays';
import type {
	CreateKeyResponseBody,
	GetKeyRequestBody,
	ImportKeyRequestBody,
	ImportKeyResponseBody,
	QueryKeyResponseBody,
	UnsuccessfulCreateKeyResponseBody,
	UnsuccessfulImportKeyResponseBody,
	UnsuccessfulQueryKeyResponseBody,
} from '../../types/key.js';
import { check } from '../validator/index.js';
import { eventTracker } from '../../services/track/tracker.js';
import type { IKeyTrack, ITrackOperation } from '../../types/track.js';
import { OperationCategoryNameEnum, OperationNameEnum } from '../../types/constants.js';
import { validate } from '../validator/decorator.js';
import { SupportedKeyTypes } from '@veramo/utils';
import crypto from 'crypto';
import { deriveSymmetricKeyFromSecret } from '../../helpers/helpers.js';

// ToDo: Make the format of /key/create and /key/read the same
// ToDo: Add valdiation for /key/import
export class KeyController {
	public static keyCreateValidator = [
		check('type')
			.optional()
			.isString()
			.isIn([SupportedKeyTypes.Ed25519, SupportedKeyTypes.Secp256k1])
			.withMessage('Invalid key type')
			.bail(),
	];
	public static keyGetValidator = [
		check('kid')
			.exists()
			.withMessage('keyId was not provided')
			.isHexadecimal()
			.withMessage('keyId should be a hexadecimal string')
			.bail(),
	];
	public static keyImportValidator = [
		check('privateKeyHex')
			.exists()
			.withMessage('Private key was not provided')
			.isHexadecimal()
			.withMessage('Private key should be a hexadecimal string')
			.bail(),
		check('encrypted')
			.isBoolean()
			.withMessage('encrypted is required')
			.custom((value, { req }) => (value === true ? req.body.ivHex && req.body.salt : true))
			.withMessage('Property ivHex, salt is required when encrypted is set to true')
			.bail(),
		check('ivHex').optional().isHexadecimal().withMessage('ivHex should be a hexadecimal string').bail(),
		check('salt').optional().isHexadecimal().withMessage('salt should be a hexadecimal string').bail(),
		check('type').optional().isString().withMessage('type should be a string').bail(),
		check('alias').optional().isString().withMessage('alias should be a string').bail(),
	];
	public static keyExportValidator = [
		check('kid')
			.exists()
			.withMessage('keyId was not provided')
			.isHexadecimal()
			.withMessage('keyId should be a hexadecimal string')
			.bail(),
		check('includePrivateKey')
			.optional()
			.isBoolean()
			.withMessage('includePrivateKey should be a boolean')
			.bail(),
		check('encrypt')
			.optional()
			.isBoolean()
			.withMessage('encrypt should be a boolean')
			.bail(),
	];
	/**
	 * @openapi
	 *
	 * /key/create:
	 *   post:
	 *     tags: [ Key ]
	 *     summary: Create an identity key pair.
	 *     description: This endpoint creates an identity key pair associated with the user's account for custodian-mode clients.
	 *     parameters:
	 *       - name: type
	 *         description: Key type of the identity key pair to create.
	 *         in: query
	 *         schema:
	 *           type: string
	 *           enum:
	 *              - Ed25519
	 *              - Secp256k1
	 *     responses:
	 *       200:
	 *         description: The request was successful.
	 *         content:
	 *           application/json:
	 *             schema:
	 *               $ref: '#/components/schemas/KeyResult'
	 *       400:
	 *         description: A problem with the input fields has occurred. Additional state information plus metadata may be available in the response body.
	 *         content:
	 *           application/json:
	 *             schema:
	 *               $ref: '#/components/schemas/InvalidRequest'
	 *             example:
	 *               error: InvalidRequest
	 *       401:
	 *         $ref: '#/components/schemas/UnauthorizedError'
	 *       500:
	 *         description: An internal error has occurred. Additional state information plus metadata may be available in the response body.
	 *         content:
	 *           application/json:
	 *             schema:
	 *               $ref: '#/components/schemas/InvalidRequest'
	 *             example:
	 *               error: Internal Error
	 */
	public async createKey(request: Request, response: Response) {
		// Get strategy e.g. postgres or local
		const identityServiceStrategySetup = new IdentityServiceStrategySetup(response.locals.customer.customerId);
		try {
			const keyType = request.query.type as SupportedKeyTypes | undefined;
			const key = await identityServiceStrategySetup.agent.createKey(
				keyType || SupportedKeyTypes.Ed25519,
				response.locals.customer
			);

			eventTracker.emit('track', {
				name: OperationNameEnum.KEY_CREATE,
				category: OperationCategoryNameEnum.KEY,
				customer: response.locals.customer,
				user: response.locals.user,
				data: {
					keyRef: key.kid,
					keyType: key.type,
				} satisfies IKeyTrack,
			} satisfies ITrackOperation);
			// Return the response
			return response.status(StatusCodes.OK).json(key satisfies CreateKeyResponseBody);
		} catch (error) {
			return response.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
				error: `Internal error: ${(error as Error)?.message || error}`,
			} satisfies UnsuccessfulCreateKeyResponseBody);
		}
	}

	/**
	 * @openapi
	 *
	 * /key/import:
	 *   post:
	 *     tags: [ Key ]
	 *     summary: Import an identity key pair.
	 *     description: This endpoint imports an identity key pair associated with the user's account for custodian-mode clients.
	 *     requestBody:
	 *       content:
	 *         application/x-www-form-urlencoded:
	 *           schema:
	 *             $ref: '#/components/schemas/KeyImportRequest'
	 *         application/json:
	 *           schema:
	 *             $ref: '#/components/schemas/KeyImportRequest'
	 *     responses:
	 *       200:
	 *         description: The request was successful.
	 *         content:
	 *           application/json:
	 *             schema:
	 *               $ref: '#/components/schemas/KeyResult'
	 *       400:
	 *         description: A problem with the input fields has occurred. Additional state information plus metadata may be available in the response body.
	 *         content:
	 *           application/json:
	 *             schema:
	 *               $ref: '#/components/schemas/InvalidRequest'
	 *             example:
	 *               error: InvalidRequest
	 *       401:
	 *         $ref: '#/components/schemas/UnauthorizedError'
	 *       500:
	 *         description: An internal error has occurred. Additional state information plus metadata may be available in the response body.
	 *         content:
	 *           application/json:
	 *             schema:
	 *               $ref: '#/components/schemas/InvalidRequest'
	 *             example:
	 *               error: Internal Error
	 */
	@validate
	public async importKey(request: Request, response: Response) {
		const { type, encrypted = false, ivHex, salt, alias, privateKeyHex, encryptionMethod = 'aes-256-cbc' } = request.body as ImportKeyRequestBody;
		const identityServiceStrategySetup = new IdentityServiceStrategySetup(response.locals.customer.customerId);
		let decryptedPrivateKeyHex = privateKeyHex;

		try {
			if (encrypted) {
				if (ivHex && salt) {
					if (encryptionMethod === 'aes-gcm') {
						// New AES-GCM method
						const key = await deriveSymmetricKeyFromSecret(privateKeyHex, salt);
						const iv = Buffer.from(ivHex, 'hex');
						const encryptedBuffer = Buffer.from(privateKeyHex, 'hex');

						const decrypted = await crypto.subtle.decrypt(
							{
								name: 'AES-GCM',
								iv
							},
							key,
							encryptedBuffer
						);

						decryptedPrivateKeyHex = Buffer.from(decrypted).toString('utf8');
					} else {
						// Legacy AES-CBC method
						decryptedPrivateKeyHex = toString(await decryptPrivateKey(privateKeyHex, ivHex, salt), 'hex');
					}
				} else {
					return response.status(StatusCodes.BAD_REQUEST).json({
						error: `Invalid request: Property ivHex, salt is required when encrypted is set to true`,
					} satisfies UnsuccessfulImportKeyResponseBody);
				}
			}

			const key = await identityServiceStrategySetup.agent.importKey(
				type || 'Ed25519',
				decryptedPrivateKeyHex,
				response.locals.customer,
				alias
			);

			// Track the operation
			eventTracker.emit('track', {
				name: OperationNameEnum.KEY_IMPORT,
				category: OperationCategoryNameEnum.KEY,
				customer: response.locals.customer,
				user: response.locals.user,
				data: {
					keyRef: key.kid,
					keyType: key.type,
				} satisfies IKeyTrack,
			} satisfies ITrackOperation);
			// Return the response
			return response.status(StatusCodes.OK).json(key satisfies ImportKeyResponseBody);
		} catch (error) {
			return response.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
				error: `Internal error: ${(error as Error)?.message || error}`,
			} satisfies UnsuccessfulImportKeyResponseBody);
		}
	}

	/**
	 * @openapi
	 *
	 * /key/read/{kid}:
	 *   get:
	 *     tags: [ Key ]
	 *     summary: Fetch an identity key pair.
	 *     description: This endpoint fetches an identity key pair's details for a given key ID. Only the user account associated with the custodian-mode client can fetch the key pair.
	 *     parameters:
	 *       - name: kid
	 *         description: Key ID of the identity key pair to fetch.
	 *         in: path
	 *         schema:
	 *           type: string
	 *         required: true
	 *     responses:
	 *       200:
	 *         description: The request was successful.
	 *         content:
	 *           application/json:
	 *             schema:
	 *               $ref: '#/components/schemas/KeyResult'
	 *       400:
	 *         description: A problem with the input fields has occurred. Additional state information plus metadata may be available in the response body.
	 *         content:
	 *           application/json:
	 *             schema:
	 *               $ref: '#/components/schemas/InvalidRequest'
	 *             example:
	 *               error: InvalidRequest
	 *       401:
	 *         $ref: '#/components/schemas/UnauthorizedError'
	 *       500:
	 *         description: An internal error has occurred. Additional state information plus metadata may be available in the response body.
	 *         content:
	 *           application/json:
	 *             schema:
	 *               $ref: '#/components/schemas/InvalidRequest'
	 *             example:
	 *               error: Internal Error
	 */
	@validate
	public async getKey(request: Request, response: Response) {
		const { kid } = request.params as GetKeyRequestBody;
		// Get strategy e.g. postgres or local
		const identityServiceStrategySetup = new IdentityServiceStrategySetup(response.locals.customer.customerId);
		try {
			const key = await identityServiceStrategySetup.agent.getKey(kid, response.locals.customer);
			if (key) {
				return response.status(StatusCodes.OK).json(key satisfies QueryKeyResponseBody);
			}
			return response.status(StatusCodes.NOT_FOUND).json({
				error: `Key with kid: ${kid} not found`,
			} satisfies UnsuccessfulQueryKeyResponseBody);
		} catch (error) {
			return response.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
				error: `${error}`,
			} satisfies UnsuccessfulQueryKeyResponseBody);
		}
	}

	/**
	 * @openapi
	 *
	 * /key/export:
	 *   post:
	 *     tags: [ Key ]
	 *     summary: Export an identity key.
	 *     description: This endpoint exports an identity key associated with the user's account. Can optionally include the private key data and encrypt it.
	 *     requestBody:
	 *       content:
	 *         application/x-www-form-urlencoded:
	 *           schema:
	 *             $ref: '#/components/schemas/KeyExportRequest'
	 *         application/json:
	 *           schema:
	 *             $ref: '#/components/schemas/KeyExportRequest'
	 *     responses:
	 *       200:
	 *         description: The request was successful.
	 *         content:
	 *           application/json:
	 *             schema:
	 *               $ref: '#/components/schemas/KeyExportResponse'
	 *       400:
	 *         description: A problem with the input fields has occurred. Additional state information plus metadata may be available in the response body.
	 *         content:
	 *           application/json:
	 *             schema:
	 *               $ref: '#/components/schemas/InvalidRequest'
	 *             example:
	 *               error: InvalidRequest
	 *       401:
	 *         $ref: '#/components/schemas/UnauthorizedError'
	 *       404:
	 *         description: The requested key was not found.
	 *         content:
	 *           application/json:
	 *             schema:
	 *               $ref: '#/components/schemas/InvalidRequest'
	 *             example:
	 *               error: Key not found
	 *       500:
	 *         description: An internal error has occurred. Additional state information plus metadata may be available in the response body.
	 *         content:
	 *           application/json:
	 *             schema:
	 *               $ref: '#/components/schemas/InvalidRequest'
	 *             example:
	 *               error: Internal Error
	 */
	@validate
	public async exportKey(request: Request, response: Response) {
		const { kid, includePrivateKey = false, encrypt = false, password, encryptionMethod = 'aes-256-cbc' } = request.body;
		
		// Get strategy e.g. postgres or local
		const identityServiceStrategySetup = new IdentityServiceStrategySetup(response.locals.customer.customerId);
		
		try {
			// First check if the key exists
			const key = await identityServiceStrategySetup.agent.getKey(kid, response.locals.customer);
			
			if (!key) {
				return response.status(StatusCodes.NOT_FOUND).json({
					error: `Key with kid: ${kid} not found`,
				});
			}
			
			// Prepare the export data
			const exportData: any = {
				kid: key.kid,
				type: key.type,
				publicKeyHex: key.publicKeyHex,
				meta: key.meta,
			};
			
			// Include private key if requested
			if (includePrivateKey) {
				// Get the private key data
				const privateKeyData = await identityServiceStrategySetup.agent.exportKey(
					kid, 
					response.locals.customer
				);
				console.log('privateKeyData', privateKeyData);
				if (!privateKeyData || !privateKeyData.privateKeyHex) {
					return response.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
						error: `Failed to retrieve private key data: ${JSON.stringify(privateKeyData)}`,
					});
				}
				
				// If encryption is requested, encrypt the private key
				if (encrypt) {
					if (!password) {
						return response.status(StatusCodes.BAD_REQUEST).json({
							error: 'Password is required for encryption',
						});
					}

					const salt = crypto.randomBytes(16).toString('hex');
					const ivHex = crypto.randomBytes(16).toString('hex');
					
					if (encryptionMethod === 'aes-gcm') {
						// New AES-GCM method
						const key = await deriveSymmetricKeyFromSecret(password, salt);
						const iv = Buffer.from(ivHex, 'hex');
						const messageBuffer = Buffer.from(privateKeyData.privateKeyHex, 'utf8');
						
						const encrypted = await crypto.subtle.encrypt(
							{
								name: 'AES-GCM',
								iv
							},
							key,
							messageBuffer
						);

						exportData.privateKeyHex = Buffer.from(encrypted).toString('hex');
					} else {
						// Legacy AES-CBC method
						const keyBuffer = crypto.scryptSync(password, salt, 32);
						const cipher = crypto.createCipheriv(
							'aes-256-cbc',
							keyBuffer as crypto.BinaryLike,
							Buffer.from(ivHex, 'hex') as crypto.BinaryLike
						);
						let encryptedPrivateKeyHex = cipher.update(privateKeyData.privateKeyHex, 'hex', 'hex');
						encryptedPrivateKeyHex += cipher.final('hex');
						
						exportData.privateKeyHex = encryptedPrivateKeyHex;
					}

					exportData.encrypted = true;
					exportData.ivHex = ivHex;
					exportData.salt = salt;
					exportData.encryptionMethod = encryptionMethod;
				} else {
					exportData.privateKeyHex = privateKeyData.privateKeyHex;
					exportData.encrypted = false;
				}
			}
			
			// Track the operation
			eventTracker.emit('track', {
				name: OperationNameEnum.KEY_EXPORT,
				category: OperationCategoryNameEnum.KEY,
				customer: response.locals.customer,
				user: response.locals.user,
				data: {
					keyRef: key.kid,
					keyType: key.type,
					includesPrivateKey: includePrivateKey,
					encrypted: encrypt && includePrivateKey,
				} satisfies IKeyTrack,
			} satisfies ITrackOperation);
			
			// Return the response
			return response.status(StatusCodes.OK).json(exportData);
		} catch (error) {
			return response.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
				error: `Internal error: ${(error as Error)?.message || error}`,
			});
		}
	}
}
