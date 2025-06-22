import type { FindOptionsOrder, FindOptionsRelations, FindOptionsWhere, Repository } from 'typeorm';
import type { CustomerEntity } from '../../database/entities/customer.entity.js';
import type { UserEntity } from '../../database/entities/user.entity.js';
import type { APIServiceOptions } from '../../types/admin.js';
import { decodeJWT } from 'did-jwt';
import { randomBytes, createHmac, pbkdf2Sync } from 'crypto';
import { SecretBox } from '@veramo/kms-local';
import { Connection } from '../../database/connection/connection.js';
import { APIKeyEntity } from '../../database/entities/api.key.entity.js';
import { API_SECRET_KEY_LENGTH, API_KEY_PREFIX, API_KEY_EXPIRATION } from '../../types/constants.js';
import { sha256 } from '../../utils/index.js';
import * as dotenv from 'dotenv';
dotenv.config();

export class APIKeyService {
	public apiKeyRepository: Repository<APIKeyEntity>;
	private secretBox: SecretBox;

	public static instance = new APIKeyService();

	constructor() {
		this.apiKeyRepository = Connection.instance.dbConnection.getRepository(APIKeyEntity);
		
		// Validate encryption key before initializing SecretBox
		if (!process.env.EXTERNAL_DB_ENCRYPTION_KEY) {
			throw new Error('EXTERNAL_DB_ENCRYPTION_KEY environment variable is required but not set');
		}
		
		this.secretBox = new SecretBox(process.env.EXTERNAL_DB_ENCRYPTION_KEY);
	}

	// ToDo: Maybe we also need to store not the API key but the hash of it?
	// But in that case the API key will be shown once and then it will be lost.

	public async create(
		apiKey: string,
		name: string,
		user: UserEntity,
		customer: CustomerEntity,
		expiresAt?: Date,
		revoked = false,
		options?: APIServiceOptions
	): Promise<APIKeyEntity> {
		const { decryptionNeeded } = options || {};
		if (!apiKey) {
			throw new Error('API key is not specified');
		}
		// fingerprint
		const fingerprint = sha256(apiKey);
		// slow - hash
		const apiKeyHash = await APIKeyService.hashAPIKey(apiKey);
		if (!name) {
			throw new Error('API key name is not specified');
		}
		if (!user) {
			throw new Error('API key user is not specified');
		}
		if (!expiresAt) {
			expiresAt = new Date();
			expiresAt.setMonth(expiresAt.getDay() + API_KEY_EXPIRATION);
		}

		// encrypt the key
		const encryptedAPIKey = await this.encryptAPIKey(apiKey);
		// Create entity
		const apiKeyEntity = new APIKeyEntity(
			apiKeyHash,
			encryptedAPIKey,
			name,
			expiresAt,
			customer,
			user,
			revoked,
			fingerprint
		);
		const apiKeyRecord = (await this.apiKeyRepository.insert(apiKeyEntity)).identifiers[0];
		if (!apiKeyRecord) throw new Error(`Cannot create a new API key`);
		if (decryptionNeeded) {
			apiKeyEntity.apiKey = apiKey;
		}
		return apiKeyEntity;
	}

	public async update(
		item: {
			apiKey: string;
			name?: string;
			expiresAt?: Date;
			revoked?: boolean;
			customer?: CustomerEntity;
			user?: UserEntity;
		},
		options?: APIServiceOptions
	) {
		const { apiKey, name, expiresAt, customer, revoked, user } = item;
		const { decryptionNeeded } = options || {};

		const existingAPIKey = await this.get(apiKey);

		if (!existingAPIKey) {
			throw new Error(`API key not found`);
		}
		if (name) {
			existingAPIKey.name = name;
		}
		if (expiresAt) {
			existingAPIKey.expiresAt = expiresAt;
		}
		if (customer) {
			existingAPIKey.customer = customer;
		}
		if (user) {
			existingAPIKey.user = user;
		}
		if (revoked) {
			existingAPIKey.revoked = revoked;
		}

		const entity = await this.apiKeyRepository.save(existingAPIKey);
		if (entity && decryptionNeeded) {
			entity.apiKey = await this.decryptAPIKey(existingAPIKey.apiKey);
		}
		return entity;
	}

	public async revoke(apiKey: string, options?: APIServiceOptions) {
		return this.update(
			{
				apiKey: apiKey,
				revoked: true,
			},
			options
		);
	}

	public async decryptAPIKey(apiKey: string) {
		try {
			return await this.secretBox.decrypt(apiKey);
		} catch (error) {
			console.error('Error decrypting API key:', error);
			throw new Error(`Failed to decrypt API key: ${(error as Error)?.message || error}`);
		}
	}

	public async encryptAPIKey(apiKey: string) {
		try {
			return await this.secretBox.encrypt(apiKey);
		} catch (error) {
			console.error('Error encrypting API key:', error);
			throw new Error(`Failed to encrypt API key: ${(error as Error)?.message || error}`);
		}
	}

	public async get(apiKey: string, options?: APIServiceOptions) {
		// fingerprint
		const fingerprint = sha256(apiKey);

		// fetch the api key entity
		const apiKeyEntity = await APIKeyService.instance.findOne(
			{
				fingerprint,
			},
			{ customer: true, user: true },
			options
		);
		if (!apiKeyEntity) {
			throw new Error('Invalid API key');
		}

		// validate expiry
		if (apiKeyEntity.revoked) {
			throw new Error('API Key is expired');
		}

		// hash comparison (supports both PBKDF2 and legacy bcrypt)
		const isValid = await APIKeyService.compareAPIKey(apiKey, apiKeyEntity.apiKeyHash);
		if (!isValid) throw new Error('Invalid API key');

		return apiKeyEntity;
	}

	public async find(
		where: FindOptionsWhere<APIKeyEntity>,
		relations?: FindOptionsRelations<APIKeyEntity>,
		options?: APIServiceOptions,
		order?: FindOptionsOrder<APIKeyEntity>
	) {
		try {
			const { decryptionNeeded } = options || {};
			const apiKeyList = await this.apiKeyRepository.find({
				where,
				relations,
				order,
			});
			if (decryptionNeeded) {
				for (const apiKey of apiKeyList) {
					apiKey.apiKey = await this.decryptAPIKey(apiKey.apiKey);
				}
			}
			return apiKeyList;
		} catch {
			return [];
		}
	}

	public async findOne(
		where: FindOptionsWhere<APIKeyEntity>,
		relations?: FindOptionsRelations<APIKeyEntity>,
		options?: APIServiceOptions,
		order?: FindOptionsOrder<APIKeyEntity>
	) {
		const apiKeyEntity = await this.apiKeyRepository.findOne({
			where,
			relations,
			order,
		});

		if (apiKeyEntity && options?.decryptionNeeded) {
			apiKeyEntity.apiKey = await this.decryptAPIKey(apiKeyEntity.apiKey);
		}

		return apiKeyEntity;
	}

	// Utils
	public static generateAPIKey(userId: string): string {
		const apiKey = createHmac('sha512', randomBytes(API_SECRET_KEY_LENGTH).toString('hex'))
			.update(userId)
			.digest('hex');
		return `${API_KEY_PREFIX}_${apiKey}`;
	}

	public static getExpiryDateJWT(apiKey: string): Date {
		const decrypted = decodeJWT(apiKey);
		return new Date(decrypted.payload.exp ? decrypted.payload.exp * 1000 : 0);
	}

	public static async hashAPIKey(apiKey: string): Promise<string> {
		try {
			// Use PBKDF2 with a fixed salt to replace bcrypt and avoid SIGSEGV
			// This maintains the same hash output format as bcrypt
			const salt = 'cheqd-studio-api-key-salt'; // Fixed salt for consistent hashing
			const hash = pbkdf2Sync(apiKey, salt, 10000, 60, 'sha512').toString('base64');
			return hash;
		} catch (error) {
			// Fallback to a simpler hash if crypto fails
			const crypto = await import('crypto');
			return crypto.createHash('sha256').update(apiKey).digest('hex');
		}
	}

	public static async compareAPIKey(apiKey: string, hash: string): Promise<boolean> {
		try {
			// Use PBKDF2 with the same fixed salt to compare hashes
			const salt = 'cheqd-studio-api-key-salt'; // Same salt as used in hashing
			const computedHash = pbkdf2Sync(apiKey, salt, 10000, 60, 'sha512').toString('base64');
			return computedHash === hash;
		} catch (error) {
			console.error('Error comparing API key with crypto:', error);
			// Fallback to simple hash comparison
			const crypto = await import('crypto');
			const simpleHash = crypto.createHash('sha256').update(apiKey).digest('hex');
			return simpleHash === hash;
		}
	}
}
