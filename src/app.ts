import express from 'express';
import Helmet from 'helmet';
import cors from 'cors';
import session from 'express-session';
import cookieParser from 'cookie-parser';
import path from 'path';
import swaggerUi from 'swagger-ui-express';
import { StatusCodes } from 'http-status-codes';
import { CredentialController } from './controllers/api/credential.js';
import { AccountController } from './controllers/api/account.js';
import { Authentication } from './middleware/authentication.js';
import { Connection } from './database/connection/connection.js';
import { CredentialStatusController } from './controllers/api/credential-status.js';
import { CORS_ALLOWED_ORIGINS, CORS_ERROR_MSG } from './types/constants.js';
import { LogToWebHook } from './middleware/hook.js';
import { Middleware } from './middleware/middleware.js';
import * as dotenv from 'dotenv';
import fs from 'fs';
// Define Swagger file
import swaggerAPIDocument from './static/swagger-api.json' with { type: 'json' };
import swaggerAdminDocument from './static/swagger-admin.json' with { type: 'json' };
import { PresentationController } from './controllers/api/presentation.js';
import { KeyController } from './controllers/api/key.js';
import { DIDController } from './controllers/api/did.js';
import { ResourceController } from './controllers/api/resource.js';
import { ResponseTracker } from './middleware/event-tracker.js';
import { ProductController } from './controllers/admin/product.js';
import { SubscriptionController } from './controllers/admin/subscriptions.js';
import { PriceController } from './controllers/admin/prices.js';
import { WebhookController } from './controllers/admin/webhook.js';
import { APIKeyController } from './controllers/admin/api-key.js';
import { OrganisationController } from './controllers/admin/organisation.js';
import { AccreditationController } from './controllers/api/accreditation.js';
import { DIDDocument } from 'did-resolver';
import { eventTracker } from './services/track/tracker.js';

dotenv.config();

class App {
	public express: express.Application;

	constructor() {
		this.express = express();
		this.middleware();
		this.routes();
		Connection.instance
			.connect()
			.then(() => {
				console.log('Database connection: successful');
			})
			.catch((err) => {
				console.log('DBConnectorError: ', err);
			});
	}

	private middleware() {
		this.express.use(
			express.json({
				limit: '50mb',
				verify: (req: express.Request & { rawBody: Buffer }, _res, buf) => {
					req.rawBody = buf;
				},
			})
		);
		this.express.use(express.raw({ type: 'application/octet-stream' }));
		this.express.use(express.urlencoded({ extended: true }));
		this.express.use(Middleware.parseUrlEncodedJson);
		this.express.use(Helmet());
		this.express.use(
			cors({
				origin: function (origin, callback) {
					if (!origin) return callback(null, true);
					const allowedList = CORS_ALLOWED_ORIGINS.split(',');

					for (const allowed of allowedList) {
						if (allowed.indexOf(origin) !== -1) {
							return callback(null, true);
						}
					}
					return callback(new Error(CORS_ERROR_MSG), false);
				},
			})
		);
		this.express.use(cookieParser());
		const auth = new Authentication();
		// EventTracking
		this.express.use(new ResponseTracker().trackJson);
		// Authentication
		if (process.env.ENABLE_AUTHENTICATION === 'true') {
			this.express.use(
				session({
					secret:
						process.env.COOKIE_SECRET ||
						(function () {
							throw new Error('COOKIE_SECRET is not defined');
						})(),
					cookie: { maxAge: 24 * 60 * 60 * 1000 }, // 24 hours
					resave: false,
					saveUninitialized: false,
				})
			);
			// Authentication functions/methods
			this.express.use(async (_req, _res, next) => await auth.setup(_res, next));
			this.express.use(async (_req, _res, next) => await auth.wrapperHandleAuthRoutes(_req, _res, next));
			this.express.use(async (_req, _res, next) => await auth.withLogtoWrapper(_req, _res, next));
			if (process.env.ENABLE_EXTERNAL_DB === 'true') {
				this.express.use(async (req, res, next) => await auth.guard(req, res, next));
			}
		}
		this.express.use(express.text());
		this.express.use(auth.handleError);
		this.express.use(async (req, res, next) => await auth.accessControl(req, res, next));
		this.express.use('/swagger', swaggerUi.serveFiles(swaggerAPIDocument), swaggerUi.setup(swaggerAPIDocument));
		if (process.env.STRIPE_ENABLED === 'true') {
			this.express.use(
				'/admin/swagger',
				swaggerUi.serveFiles(swaggerAdminDocument),
				swaggerUi.setup(swaggerAdminDocument)
			);
			this.express.use(Middleware.setStripeClient);
		}
	}

	private routes() {
		const app = this.express;

		// Top-level routes
		app.get('/', (_req, res) => res.redirect('swagger'));

		// Credential API
		app.post(`/credential/issue`, CredentialController.issueValidator, new CredentialController().issue);
		app.post(`/credential/verify`, CredentialController.verifyValidator, new CredentialController().verify);
		app.post(`/credential/revoke`, CredentialController.revokeValidator, new CredentialController().revoke);
		app.post('/credential/suspend', CredentialController.suspendValidator, new CredentialController().suspend);
		app.post(
			'/credential/reinstate',
			CredentialController.reinstateValidator,
			new CredentialController().reinstate
		);

		// Presentation API
		app.post(
			`/presentation/verify`,
			PresentationController.presentationVerifyValidator,
			new PresentationController().verifyPresentation
		);
		app.post(
			`/presentation/create`,
			PresentationController.presentationCreateValidator,
			new PresentationController().createPresentation
		);

		// Credential status API
		app.post(
			'/credential-status/create/unencrypted',
			CredentialStatusController.createUnencryptedValidator,
			new CredentialStatusController().createUnencryptedStatusList
		);
		app.post(
			'/credential-status/create/encrypted',
			CredentialStatusController.createEncryptedValidator,
			new CredentialStatusController().createEncryptedStatusList
		);
		app.post(
			'/credential-status/update/unencrypted',
			CredentialStatusController.updateUnencryptedValidator,
			new CredentialStatusController().updateUnencryptedStatusList
		);
		app.post(
			'/credential-status/update/encrypted',
			CredentialStatusController.updateEncryptedValidator,
			new CredentialStatusController().updateEncryptedStatusList
		);
		app.post(
			'/credential-status/check',
			CredentialStatusController.checkValidator,
			new CredentialStatusController().checkStatusList
		);
		app.get(
			'/credential-status/search',
			CredentialStatusController.searchValidator,
			new CredentialStatusController().searchStatusList
		);

		// Keys API
		app.post('/key/create', new KeyController().createKey);
		app.post('/key/import', KeyController.keyImportValidator, new KeyController().importKey);
		app.get('/key/read/:kid', KeyController.keyGetValidator, new KeyController().getKey);
		app.post('/key/export', KeyController.keyExportValidator, new KeyController().exportKey);

		// DIDs API
		app.post('/did/create', DIDController.createDIDValidator, new DIDController().createDid);
		app.post('/did/update', DIDController.updateDIDValidator, new DIDController().updateDid);
		app.post('/did/import', DIDController.importDIDValidator, new DIDController().importDid);
		app.post('/did/deactivate/:did', DIDController.deactivateDIDValidator, new DIDController().deactivateDid);
		app.get('/did/list', new DIDController().getDids);
		app.get('/did/search/:did', new DIDController().resolveDidUrl);
		app.post('/did/add-key', DIDController.addKeyToDIDValidator, new DIDController().addKeyToDid);

		// Trust Registry API
		app.post(
			'/trust-registry/accreditation/issue',
			AccreditationController.issueValidator,
			new AccreditationController().issue
		);
		app.post(
			'/trust-registry/accreditation/verify',
			AccreditationController.verifyValidator,
			new AccreditationController().verify
		);
		app.post(
			'/trust-registry/accreditation/revoke',
			AccreditationController.publishValidator,
			new AccreditationController().revoke
		);
		app.post(
			'/trust-registry/accreditation/suspend',
			AccreditationController.publishValidator,
			new AccreditationController().suspend
		);
		app.post(
			'/trust-registry/accreditation/reinstate',
			AccreditationController.publishValidator,
			new AccreditationController().reinstate
		);

		// Resource API
		app.post(
			'/resource/create/:did',
			ResourceController.createResourceValidator,
			new ResourceController().createResource
		);
		app.get(
			'/resource/search/:did',
			ResourceController.searchResourceValidator,
			new ResourceController().searchResource
		);

		// Account API
		app.post('/account/create', AccountController.createValidator, new AccountController().create);
		app.get('/account', new AccountController().get);
		app.get('/account/idtoken', new AccountController().getIdToken);

		// LogTo webhooks
		app.post('/account/bootstrap', LogToWebHook.verifyHookSignature, new AccountController().bootstrap);

		// LogTo user info
		app.get('/auth/user-info', async (req, res) => {
			return res.json(req.user);
		});

		// static files
		app.get(
			'/static/custom-button.js',
			express.static(path.join(process.cwd(), '/dist'), { extensions: ['js'], index: false })
		);

		// Portal
		// Product
		if (process.env.STRIPE_ENABLED === 'true') {
			app.get(
				'/admin/product/list',
				ProductController.productListValidator,
				new ProductController().listProducts
			);
			app.get(
				'/admin/product/get/:productId',
				ProductController.productGetValidator,
				new ProductController().getProduct
			);

			// Prices
			app.get('/admin/price/list', PriceController.priceListValidator, new PriceController().getListPrices);

			// Subscription
			app.post(
				'/admin/subscription/create',
				SubscriptionController.subscriptionCreateValidator,
				new SubscriptionController().create
			);
			app.post(
				'/admin/subscription/update',
				SubscriptionController.subscriptionUpdateValidator,
				new SubscriptionController().update
			);
			app.get('/admin/subscription/get', new SubscriptionController().get);
			app.get(
				'/admin/subscription/list',
				SubscriptionController.subscriptionListValidator,
				new SubscriptionController().list
			);
			app.delete(
				'/admin/subscription/cancel',
				SubscriptionController.subscriptionCancelValidator,
				new SubscriptionController().cancel
			);
			app.post(
				'/admin/subscription/resume',
				SubscriptionController.subscriptionResumeValidator,
				new SubscriptionController().resume
			);

			app.get('/admin/checkout/session/:id', new SubscriptionController().getCheckoutSession);

			// API key
			app.post('/admin/api-key/create', APIKeyController.apiKeyCreateValidator, new APIKeyController().create);
			app.post('/admin/api-key/update', APIKeyController.apiKeyUpdateValidator, new APIKeyController().update);
			app.get('/admin/api-key/get', APIKeyController.apiKeyGetValidator, new APIKeyController().get);
			app.get('/admin/api-key/list', APIKeyController.apiKeyListValidator, new APIKeyController().list);
			app.delete('/admin/api-key/revoke', APIKeyController.apiKeyRevokeValidator, new APIKeyController().revoke);

			// Webhook
			app.post('/admin/webhook', new WebhookController().handleWebhook);

			// Customer
			app.post(
				'/admin/organisation/update',
				OrganisationController.organisationUpdatevalidator,
				new OrganisationController().update
			);
			app.get('/admin/organisation/get', new OrganisationController().get);
		}

		// Health check
		app.get('/health', (req, res) => {
			res.status(StatusCodes.OK).send('OK');
		});

		// Whoami
		app.get('/whoami', (req, res) => {
			const didDocPath = path.join(process.cwd(), '/public/.well-known/did-configuration.json');
			if (!fs.existsSync(didDocPath)) {
				res.status(StatusCodes.INTERNAL_SERVER_ERROR).send('Did doc not found');
			}
			const didDoc: { didDocument: DIDDocument } = JSON.parse(fs.readFileSync(didDocPath, 'utf8'));
			res.json(didDoc);
		});

		app.get('/robots.txt', (req, res) => {
			const robotsPath = path.join(process.cwd(), 'public', 'robots.txt');
			if (!fs.existsSync(robotsPath)) {
				res.status(StatusCodes.NOT_FOUND).send('robots.txt not found');
			}
			
			eventTracker.emit('notify', {
				message: 'robots.txt requested at ' + new Date().toISOString(),
				severity: 'info',
			});
			res.type('text/plain').send(fs.readFileSync(robotsPath, 'utf8'));
		});

		app.get('/./favicon-32x32.png', (req, res) => {
			const faviconPath = path.join(process.cwd(), 'public', 'favicon-32x32.png');
			if (!fs.existsSync(faviconPath)) {
				res.status(StatusCodes.NOT_FOUND).send('favicon-32x32.png not found');
			}

			eventTracker.emit('notify', {
				message: 'favicon-32x32.png requested at ' + new Date().toISOString(),
				severity: 'info',
			});

			res.type('image/png').send(fs.readFileSync(faviconPath, 'utf8'));
		});

		app.get('/./favicon-16x16.png', (req, res) => {
			const faviconPath = path.join(process.cwd(), 'public', 'favicon-16x16.png');
			if (!fs.existsSync(faviconPath)) {
				res.status(StatusCodes.NOT_FOUND).send('favicon-16x16.png not found');
			}

			eventTracker.emit('notify', {
				message: 'favicon-16x16.png requested at ' + new Date().toISOString(),
				severity: 'info',
			});

			res.type('image/png').send(fs.readFileSync(faviconPath, 'utf8'));
		});

		app.get('/favicon.ico', (req, res) => {
			const faviconPath = path.join(process.cwd(), 'public', 'favicon.ico');
			if (!fs.existsSync(faviconPath)) {
				res.status(StatusCodes.NOT_FOUND).send('favicon.ico not found');
			}

			eventTracker.emit('notify', {
				message: 'favicon.ico requested at ' + new Date().toISOString(),
				severity: 'info',
			});

			res.type('image/x-icon').send(fs.readFileSync(faviconPath, 'utf8'));
		});

		// Wiki endpoint
		app.get('/wiki', (req, res) => {
			eventTracker.emit('notify', {
				message: 'wiki endpoint requested at ' + new Date().toISOString(),
				severity: 'info',
			});
			
			// Return list of available APIs
			res.status(StatusCodes.OK).json({
				message: 'Cheqd Studio API Documentation',
				description: 'Available API endpoints and their descriptions',
				swaggerEndpoints: {
					api: '/swagger',
					admin: '/admin/swagger'
				},
				apis: {
					credential: {
						description: 'Credential management operations',
						endpoints: [
							{ method: 'POST', path: '/credential/issue', description: 'Issue a new credential' },
							{ method: 'POST', path: '/credential/verify', description: 'Verify a credential' },
							{ method: 'POST', path: '/credential/revoke', description: 'Revoke a credential' },
							{ method: 'POST', path: '/credential/suspend', description: 'Suspend a credential' },
							{ method: 'POST', path: '/credential/reinstate', description: 'Reinstate a suspended credential' }
						]
					},
					presentation: {
						description: 'Presentation verification and creation',
						endpoints: [
							{ method: 'POST', path: '/presentation/verify', description: 'Verify a presentation' },
							{ method: 'POST', path: '/presentation/create', description: 'Create a new presentation' }
						]
					},
					credentialStatus: {
						description: 'Credential status list management',
						endpoints: [
							{ method: 'POST', path: '/credential-status/create/unencrypted', description: 'Create unencrypted status list' },
							{ method: 'POST', path: '/credential-status/create/encrypted', description: 'Create encrypted status list' },
							{ method: 'POST', path: '/credential-status/update/unencrypted', description: 'Update unencrypted status list' },
							{ method: 'POST', path: '/credential-status/update/encrypted', description: 'Update encrypted status list' },
							{ method: 'POST', path: '/credential-status/check', description: 'Check status list' },
							{ method: 'GET', path: '/credential-status/search', description: 'Search status lists' }
						]
					},
					key: {
						description: 'Key management operations',
						endpoints: [
							{ method: 'POST', path: '/key/create', description: 'Create a new key' },
							{ method: 'POST', path: '/key/import', description: 'Import an existing key' },
							{ method: 'GET', path: '/key/read/:kid', description: 'Read a key by ID' },
							{ method: 'POST', path: '/key/export', description: 'Export a key' }
						]
					},
					did: {
						description: 'DID (Decentralized Identifier) operations',
						endpoints: [
							{ method: 'POST', path: '/did/create', description: 'Create a new DID' },
							{ method: 'POST', path: '/did/update', description: 'Update an existing DID' },
							{ method: 'POST', path: '/did/import', description: 'Import an existing DID' },
							{ method: 'POST', path: '/did/deactivate/:did', description: 'Deactivate a DID' },
							{ method: 'GET', path: '/did/list', description: 'List all DIDs' },
							{ method: 'GET', path: '/did/search/:did', description: 'Resolve a DID URL' },
							{ method: 'POST', path: '/did/add-key', description: 'Add a key to a DID' }
						]
					},
					trustRegistry: {
						description: 'Trust registry and accreditation operations',
						endpoints: [
							{ method: 'POST', path: '/trust-registry/accreditation/issue', description: 'Issue an accreditation' },
							{ method: 'POST', path: '/trust-registry/accreditation/verify', description: 'Verify an accreditation' },
							{ method: 'POST', path: '/trust-registry/accreditation/revoke', description: 'Revoke an accreditation' },
							{ method: 'POST', path: '/trust-registry/accreditation/suspend', description: 'Suspend an accreditation' },
							{ method: 'POST', path: '/trust-registry/accreditation/reinstate', description: 'Reinstate an accreditation' }
						]
					},
					resource: {
						description: 'Resource management operations',
						endpoints: [
							{ method: 'POST', path: '/resource/create/:did', description: 'Create a resource for a DID' },
							{ method: 'GET', path: '/resource/search/:did', description: 'Search resources for a DID' }
						]
					},
					account: {
						description: 'Account management operations',
						endpoints: [
							{ method: 'POST', path: '/account/create', description: 'Create a new account' },
							{ method: 'GET', path: '/account', description: 'Get account information' },
							{ method: 'GET', path: '/account/idtoken', description: 'Get ID token' },
							{ method: 'POST', path: '/account/bootstrap', description: 'Bootstrap account (LogTo webhook)' }
						]
					},
					admin: {
						description: 'Administrative operations (Stripe enabled only)',
						endpoints: [
							{ method: 'GET', path: '/admin/product/list', description: 'List products' },
							{ method: 'GET', path: '/admin/product/get/:productId', description: 'Get product details' },
							{ method: 'GET', path: '/admin/price/list', description: 'List prices' },
							{ method: 'POST', path: '/admin/subscription/create', description: 'Create subscription' },
							{ method: 'POST', path: '/admin/subscription/update', description: 'Update subscription' },
							{ method: 'GET', path: '/admin/subscription/get', description: 'Get subscription' },
							{ method: 'GET', path: '/admin/subscription/list', description: 'List subscriptions' },
							{ method: 'DELETE', path: '/admin/subscription/cancel', description: 'Cancel subscription' },
							{ method: 'POST', path: '/admin/subscription/resume', description: 'Resume subscription' },
							{ method: 'GET', path: '/admin/checkout/session/:id', description: 'Get checkout session' },
							{ method: 'POST', path: '/admin/api-key/create', description: 'Create API key' },
							{ method: 'POST', path: '/admin/api-key/update', description: 'Update API key' },
							{ method: 'GET', path: '/admin/api-key/get', description: 'Get API key' },
							{ method: 'GET', path: '/admin/api-key/list', description: 'List API keys' },
							{ method: 'DELETE', path: '/admin/api-key/revoke', description: 'Revoke API key' },
							{ method: 'POST', path: '/admin/webhook', description: 'Handle webhook' },
							{ method: 'POST', path: '/admin/organisation/update', description: 'Update organisation' },
							{ method: 'GET', path: '/admin/organisation/get', description: 'Get organisation' }
						]
					},
					utility: {
						description: 'Utility and system endpoints',
						endpoints: [
							{ method: 'GET', path: '/health', description: 'Health check' },
							{ method: 'GET', path: '/whoami', description: 'Get DID configuration' },
							{ method: 'GET', path: '/auth/user-info', description: 'Get user information' },
							{ method: 'GET', path: '/static/custom-button.js', description: 'Get custom button script' }
						]
					}
				}
			});
		});

		// 404 for all other requests
		app.all('*', (_req, res) => res.status(StatusCodes.BAD_REQUEST).send('Bad request'));
	}
}

export default new App().express;
