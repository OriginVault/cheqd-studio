import { AuthRuleProvider } from '../auth-rule-provider.js';
import { eventTracker } from '../../../../services/track/tracker.js';
import type { Request } from 'express';
import { AuthRule } from '../../../../types/authentication.js';

export class AdminAuthRuleProvider extends AuthRuleProvider {
	/**
	 * Constructor for the AdminHandler class. Registers various routes related to admin functionalities like swagger, subscriptions, prices, products, and API keys for different environments.
	 */
	constructor() {
		super();
		// Main swagger route
		this.registerRule('/admin/swagger', 'GET', 'admin:swagger', { skipNamespace: true });
		// Subscriptions
		// skipNamespace is set to true cause we don't have the information about the namespace in the request
		this.registerRule('/admin/subscription/create', 'POST', 'admin:subscription:create', {
			skipNamespace: true,
		});
		this.registerRule('/admin/subscription/list', 'GET', 'admin:subscription:list', {
			skipNamespace: true,
		});
		this.registerRule('/admin/subscription/update', 'POST', 'admin:subscription:update', {
			skipNamespace: true,
		});
		this.registerRule('/admin/subscription/cancel', 'POST', 'admin:subscription:cancel', {
			skipNamespace: true,
		});
		this.registerRule('/admin/subscription/resume', 'POST', 'admin:subscription:resume', {
			skipNamespace: true,
		});
		this.registerRule('/admin/subscription/get', 'GET', 'admin:subscription:get', { skipNamespace: true });
		this.registerRule('/admin/checkout/session/(.*)', 'GET', 'admin:subscription:get', { skipNamespace: true });
		// Prices
		this.registerRule('/admin/price/list', 'GET', 'admin:price:list', { skipNamespace: true });

		// Products
		this.registerRule('/admin/product/list', 'GET', 'admin:product:list', { skipNamespace: true });
		this.registerRule('/admin/product/get', 'GET', 'admin:product:get', { skipNamespace: true });
		// API Key
		this.registerRule('/admin/api-key/create', 'POST', 'admin:api-key:create', { skipNamespace: true });
		this.registerRule('/admin/api-key/update', 'POST', 'admin:api-key:update', { skipNamespace: true });
		this.registerRule('/admin/api-key/revoke', 'DELETE', 'admin:api-key:revoke', { skipNamespace: true });
		this.registerRule('/admin/api-key/get', 'GET', 'admin:api-key:get', { skipNamespace: true });
		this.registerRule('/admin/api-key/list', 'GET', 'admin:api-key:list', { skipNamespace: true });
		// Customer
		this.registerRule('/admin/organisation/update', 'POST', 'admin:organisation:update', { skipNamespace: true });
		this.registerRule('/admin/organisation/get', 'GET', 'admin:organisation:get', { skipNamespace: true });
	}

	/**
	 * Extracts and anonymizes the IP address from the request, handling various proxy scenarios
	 * @param request - The Express request object
	 * @returns The anonymized IP address as a string
	 */
	private getAnonymizedIP(request: Request): string {
		// Get the real IP address
		let realIP = '';
		
		// Check for forwarded headers first (when behind a proxy)
		const forwardedFor = request.headers['x-forwarded-for'] as string;
		if (forwardedFor) {
			// x-forwarded-for can contain multiple IPs, take the first one
			realIP = forwardedFor.split(',')[0].trim();
		} else {
			// Check for real IP header
			const realIPHeader = request.headers['x-real-ip'] as string;
			if (realIPHeader) {
				realIP = realIPHeader;
			} else {
				// Fall back to the connection remote address
				realIP = request.connection?.remoteAddress || 
						request.socket?.remoteAddress || 
						(request as any).ip || 
						'unknown';
			}
		}

		// Anonymize the IP address
		return this.anonymizeIP(realIP);
	}

	/**
	 * Anonymizes an IP address by masking the last octet (IPv4) or last 80 bits (IPv6)
	 * @param ip - The IP address to anonymize
	 * @returns The anonymized IP address
	 */
	private anonymizeIP(ip: string): string {
		if (!ip || ip === 'unknown') {
			return 'unknown';
		}

		// Handle IPv4 addresses
		if (ip.includes('.')) {
			const parts = ip.split('.');
			if (parts.length === 4) {
				// Mask the last octet
				return `${parts[0]}.${parts[1]}.${parts[2]}.0`;
			}
		}

		// Handle IPv6 addresses
		if (ip.includes(':')) {
			// For IPv6, mask the last 80 bits (last 5 groups)
			const parts = ip.split(':');
			if (parts.length >= 6) {
				// Keep the first 3 groups, mask the rest
				const maskedParts = parts.slice(0, 3).map(part => part.padStart(4, '0'));
				return `${maskedParts.join(':')}::`;
			}
		}

		// If we can't parse it, return a generic masked version
		return 'masked';
	}

	/**
	 * Override the match method to include IP address logging
	 * @param request - The Express request object
	 * @returns The matching AuthRule or null
	 */
	public match(request: Request): AuthRule | null {
		const matchingRule = super.match(request);
		
		if (matchingRule) {
			const clientIP = this.getAnonymizedIP(request);
			eventTracker.emit('notify', {
				message: `Admin route accessed: ${request.method} ${request.path} from IP: ${clientIP}`,
				severity: 'info'
			});
		}
		
		return matchingRule;
	}
}
