import { SHA256Double as hashTwiceSha256 } from '../utils/crypto.js';
import { getTransportConfig, getTransportPathParam } from '../subscriptions/transformers.js';
import { normalizeToArray } from '../utils/normalization.js';

const PROXYIP_KEY = "PROXYIP";
const PATH_PLACEHOLDER = '{{IP:PORT}}';
const DEFAULT_AUTO_PROXYIP = 'pyip.ygkkk.dpdns.org';

export async function readConfigJSON(env, hostname, userID, {
	userAgent = "Mozilla/5.0",
	resetConfig = false,
	reverseProxyState = {},
} = {}) {
	const host = hostname;
	const initStartTime = performance.now();
	const defaultConfigJSON = await createDefaultConfig(hostname, userID, userAgent, reverseProxyState);
	let configJSON;

	try {
		const configText = await env.KV.get('config.json');
		if (!configText || resetConfig === true) {
			await env.KV.put('config.json', JSON.stringify(cleanConfigForStorage(defaultConfigJSON), null, 2));
			configJSON = defaultConfigJSON;
		} else {
			configJSON = mergeConfigDefaults(defaultConfigJSON, JSON.parse(configText));
		}
	} catch (error) {
		console.error(`readConfigJSONError: ${error.message}`);
		configJSON = defaultConfigJSON;
	}
	configJSON = await normalizeRuntimeConfig(configJSON, env, host, hostname, userID, userAgent, reverseProxyState);

	configJSON.loadTime = (performance.now() - initStartTime).toFixed(2) + 'ms';
	return configJSON;
}

export function cleanConfigForStorage(config) {
	const preferredSubGen = config.preferredSubGen || {};
	const localIPDB = preferredSubGen.localIPDB || {};
	const reverseProxy = config.reverseProxy || {};
	const reverseProxySOCKS5 = reverseProxy.SOCKS5 || {};
	const pathTemplate = reverseProxy.pathTemplate || {};
	return {
		HOSTS: Array.isArray(config.HOSTS) ? config.HOSTS : [],
		PATH: config.PATH,
		protocolType: config.protocolType,
		transportProtocol: config.transportProtocol,
		gRPCmode: config.gRPCmode,
		skipCertVerify: config.skipCertVerify,
		enable0RTT: config.enable0RTT,
		tlsFragment: config.tlsFragment,
		randomPath: config.randomPath,
		SS: {
			encryptMethod: config.SS?.encryptMethod,
			TLS: config.SS?.TLS,
		},
		Fingerprint: config.Fingerprint,
		preferredSubGen: {
			local: preferredSubGen.local,
			localIPDB: {
				randomIP: localIPDB.randomIP,
				randomCount: localIPDB.randomCount,
				specifiedPort: localIPDB.specifiedPort,
			},
			SUB: preferredSubGen.SUB,
			SUBNAME: preferredSubGen.SUBNAME,
			SUBUpdateTime: preferredSubGen.SUBUpdateTime,
		},
		reverseProxy: {
			PROXYIP: reverseProxy.PROXYIP,
			SOCKS5: {
				enabled: reverseProxySOCKS5.enabled,
				global: reverseProxySOCKS5.global,
				account: reverseProxySOCKS5.account,
				whitelist: Array.isArray(reverseProxySOCKS5.whitelist) ? reverseProxySOCKS5.whitelist : [],
			},
			pathTemplate: {
				PROXYIP: pathTemplate.PROXYIP,
				SOCKS5: cleanPathTemplateProtocol(pathTemplate.SOCKS5),
				HTTP: cleanPathTemplateProtocol(pathTemplate.HTTP),
				HTTPS: cleanPathTemplateProtocol(pathTemplate.HTTPS),
				TURN: cleanPathTemplateProtocol(pathTemplate.TURN),
				SSTP: cleanPathTemplateProtocol(pathTemplate.SSTP),
			},
		},
	};
}

function cleanPathTemplateProtocol(config: { global?: string; standard?: string } = {}) {
	return {
		global: config.global,
		standard: config.standard,
	};
}

function mergeConfigDefaults(defaultConfig, storedConfig) {
	if (Array.isArray(defaultConfig)) return Array.isArray(storedConfig) ? storedConfig : [...defaultConfig];
	if (defaultConfig && typeof defaultConfig === 'object') {
		const merged = {};
		for (const [key, defaultValue] of Object.entries(defaultConfig)) {
			merged[key] = mergeConfigDefaults(defaultValue, storedConfig?.[key]);
		}
		return merged;
	}
	return storedConfig === undefined ? defaultConfig : storedConfig;
}

async function createDefaultConfig(hostname, userID, userAgent, reverseProxyState) {
	const {
		enableSOCKS5Proxy: proxyProtocol = null,
		enableSOCKS5GlobalProxy: globalProxyEnabled = false,
		mySOCKS5Account: proxyAccount = '',
		SOCKS5whitelist: proxyWhitelist = [],
	} = reverseProxyState;
	return {
		TIME: new Date().toISOString(),
		HOST: hostname,
		HOSTS: [hostname],
		UUID: userID,
		PATH: "/",
		protocolType: "vless",
		transportProtocol: "ws",
		gRPCmode: "gun",
		gRPCUserAgent: userAgent,
		skipCertVerify: false,
		enable0RTT: false,
		tlsFragment: null,
		randomPath: false,
		SS: {
			encryptMethod: "aes-128-gcm",
			TLS: true,
		},
		Fingerprint: "chrome",
		preferredSubGen: {
			local: true,
			localIPDB: {
				randomIP: true,
				randomCount: 16,
				specifiedPort: -1,
			},
			SUB: null,
			SUBNAME: "edgetunnel",
			SUBUpdateTime: 3,
			TOKEN: await hashTwiceSha256(hostname + userID),
		},
		reverseProxy: {
			[PROXYIP_KEY]: "auto",
			SOCKS5: {
				enabled: proxyProtocol,
				global: globalProxyEnabled,
				account: proxyAccount,
				whitelist: proxyWhitelist,
			},
			pathTemplate: defaultProxyPathTemplate(),
		}
	};
}

async function normalizeRuntimeConfig(configJSON, env, host, hostname, userID, userAgent, reverseProxyState) {
	if (!configJSON.gRPCUserAgent) configJSON.gRPCUserAgent = userAgent;
	configJSON.HOST = host;
	if (!configJSON.HOSTS) configJSON.HOSTS = [hostname];
	if (env.HOST) configJSON.HOSTS = (await normalizeToArray(env.HOST)).map(h => h.toLowerCase().replace(/^https?:\/\//, '').split('/')[0].split(':')[0]);
	configJSON.UUID = userID;
	if (!configJSON.randomPath) configJSON.randomPath = false;
	if (!configJSON.enable0RTT) configJSON.enable0RTT = false;

	if (env.PATH) configJSON.PATH = env.PATH.startsWith('/') ? env.PATH : '/' + env.PATH;
	else if (!configJSON.PATH) configJSON.PATH = '/';

	if (!configJSON.gRPCmode) configJSON.gRPCmode = 'gun';
	if (!configJSON.SS) configJSON.SS = { encryptMethod: "aes-128-gcm", TLS: false };
	if (!configJSON.reverseProxy) configJSON.reverseProxy = { [PROXYIP_KEY]: 'auto', SOCKS5: {}, pathTemplate: defaultProxyPathTemplate() };
	if (!configJSON.reverseProxy.SOCKS5) configJSON.reverseProxy.SOCKS5 = {};
	applyReverseProxyState(configJSON, reverseProxyState);

	if (!configJSON.reverseProxy.pathTemplate?.[PROXYIP_KEY]) configJSON.reverseProxy.pathTemplate = defaultProxyPathTemplate();
	if (!configJSON.reverseProxy.pathTemplate.HTTPS) configJSON.reverseProxy.pathTemplate.HTTPS = { global: "https://" + PATH_PLACEHOLDER, standard: "https=" + PATH_PLACEHOLDER };
	if (!configJSON.reverseProxy.pathTemplate.TURN) configJSON.reverseProxy.pathTemplate.TURN = { global: "turn://" + PATH_PLACEHOLDER, standard: "turn=" + PATH_PLACEHOLDER };
	if (!configJSON.reverseProxy.pathTemplate.SSTP) configJSON.reverseProxy.pathTemplate.SSTP = { global: "sstp://" + PATH_PLACEHOLDER, standard: "sstp=" + PATH_PLACEHOLDER };

	const proxyConfig = configJSON.reverseProxy.pathTemplate[configJSON.reverseProxy.SOCKS5.enabled?.toUpperCase()];
	const configuredProxyIP = configJSON.reverseProxy[PROXYIP_KEY];
	const effectiveProxyIP = configuredProxyIP === 'auto' ? DEFAULT_AUTO_PROXYIP : configuredProxyIP;
	let pathProxyParam = '';
	if (proxyConfig && configJSON.reverseProxy.SOCKS5.account) pathProxyParam = (configJSON.reverseProxy.SOCKS5.global ? proxyConfig.global : proxyConfig.standard).replace(PATH_PLACEHOLDER, configJSON.reverseProxy.SOCKS5.account);
	else if (effectiveProxyIP) pathProxyParam = configJSON.reverseProxy.pathTemplate[PROXYIP_KEY].replace(PATH_PLACEHOLDER, effectiveProxyIP);

	let proxyQueryParam = '';
	if (pathProxyParam.includes('?')) {
		const [proxyPathPart, proxyQueryPart] = pathProxyParam.split('?');
		pathProxyParam = proxyPathPart;
		proxyQueryParam = proxyQueryPart;
	}

	configJSON.PATH = configJSON.PATH.replace(pathProxyParam, '').replace('//', '/');
	const normalizedPath = configJSON.PATH === '/' ? '' : configJSON.PATH.replace(/\/+(?=\?|$)/, '').replace(/\/+$/, '');
	const [pathPart, ...queryArray] = normalizedPath.split('?');
	const queryPart = queryArray.length ? '?' + queryArray.join('?') : '';
	const finalQueryPart = proxyQueryParam ? (queryPart ? queryPart + '&' + proxyQueryParam : '?' + proxyQueryParam) : queryPart;
	configJSON.fullNodePath = (pathPart || '/') + (pathPart && pathProxyParam ? '/' : '') + pathProxyParam + finalQueryPart + (configJSON.enable0RTT ? (finalQueryPart ? '&' : '?') + 'ed=2560' : '');

	if (!configJSON.tlsFragment && configJSON.tlsFragment !== null) configJSON.tlsFragment = null;
	const tlsFragmentparams = configJSON.tlsFragment == 'Shadowrocket' ? `&fragment=${encodeURIComponent('1,40-60,30-50,tlshello')}` : configJSON.tlsFragment == 'Happ' ? `&fragment=${encodeURIComponent('3,1,tlshello')}` : '';
	if (!configJSON.Fingerprint) configJSON.Fingerprint = "chrome";
	const { type: transportProtocol, pathFieldName, domainFieldName } = getTransportConfig(configJSON);
	const transportPathParamValue = getTransportPathParam(configJSON, configJSON.fullNodePath);
	configJSON.LINK = configJSON.protocolType === 'ss'
		? `${configJSON.protocolType}://${btoa(configJSON.SS.encryptMethod + ':' + userID)}@${host}:${configJSON.SS.TLS ? '443' : '80'}?plugin=v2${encodeURIComponent(`ray-plugin;mode=websocket;host=${host};path=${((configJSON.fullNodePath.includes('?') ? configJSON.fullNodePath.replace('?', '?enc=' + configJSON.SS.encryptMethod + '&') : (configJSON.fullNodePath + '?enc=' + configJSON.SS.encryptMethod)) + (configJSON.SS.TLS ? ';tls' : ''))};mux=0`)}#${encodeURIComponent(configJSON.preferredSubGen.SUBNAME)}`
		: `${configJSON.protocolType}://${userID}@${host}:443?security=tls&type=${transportProtocol}&${domainFieldName}=${host}&fp=${configJSON.Fingerprint}&sni=${host}&${pathFieldName}=${encodeURIComponent(transportPathParamValue) + tlsFragmentparams}&encryption=none${configJSON.skipCertVerify ? '&insecure=1&allowInsecure=1' : ''}#${encodeURIComponent(configJSON.preferredSubGen.SUBNAME)}`;
	configJSON.preferredSubGen.TOKEN = await hashTwiceSha256(hostname + userID);
	return configJSON;
}

function applyReverseProxyState(configJSON, reverseProxyState) {
	const {
		enableSOCKS5Proxy: proxyProtocol,
		enableSOCKS5GlobalProxy: globalProxyEnabled,
		mySOCKS5Account: proxyAccount,
		SOCKS5whitelist: proxyWhitelist,
		proxyIP,
	} = reverseProxyState;
	if (proxyProtocol !== undefined) configJSON.reverseProxy.SOCKS5.enabled = proxyProtocol;
	if (globalProxyEnabled !== undefined) configJSON.reverseProxy.SOCKS5.global = globalProxyEnabled;
	if (proxyAccount !== undefined) configJSON.reverseProxy.SOCKS5.account = proxyAccount;
	if (proxyWhitelist !== undefined) configJSON.reverseProxy.SOCKS5.whitelist = proxyWhitelist;
	if (proxyIP !== undefined && proxyIP !== 'chainProxy') configJSON.reverseProxy[PROXYIP_KEY] = proxyIP || configJSON.reverseProxy[PROXYIP_KEY] || 'auto';
}

function defaultProxyPathTemplate() {
	return {
		[PROXYIP_KEY]: "proxyip=" + PATH_PLACEHOLDER,
		SOCKS5: {
			global: "socks5://" + PATH_PLACEHOLDER,
			standard: "socks5=" + PATH_PLACEHOLDER
		},
		HTTP: {
			global: "http://" + PATH_PLACEHOLDER,
			standard: "http=" + PATH_PLACEHOLDER
		},
		HTTPS: {
			global: "https://" + PATH_PLACEHOLDER,
			standard: "https=" + PATH_PLACEHOLDER
		},
		TURN: {
			global: "turn://" + PATH_PLACEHOLDER,
			standard: "turn=" + PATH_PLACEHOLDER
		},
		SSTP: {
			global: "sstp://" + PATH_PLACEHOLDER,
			standard: "sstp=" + PATH_PLACEHOLDER
		},
	};
}
