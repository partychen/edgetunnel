import { connect } from 'cloudflare:sockets';
import { safeRelease, safeClose, uuidRegex } from './utils/helpers.js';
import { dataToUint8Array, joinBytes } from './utils/bytes.js';
import { normalizeToArray } from './utils/normalization.js';
import { createProxyConnectors } from './protocols/proxies.js';
import { getProxyDefaultPort, getSOCKS5Account } from './protocols/proxy-address.js';
import { parseProxyParams } from './protocols/proxy-params.js';
import { createProxyResolver } from './protocols/proxy-resolver.js';
import { isSpeedTestSite, parseTrojanRequest, parseVLESSRequest } from './protocols/request-parsers.js';
import { readXHTTPFirstPacket, validDataLength } from './protocols/xhttp.js';
import { decryptShadowsocksAead, deriveShadowsocksMasterKey, deriveShadowsocksSessionKey, encryptShadowsocksAead, SHADOWSOCKS_AEAD_TAG_LENGTH, SHADOWSOCKS_NONCE_LENGTH, shadowsocksTextDecoder, supportedShadowsocksCiphers } from './protocols/shadowsocks.js';
import { SHA256Double as hashTwiceSha256, generateAuthCookie, verifyAuthCookie } from './utils/crypto.js';
import { dohQuery } from './utils/dns.js';
import { requestLogger } from './utils/logger.js';
import { jsonResponse, redirectResponse } from './http/responses.js';
import { createWebSocketTransport } from './transport/websocket.js';
import { createTransportHandlers } from './transport/request-handlers.js';
import { getAuthCookie } from './admin/auth.js';
import { checkProxyConnectivity } from './admin/proxy-check.js';
import { base64SecretEncode, getTransportConfig, getTransportPathParam, randomPath, replaceStarsWithRandom } from './subscriptions/transformers.js';
import { generateRandomIP, getSubGenData, requestPreferredAPI } from './subscriptions/preferred-addresses.js';
import { cleanConfigForStorage, readConfigJSON } from './config/runtime.js';
import { renderAdminPage, renderLoginPage, renderMissingAdminPage, renderMissingKvPage } from './pages/admin.js';
import { html1101, nginx } from './pages/disguise.js';
import type { DoHAnswer, LogFn, ParsedProxyAddress, ProxyState } from './types.js';

const DEFAULT_SOCKS5_WHITELIST = [
	'*tapecontent.net',
	'*cloudatacdn.com',
	'*loadshare.org',
	'*cdn-centaurus.com',
	'scholar.google.com',
	'chatgpt.com',
	'*.chatgpt.com',
	'openai.com',
	'*.openai.com',
	'oaistatic.com',
	'*.oaistatic.com',
	'oaiusercontent.com',
	'*.oaiusercontent.com',
	'challenges.cloudflare.com',
	'x.com',
	'*.x.com',
	'twitter.com',
	'*.twitter.com',
	'twimg.com',
	'*.twimg.com',
	't.co',
	'*.t.co',
];
const BUILD_VERSION = '2026-05-10 03:38:38';
let cachedProxyArrayIndex = 0;

function createRequestLogger(env): LogFn {
	const debugEnabled = ['1', 'true'].includes(String(env.DEBUG || '').toLowerCase());
	return (...args) => {
		if (debugEnabled) console.log(...args);
	};
}

async function createBaseProxyState(env): Promise<ProxyState> {
	const proxyState: ProxyState = {
		proxyIP: '',
		enableProxyFallback: true,
		enableSOCKS5Proxy: null,
		enableSOCKS5GlobalProxy: false,
		mySOCKS5Account: '',
		parsedSocks5Address: {},
		SOCKS5whitelist: env.GO2SOCKS5 ? await normalizeToArray(env.GO2SOCKS5) : [...DEFAULT_SOCKS5_WHITELIST],
		cachedProxyArrayIndex,
	};

	if (env.PROXYIP) {
		const proxyIPs = await normalizeToArray(env.PROXYIP);
		proxyState.proxyIP = proxyIPs[Math.floor(Math.random() * proxyIPs.length)];
		proxyState.enableProxyFallback = false;
	}

	return freezeProxyState(proxyState);
}

function mergeProxyState(baseState: ProxyState, overrideState: ProxyState = {}): ProxyState {
	return freezeProxyState({
		...baseState,
		...overrideState,
		SOCKS5whitelist: overrideState.SOCKS5whitelist || baseState.SOCKS5whitelist || [],
		parsedSocks5Address: overrideState.parsedSocks5Address || baseState.parsedSocks5Address || {},
		cachedProxyArrayIndex,
	});
}

function freezeProxyState(proxyState: ProxyState): ProxyState {
	return Object.freeze({
		...proxyState,
		SOCKS5whitelist: Object.freeze([...(proxyState.SOCKS5whitelist || [])]),
		parsedSocks5Address: Object.freeze({ ...(proxyState.parsedSocks5Address || {}) }),
	});
}

function getReverseProxyState(proxyState: ProxyState) {
	return {
		enableSOCKS5Proxy: proxyState.enableSOCKS5Proxy,
		enableSOCKS5GlobalProxy: proxyState.enableSOCKS5GlobalProxy,
		mySOCKS5Account: proxyState.mySOCKS5Account,
		SOCKS5whitelist: proxyState.SOCKS5whitelist,
		proxyIP: proxyState.proxyIP,
	};
}

function createRequestProxyConnectors(parsedProxyAddress: ParsedProxyAddress, requestLog: LogFn) {
	const queryDnsOverHttps = (domain: string, recordType: string, server?: string): Promise<DoHAnswer[]> => dohQuery(domain, recordType, server, requestLog);
	return createProxyConnectors({
		getParsedProxy: () => parsedProxyAddress,
		validDataLength,
		log: requestLog,
		dohQuery: queryDnsOverHttps,
	});
}

function createRequestTransportHandlers(proxyState: ProxyState, requestLog: LogFn) {
	const queryDnsOverHttps = (domain: string, recordType: string, server?: string): Promise<DoHAnswer[]> => dohQuery(domain, recordType, server, requestLog);
	const resolveProxyAddresses = createProxyResolver({ dohQuery: queryDnsOverHttps });
	const proxyConnectors = createProxyConnectors({
		getParsedProxy: () => proxyState.parsedSocks5Address || {},
		validDataLength,
		log: requestLog,
		dohQuery: queryDnsOverHttps,
	});
	const webSocketTransport = createWebSocketTransport({ log: requestLog });
	return createTransportHandlers({
		connect,
		safeRelease,
		safeClose,
		dataToUint8Array,
		joinBytes,
		readXHTTPFirstPacket,
		validDataLength,
		isSpeedTestSite,
		parseTrojanRequest,
		parseVLESSRequest,
		decryptShadowsocksAead,
		encryptShadowsocksAead,
		shadowsocksAeadTagLength: SHADOWSOCKS_AEAD_TAG_LENGTH,
		deriveShadowsocksMasterKey,
		deriveShadowsocksSessionKey,
		shadowsocksNonceLength: SHADOWSOCKS_NONCE_LENGTH,
		supportedShadowsocksCiphers,
		shadowsocksTextDecoder,
		...proxyConnectors,
		resolveProxyAddresses,
		getProxyState: () => ({ ...proxyState, cachedProxyArrayIndex }),
		setCachedProxyArrayIndex: (index) => { cachedProxyArrayIndex = index },
		...webSocketTransport,
		log: requestLog,
	});
}

export default {
	async fetch(request, env, ctx) {
		let runtimeConfig;
		let requestURLText = request.url.replace(/%5[Cc]/g, '').replace(/\\/g, '').replace(/[\x00-\x1f]/g, '').replace(/\.\.\//g, '');
		const requestURLAnchorIndex = requestURLText.indexOf('#');
		const requestURLBodyPart = requestURLAnchorIndex === -1 ? requestURLText : requestURLText.slice(0, requestURLAnchorIndex);
		if (!requestURLBodyPart.includes('?') && /%3f/i.test(requestURLBodyPart)) {
			const requestURLAnchorPart = requestURLAnchorIndex === -1 ? '' : requestURLText.slice(requestURLAnchorIndex);
			requestURLText = requestURLBodyPart.replace(/%3f/i, '?') + requestURLAnchorPart;
		}
		const url = new URL(requestURLText);
		const userAgent = request.headers.get('User-Agent') || 'null';
		const upgradeHeader = (request.headers.get('Upgrade') || '').toLowerCase(), contentType = (request.headers.get('content-type') || '').toLowerCase();
		const adminPassword = env.ADMIN || env.admin || env.PASSWORD || env.password || env.pswd || env.TOKEN || env.KEY || env.UUID || env.uuid;
		const encryptKey = env.KEY || 'doNotModifyDefaultKey，modifyViaEnvVarIfNeeded';
		const userIDMD5 = await hashTwiceSha256(adminPassword + encryptKey);
		const envUUID = env.UUID || env.uuid;
		const userID = (envUUID && uuidRegex.test(envUUID)) ? envUUID.toLowerCase() : [userIDMD5.slice(0, 8), userIDMD5.slice(8, 12), '4' + userIDMD5.slice(13, 16), '8' + userIDMD5.slice(17, 20), userIDMD5.slice(20, 32)].join('-');
		const hosts = env.HOST ? (await normalizeToArray(env.HOST)).map(h => h.toLowerCase().replace(/^https?:\/\//, '').split('/')[0].split(':')[0]) : [url.hostname];
		const host = hosts[0];
		const accessPath = url.pathname.slice(1).toLowerCase();
		const requestLog = createRequestLogger(env);
		const baseProxyState = await createBaseProxyState(env);
		const requestCf = request.cf || {};
		const clientIP = request.headers.get('CF-Connecting-IP') || request.headers.get('True-Client-IP') || request.headers.get('X-Real-IP') || request.headers.get('X-Forwarded-For') || request.headers.get('Fly-Client-IP') || request.headers.get('X-Appengine-Remote-Addr') || request.headers.get('X-Cluster-Client-IP') || 'unknownIP';
		if (adminPassword && upgradeHeader === 'websocket') {
			const requestProxyState = mergeProxyState(baseProxyState, await parseProxyParams(url, userID));
			const transportHandlers = createRequestTransportHandlers(requestProxyState, requestLog);
			requestLog(`[WebSocket] matchedRequest: ${url.pathname}${url.search}`);
			return await transportHandlers.handleWebSocket(request, userID, url);
		} else if (adminPassword && !accessPath.startsWith('admin/') && accessPath !== 'login' && request.method === 'POST') {
			const requestProxyState = mergeProxyState(baseProxyState, await parseProxyParams(url, userID));
			const transportHandlers = createRequestTransportHandlers(requestProxyState, requestLog);
			const referer = request.headers.get('Referer') || '';
			const matchedXHTTPFeature = referer.includes('x_padding', 14) || referer.includes('x_padding=');
			if (!matchedXHTTPFeature && contentType.startsWith('application/grpc')) {
				requestLog(`[gRPC] matchedRequest: ${url.pathname}${url.search}`);
				return await transportHandlers.handleGRPC(request, userID);
			}
			requestLog(`[XHTTP] matchedRequest: ${url.pathname}${url.search}`);
			return await transportHandlers.handleXHTTP(request, userID);
		} else {
			if (url.protocol === 'http:') return Response.redirect(url.href.replace(`http://${url.hostname}`, `https://${url.hostname}`), 301);
			if (!adminPassword) return renderMissingAdminPage();
			if (accessPath === 'version') return jsonResponse({ Version: BUILD_VERSION });
			if (env.KV && typeof env.KV.get === 'function') {
				const caseSensitivePath = url.pathname.slice(1);
				if (caseSensitivePath === encryptKey && encryptKey !== 'doNotModifyDefaultKey，modifyViaEnvVarIfNeeded') {
					const params = new URLSearchParams(url.search);
					params.set('token', await hashTwiceSha256(host + userID));
					return redirectResponse(`/sub?${params.toString()}`);
				} else if (accessPath === 'login') {
					const authCookie = getAuthCookie(request);
					if (await verifyAuthCookie(authCookie, userAgent, encryptKey, adminPassword)) return redirectResponse('/admin');
					if (request.method === 'POST') {
						const formData = await request.text();
						const params = new URLSearchParams(formData);
						const inputPassword = params.get('password');
						if (inputPassword === adminPassword) {
							const authValue = await generateAuthCookie(userAgent, encryptKey, adminPassword);
							const response = jsonResponse({ success: true });
							response.headers.set('Set-Cookie', `auth=${authValue}; Path=/; Max-Age=86400; HttpOnly; Secure; SameSite=Strict`);
							return response;
						}
						return jsonResponse({ success: false, error: 'invalidPassword' }, 401);
					}
					return renderLoginPage();
				} else if (accessPath === 'admin' || accessPath.startsWith('admin/')) {
					const authCookie = getAuthCookie(request);
					if (!await verifyAuthCookie(authCookie, userAgent, encryptKey, adminPassword)) return redirectResponse('/login');
					if (accessPath === 'admin/log.json') {
						const readLogContent = await env.KV.get('log.json') || '[]';
						return new Response(readLogContent, { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
					} else if (caseSensitivePath === 'admin/getADDAPI') {
						if (url.searchParams.get('url')) {
							const preferredApiUrl = url.searchParams.get('url');
							try {
								new URL(preferredApiUrl);
								const preferredApiResult = await requestPreferredAPI([preferredApiUrl], url.searchParams.get('port') || '443');
								let preferredApiAddresses = preferredApiResult[0].length > 0 ? preferredApiResult[0] : preferredApiResult[1];
								preferredApiAddresses = preferredApiAddresses.map(item => String(item).replace(/#(.+)$/, (_, remark) => '#' + decodeURIComponent(remark)));
								return jsonResponse({ success: true, data: preferredApiAddresses });
							} catch (err) {
								return jsonResponse({ msg: 'validatePreferredAPIFailed，failReason：' + err.message, error: err.message }, 500);
							}
						}
						return jsonResponse({ success: false, data: [] }, 403);
					} else if (accessPath === 'admin/check') {
						const proxyProtocol = ['socks5', 'http', 'https', 'turn', 'sstp'].find(type => url.searchParams.has(type)) || null;
						if (!proxyProtocol) return jsonResponse({ error: 'missingProxyParams' }, 400);
						const proxyParams = url.searchParams.get(proxyProtocol);
						const { response: detectProxyResponse } = await checkProxyConnectivity(proxyProtocol, proxyParams, {
							createConnectors: (parsedProxyAddress) => createRequestProxyConnectors(parsedProxyAddress, requestLog),
						});
						return jsonResponse(detectProxyResponse);
					}

					if (accessPath === 'admin') return renderAdminPage();

					runtimeConfig = await readConfigJSON(env, host, userID, { userAgent, reverseProxyState: getReverseProxyState(baseProxyState) });

					if (accessPath === 'admin/init') {
						try {
							runtimeConfig = await readConfigJSON(env, host, userID, { userAgent, resetConfig: true, reverseProxyState: getReverseProxyState(baseProxyState) });
							ctx.waitUntil(requestLogger(env, request, clientIP, 'Init_Config', runtimeConfig));
							runtimeConfig.init = 'configResetToDefault';
							return jsonResponse(runtimeConfig);
						} catch (err) {
							return jsonResponse({ msg: 'configResetFailed，failReason：' + err.message, error: err.message }, 500);
						}
					} else if (request.method === 'POST') {
						if (accessPath === 'admin/config.json') {
							try {
								const newConfig = await request.json();
								if (!newConfig.UUID || !newConfig.HOST) return jsonResponse({ error: 'configIncomplete' }, 400);
								await env.KV.put('config.json', JSON.stringify(cleanConfigForStorage(newConfig), null, 2));
								ctx.waitUntil(requestLogger(env, request, clientIP, 'Save_Config', runtimeConfig));
								return jsonResponse({ success: true, message: 'configSaved' });
							} catch (error) {
								console.error('saveConfigFailed:', error);
								return jsonResponse({ error: 'saveConfigFailed: ' + error.message }, 500);
							}
						} else if (caseSensitivePath === 'admin/ADD.txt') {
							try {
								const customIPs = await request.text();
								await env.KV.put('ADD.txt', customIPs);
								ctx.waitUntil(requestLogger(env, request, clientIP, 'Save_Custom_IPs', runtimeConfig));
								return jsonResponse({ success: true, message: 'customIPSaved' });
							} catch (error) {
								console.error('saveCustomIPFailed:', error);
								return jsonResponse({ error: 'saveCustomIPFailed: ' + error.message }, 500);
							}
						} else return jsonResponse({ error: 'unsupportedPOSTPath' }, 404);
					} else if (accessPath === 'admin/config.json') {
						return jsonResponse(runtimeConfig, 200, { 'Content-Type': 'application/json' });
					} else if (caseSensitivePath === 'admin/ADD.txt') {
						let localPreferredIP = await env.KV.get('ADD.txt') || 'null';
						if (localPreferredIP == 'null') localPreferredIP = (await generateRandomIP(request, runtimeConfig.preferredSubGen.localIPDB.randomCount, runtimeConfig.preferredSubGen.localIPDB.specifiedPort, (runtimeConfig.protocolType === 'ss' ? runtimeConfig.SS.TLS : true)))[1];
						return new Response(localPreferredIP, { status: 200, headers: { 'Content-Type': 'text/plain;charset=utf-8', 'asn': String(requestCf.asn || '') } });
					}

					ctx.waitUntil(requestLogger(env, request, clientIP, 'Admin_Login', runtimeConfig));
					return renderAdminPage();
				} else if (accessPath === 'logout' || uuidRegex.test(accessPath)) {
					const response = new Response('redirecting...', { status: 302, headers: { 'Location': '/login' } });
					response.headers.set('Set-Cookie', 'auth=; Path=/; Max-Age=0; HttpOnly');
					return response;
				} else if (accessPath === 'sub') {
					const subscriptionToken = await hashTwiceSha256(host + userID), asSubGenerator = ['1', 'true'].includes(env.BEST_SUB) && url.searchParams.get('host') === 'example.com' && url.searchParams.get('uuid') === '00000000-0000-4000-8000-000000000000' && userAgent.toLowerCase().includes('tunnel (https://github.com/cmliu/edge');
					const requestTOKEN = url.searchParams.get('token');
					const clientRequestSubscription = requestTOKEN === subscriptionToken;
					if (clientRequestSubscription || asSubGenerator) {
						runtimeConfig = await readConfigJSON(env, host, userID, { userAgent, reverseProxyState: getReverseProxyState(baseProxyState) });
						if (asSubGenerator) ctx.waitUntil(requestLogger(env, request, clientIP, 'Get_Best_SUB', runtimeConfig, false));
						else ctx.waitUntil(requestLogger(env, request, clientIP, 'Get_SUB', runtimeConfig));
						const userAgentLower = userAgent.toLowerCase();
						const expire = 4102329600;
						const now = Date.now();
						const today = new Date(now);
						today.setHours(0, 0, 0, 0);
						const UD = Math.floor(((now - today.getTime()) / 86400000) * 24 * 1099511627776 / 2);
						const responseHeaders = {
							"content-type": "text/plain; charset=utf-8",
							"Profile-Update-Interval": runtimeConfig.preferredSubGen.SUBUpdateTime,
							"Profile-web-page-url": url.protocol + '//' + url.host + '/admin',
							"Subscription-Userinfo": `upload=${UD}; download=${UD}; total=${24 * 1099511627776}; expire=${expire}`,
							"Cache-Control": "no-store",
						};
						const isSubConverterRequest = url.searchParams.has('b64') || url.searchParams.has('base64') || request.headers.get('subconverter-request') || request.headers.get('subconverter-version') || userAgentLower.includes('subconverter') || userAgentLower.includes('cf-workers-sub') || asSubGenerator;
						let subType = isSubConverterRequest
							? 'mixed'
							: url.searchParams.has('target')
								? url.searchParams.get('target')
								: url.searchParams.has('clash') || userAgentLower.includes('clash') || userAgentLower.includes('meta') || userAgentLower.includes('mihomo')
									? 'clash'
									: url.searchParams.has('sb') || url.searchParams.has('singbox') || userAgentLower.includes('singbox') || userAgentLower.includes('sing-box')
										? 'singbox'
										: url.searchParams.has('surge') || userAgentLower.includes('surge')
											? 'surge&ver=4'
											: url.searchParams.has('quanx') || userAgentLower.includes('quantumult')
												? 'quanx'
												: url.searchParams.has('loon') || userAgentLower.includes('loon')
													? 'loon'
													: 'mixed';
						if (subType !== 'mixed') {
							subType = 'mixed';
							responseHeaders["X-Subscription-Format"] = 'mixed';
						}

						if (!userAgentLower.includes('mozilla')) responseHeaders["Content-Disposition"] = `attachment; filename*=utf-8''${encodeURIComponent(runtimeConfig.preferredSubGen.SUBNAME)}`;
						const protocolType = ((url.searchParams.has('surge') || userAgentLower.includes('surge')) && runtimeConfig.protocolType !== 'ss') ? 'trojan' : runtimeConfig.protocolType;
						let subContent = '';
						if (subType === 'mixed') {
							const tlsFragmentparams = runtimeConfig.tlsFragment == 'Shadowrocket' ? `&fragment=${encodeURIComponent('1,40-60,30-50,tlshello')}` : runtimeConfig.tlsFragment == 'Happ' ? `&fragment=${encodeURIComponent('3,1,tlshello')}` : '';
							let fullPreferredIP = [], otherNodeLinks = '', proxyIPPool = [];

							if (!url.searchParams.has('sub') && runtimeConfig.preferredSubGen.local) {
								const customPreferredList = runtimeConfig.preferredSubGen.localIPDB.randomIP ? null : await env.KV.get('ADD.txt');
								const fullPreferredList = runtimeConfig.preferredSubGen.localIPDB.randomIP ? (
									await generateRandomIP(request, runtimeConfig.preferredSubGen.localIPDB.randomCount, runtimeConfig.preferredSubGen.localIPDB.specifiedPort, (protocolType === 'ss' ? runtimeConfig.SS.TLS : true))
								)[0] : customPreferredList ? await normalizeToArray(customPreferredList) : (
									await generateRandomIP(request, runtimeConfig.preferredSubGen.localIPDB.randomCount, runtimeConfig.preferredSubGen.localIPDB.specifiedPort, (protocolType === 'ss' ? runtimeConfig.SS.TLS : true))
								)[0];
								const preferredAPI = [], preferredIP = [], otherNodes = [];
								for (const item of fullPreferredList) {
									if (item.toLowerCase().startsWith('sub://')) {
										preferredAPI.push(item);
									} else {
										const remarkPosition = item.indexOf('#');
										const addrPart = remarkPosition > -1 ? item.slice(0, remarkPosition) : item;
										const remarkPart = remarkPosition > -1 ? item.slice(remarkPosition) : '';
										const subMatch = item.match(/sub\s*=\s*([^\s&#]+)/i);
										if (subMatch && subMatch[1].trim().includes('.')) {
											const preferredIPAsProxyIP = item.toLowerCase().includes('proxyip=true');
											if (preferredIPAsProxyIP) preferredAPI.push('sub://' + subMatch[1].trim() + "?proxyip=true" + (item.includes('#') ? ('#' + item.split('#')[1]) : ''));
											else preferredAPI.push('sub://' + subMatch[1].trim() + (item.includes('#') ? ('#' + item.split('#')[1]) : ''));
										} else if (addrPart.toLowerCase().startsWith('https://')) {
											preferredAPI.push(item);
										} else if (addrPart.toLowerCase().includes('://')) {
											if (item.includes('#')) {
												const separateAddrRemark = item.split('#');
												otherNodes.push(separateAddrRemark[0] + '#' + encodeURIComponent(decodeURIComponent(separateAddrRemark[1])));
											} else otherNodes.push(item);
										} else {
											if (addrPart.includes('*')) {
												preferredIP.push(replaceStarsWithRandom(addrPart) + remarkPart);
											} else preferredIP.push(item);
										}
									}
								}
								const preferredApiResult = await requestPreferredAPI(preferredAPI, (protocolType === 'ss' && !runtimeConfig.SS.TLS) ? '80' : '443');
								const mergeOtherNodesArray = [...new Set(otherNodes.concat(preferredApiResult[1]))];
								otherNodeLinks = mergeOtherNodesArray.length > 0 ? mergeOtherNodesArray.join('\n') + '\n' : '';
								const preferredApiAddresses = preferredApiResult[0];
								proxyIPPool = preferredApiResult[3] || [];
								fullPreferredIP = [...new Set(preferredIP.concat(preferredApiAddresses))];
							} else {
								let subGenHOST = url.searchParams.get('sub') || runtimeConfig.preferredSubGen.SUB;
								const [subGenIPArray, subGenOtherNodes] = await getSubGenData(subGenHOST);
								fullPreferredIP = fullPreferredIP.concat(subGenIPArray);
								otherNodeLinks += subGenOtherNodes;
							}
							const isLoonOrSurge = userAgentLower.includes('loon') || userAgentLower.includes('surge');
							const { type: transportProtocol, pathFieldName, domainFieldName } = getTransportConfig(runtimeConfig);
							subContent = otherNodeLinks + fullPreferredIP.map(originalAddr => {
								const regex = /^(\[[\da-fA-F:]+\]|[\d.]+|[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*)(?::(\d+))?(?:#(.+))?$/;
								const match = originalAddr.match(regex);

								let nodeAddr, nodePort = "443", nodeRemark;

								if (match) {
									nodeAddr = match[1];
									nodePort = match[2] ? match[2] : (protocolType === 'ss' && !runtimeConfig.SS.TLS) ? '80' : '443';
									nodeRemark = match[3] || nodeAddr;
								} else {
									console.warn(`[subContent] irregularIPIgnored: ${originalAddr}`);
									return null;
								}

								let fullNodePath = runtimeConfig.fullNodePath;

								const chainProxyMatch = nodeRemark.match(/\$(socks5|http|https|turn|sstp):\/\/([^#\s]+)/i);
								if (chainProxyMatch) {
									try {
										const proxyProtocol = chainProxyMatch[1].toLowerCase(), proxyParams = chainProxyMatch[2];
										const chainProxyData = { type: proxyProtocol, ...getSOCKS5Account(proxyParams, getProxyDefaultPort(proxyProtocol)) };
										fullNodePath = `/video/${base64SecretEncode(JSON.stringify(chainProxyData), userID) + (runtimeConfig.enable0RTT ? '?ed=2560' : '')}`;
										nodeRemark = nodeRemark.replace(chainProxyMatch[0], '').trim() || nodeAddr;
									} catch (error) {
										console.warn(`[subContent] chainProxyParseFailed，instructionIgnored: ${chainProxyMatch[0]} (${error && error.message ? error.message : error})`);
									}
								} else if (proxyIPPool.length > 0) {
									const matchedProxyIP = proxyIPPool.find(p => p.includes(nodeAddr));
									if (matchedProxyIP) fullNodePath = (`${runtimeConfig.PATH}/proxyip=${matchedProxyIP}`).replace(/\/\//g, '/') + (runtimeConfig.enable0RTT ? '?ed=2560' : '');
								}
								if (isLoonOrSurge) fullNodePath = fullNodePath.replace(/,/g, '%2C');

								if (protocolType === 'ss' && !asSubGenerator) {
									fullNodePath = (fullNodePath.includes('?') ? fullNodePath.replace('?', '?enc=' + runtimeConfig.SS.encryptMethod + '&') : (fullNodePath + '?enc=' + runtimeConfig.SS.encryptMethod)).replace(/([=,])/g, '\\$1');
									if (!isSubConverterRequest) fullNodePath = fullNodePath + ';mux=0';
									return `${protocolType}://${btoa(runtimeConfig.SS.encryptMethod + ':00000000-0000-4000-8000-000000000000')}@${nodeAddr}:${nodePort}?plugin=v2${encodeURIComponent('ray-plugin;mode=websocket;host=example.com;path=' + (runtimeConfig.randomPath ? randomPath(fullNodePath) : fullNodePath) + (runtimeConfig.SS.TLS ? ';tls' : '')) + tlsFragmentparams}#${encodeURIComponent(nodeRemark)}`;
								} else {
									const transportPathParamValue = getTransportPathParam(runtimeConfig, fullNodePath, asSubGenerator);
									return `${protocolType}://00000000-0000-4000-8000-000000000000@${nodeAddr}:${nodePort}?security=tls&type=${transportProtocol}&${domainFieldName}=example.com&fp=${runtimeConfig.Fingerprint}&sni=example.com&${pathFieldName}=${encodeURIComponent(transportPathParamValue) + tlsFragmentparams}&encryption=none${runtimeConfig.skipCertVerify ? '&insecure=1&allowInsecure=1' : ''}#${encodeURIComponent(nodeRemark)}`;
								}
							}).filter(item => item !== null).join('\n');
						}

						if (!userAgentLower.includes('subconverter') && clientRequestSubscription) {
							const shuffledHOSTS = [...runtimeConfig.HOSTS].sort(() => Math.random() - 0.5);
							let replaceDomainCount = 0, currentRandomHOST = null;
							subContent = subContent
								.replace(/00000000-0000-4000-8000-000000000000/g, runtimeConfig.UUID)
								.replace(/MDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDAwMDAw/g, btoa(runtimeConfig.UUID))
								.replace(/example\.com/g, () => {
									if (replaceDomainCount % 2 === 0) {
										const originalHost = shuffledHOSTS[Math.floor(replaceDomainCount / 2) % shuffledHOSTS.length];
										currentRandomHOST = replaceStarsWithRandom(originalHost);
									}
									replaceDomainCount++;
									return currentRandomHOST;
								});
						}

						if (subType === 'mixed' && (!userAgentLower.includes('mozilla') || url.searchParams.has('b64') || url.searchParams.has('base64'))) subContent = btoa(subContent);

						return new Response(subContent, { status: 200, headers: responseHeaders });
					}
				} else if (accessPath === 'locations') {
					const cookies = request.headers.get('Cookie') || '';
					const authCookie = cookies.split(';').find(c => c.trim().startsWith('auth='))?.split('=')[1];
					if (await verifyAuthCookie(authCookie, userAgent, encryptKey, adminPassword)) return fetch(new Request('https://speed.cloudflare.com/locations', { headers: { 'Referer': 'https://speed.cloudflare.com/' } }));
				} else if (accessPath === 'robots.txt') return new Response('User-agent: *\nDisallow: /', { status: 200, headers: { 'Content-Type': 'text/plain; charset=UTF-8' } });
			} else if (!envUUID) return renderMissingKvPage();
		}

		let disguisePageURL = env.URL || 'nginx';
		if (disguisePageURL && disguisePageURL !== 'nginx' && disguisePageURL !== '1101') {
			disguisePageURL = disguisePageURL.trim().replace(/\/$/, '');
			if (!disguisePageURL.match(/^https?:\/\//i)) disguisePageURL = 'https://' + disguisePageURL;
			if (disguisePageURL.toLowerCase().startsWith('http://')) disguisePageURL = 'https://' + disguisePageURL.substring(7);
			try { const u = new URL(disguisePageURL); disguisePageURL = u.protocol + '//' + u.host } catch (e) { disguisePageURL = 'nginx' }
		}
		if (disguisePageURL === '1101') return new Response(await html1101(url.host, clientIP), { status: 200, headers: { 'Content-Type': 'text/html; charset=UTF-8' } });
		try {
			const proxyURL = new URL(disguisePageURL), newRequestHeaders = new Headers(request.headers);
			newRequestHeaders.set('Host', proxyURL.host);
			newRequestHeaders.set('Referer', proxyURL.origin);
			newRequestHeaders.set('Origin', proxyURL.origin);
			if (!newRequestHeaders.has('User-Agent') && userAgent && userAgent !== 'null') newRequestHeaders.set('User-Agent', userAgent);
			const proxyResponse = await fetch(proxyURL.origin + url.pathname + url.search, { method: request.method, headers: newRequestHeaders, body: request.body, cf: requestCf });
			const contentType = proxyResponse.headers.get('content-type') || '';
			if (/text|javascript|json|xml/.test(contentType)) {
				const responseContent = (await proxyResponse.text()).replaceAll(proxyURL.host, url.host);
				return new Response(responseContent, { status: proxyResponse.status, headers: { ...Object.fromEntries(proxyResponse.headers), 'Cache-Control': 'no-store' } });
			}
			return proxyResponse;
		} catch (error) { requestLog(`[reverseProxy] requestFailed: ${error.message}`) }
		return new Response(await nginx(), { status: 200, headers: { 'Content-Type': 'text/html; charset=UTF-8' } });
	}
};
