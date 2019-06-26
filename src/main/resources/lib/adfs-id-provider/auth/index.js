/**
 * auth module.
 * @module lib/adfs-id-provider/auth
 */

//──────────────────────────────────────────────────────────────────────────────
// Require libs
//──────────────────────────────────────────────────────────────────────────────
exports.group         = require('./group');
exports.sanitizeName  = require('./sanitizeName');
exports.user          = require('./user');

var lib = {
	adfsIdProvider: {
		context: require('/lib/adfs-id-provider/context'),
		object: require('/lib/adfs-id-provider/object')
	},
	xp: {
		auth: require('/lib/xp/auth'),
		portal: require('/lib/xp/portal')
	}
};

//──────────────────────────────────────────────────────────────────────────────
// Alias functions from libs
//──────────────────────────────────────────────────────────────────────────────
var runAsAdmin          = lib.adfsIdProvider.context.runAsAdmin;
var toStr               = lib.adfsIdProvider.object.toStr;
var getIdProviderConfig = lib.xp.auth.getIdProviderConfig;
var logout              = lib.xp.auth.logout;
var getSite             = lib.xp.portal.getSite;
var loginUrl            = lib.xp.portal.loginUrl;
var pageUrl             = lib.xp.portal.pageUrl;

//──────────────────────────────────────────────────────────────────────────────
// Auth methods
//──────────────────────────────────────────────────────────────────────────────

/**
 * If the request has a redirectUrl and a valid ticket it returns the redirectUrl.
 * Or tries to get site from context and return its url.
 * Or fallbacks to /
 * @param {Object} request
 * @param {Object} request.params
 * @param {string} request.params.redirect
 * @param {string} request.validTicket
 * @returns {url}
 */
function getRedirectAfterLogoutUrl(request) {
	var redirectAfterLogoutUrl = function(request) {
		if(request && request.validTicket && request.params && request.params.redirect) {
			return request.params.redirect;
		}
		var site = getSite();
		return site ? pageUrl({ id: site._id, type: 'absolute' }) : '/';
	}();
	log.debug('redirectAfterLogoutUrl:' + toStr(redirectAfterLogoutUrl));
	return redirectAfterLogoutUrl;
};
exports.getRedirectAfterLogoutUrl = getRedirectAfterLogoutUrl;


/**
 * Redirects the browser to idProviderConfig.logoutUrl
 * @param {Object} request
 * @returns {redirectResponse}
 */
exports.handleLogoutRequest = function(request) {
	log.debug('handleLogoutRequest(' + toStr(request) + ')');

	var logoutResult = logout();
	//log.debug('logoutResult:' + toStr(logoutResult)); // Always undefined in Enonix XP 6.9.2

	var redirectAfterLogoutUrl = getRedirectAfterLogoutUrl(request);

	var idProviderConfig = getIdProviderConfig();
	log.debug('idProviderConfig:' + toStr(idProviderConfig));

	var redirectResponse = {
		status: 307, // Temporary redirect // http://insanecoding.blogspot.no/2014/02/http-308-incompetence-expected.html
		headers: {
			'Location': idProviderConfig.logoutUrl + redirectAfterLogoutUrl
		},
		postProcess: false,
		applyFilters: false
	};
	log.debug('redirectResponse:' + toStr(redirectResponse));
	return redirectResponse;
};

exports.addOrReplaceToState = function (key, jwt) {
	var bean = __.newBean('openidConnectTokenMediator.no.item.lib.impl.StateScriptBean');
	return bean.addOrReplaceToState(key, jwt);
};