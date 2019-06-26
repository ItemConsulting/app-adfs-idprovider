/**
 * oauth2 module.
 * @module lib/adfs-id-provider/oauth2
 */

//──────────────────────────────────────────────────────────────────────────────
// Require libs
//──────────────────────────────────────────────────────────────────────────────
var lib = {
	adfsIdProvider: {
		object: require('/lib/adfs-id-provider/object'),
		portal: require('/lib/adfs-id-provider/portal')
	},
	node: {
		uriJs: require('/lib/urijs/src/URI')
	},
	xp: {
		auth:       require('/lib/xp/auth'),
		httpClient: require('/lib/http-client'),
		portal:     require('/lib/xp/portal')
	}
};

//──────────────────────────────────────────────────────────────────────────────
// Alias functions from libs
//──────────────────────────────────────────────────────────────────────────────
var toStr               = lib.adfsIdProvider.object.toStr;
var valueFromFormat     = lib.adfsIdProvider.object.valueFromFormat;
var getReturnToUrl      = lib.adfsIdProvider.portal.getReturnToUrl;
var getIdProviderConfig = lib.xp.auth.getIdProviderConfig;
var sendRequest         = lib.xp.httpClient.request;
var getIdProviderKey     = lib.xp.portal.getIdProviderKey;
var getIdProviderUrl    = lib.xp.portal.idProviderUrl;

//──────────────────────────────────────────────────────────────────────────────
// Oauth2 methods
//──────────────────────────────────────────────────────────────────────────────


/**
 * Redirect the browser to the SSO login page so the user can login.
 * @param {request} request
 * @returns {httpTemporaryRedirectResponse}
 */
exports.redirectToAuthorizationUrl = function(request) {
	log.debug('redirectToAuthorizationUrl(' + toStr(request) + ')');

	var idProviderConfig = getIdProviderConfig();
	log.debug('idProviderConfig:' + toStr(idProviderConfig));

	var clientId = idProviderConfig.clientId;
	var resource = idProviderConfig.resource || request.scheme + '://' + request.host + (request.port ? ':' + request.port : '');
	var redirectUri = lib.xp.portal.idProviderUrl({type:'absolute'});
    log.debug('redirectUri:' + redirectUri);
	var returnToUrl = getReturnToUrl(request);
	var location = new lib.node.uriJs(idProviderConfig.authorizationUrl);
	location.addQuery('response_type', 'code');
	location.addQuery('client_id', clientId);
	location.addQuery('scope', 'openid');
	location.addQuery('resource', resource);
	location.addQuery('redirect_uri', redirectUri);

	var response = {
		body: '', // NOTE: Workaround for Safari so Content-Length header becomes 0 on /admin/tool
		status: 307, // Temporary redirect // http://insanecoding.blogspot.no/2014/02/http-308-incompetence-expected.html
		headers: {
			'Location': location.toString()
		},
		postProcess: false,
		applyFilters: false
	};
	log.debug('redirectToAuthorizationUrl() response:' + toStr(response));
	return response;
}; // function redirectToAuthorizationUrl


/**
 * Ask the authentication provider directly (server to server) for an access token, using request.params.code and clientId.
 * @param {request} request
 * @returns {accessTokenResponse}
 */
exports.requestAccessToken = function(request) {
	log.debug('requestAccessToken(' + toStr(arguments) + ')');

	var idProviderConfig = getIdProviderConfig();
	log.debug('idProviderConfig:' + toStr(idProviderConfig));

	var idProviderUrl = getIdProviderUrl({type:'absolute'});
	log.debug('idProviderUrl:' + toStr(idProviderUrl));

	var redirectUri = lib.xp.portal.idProviderUrl({type:'absolute'});
	var accessTokenRequest = {
		method: 'POST',
		url: idProviderConfig.tokenUrl,
		headers: {
			Accept: 'appication/json'
		},
		params: {
			grant_type: 'authorization_code',
			client_id: idProviderConfig.clientId,
			code: request.params.code,
			client_secret: idProviderConfig.clientSecret,
			redirect_uri: redirectUri
		},
		proxy: idProviderConfig.proxy
	};
	log.debug('requestAccessToken: accessTokenRequest:' + toStr(accessTokenRequest));

	var accessTokenResponse = sendRequest(accessTokenRequest);
	log.debug('requestAccessToken: accessTokenResponse:' + toStr(accessTokenResponse));

	return accessTokenResponse;
	/* {
		"access_token":"thetoken", // JWT format
		"token_type":"bearer",
		"expires_in":3600
		// Because the Client did not authenticate itself with any client secret, no refresh token is issued
	}*/
};
