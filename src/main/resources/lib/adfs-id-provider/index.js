/**
 * adfs-id-provider module.
 * @module lib/adfs-id-provider
 */

//──────────────────────────────────────────────────────────────────────────────
// Require libs
//──────────────────────────────────────────────────────────────────────────────
exports.array = require('./array');
exports.auth = require('./auth');
exports.jwt = require('./jwt');
exports.oauth2 = require('./oauth2');
exports.object = require('./object');

var lib = {
    xp: {
        auth: require('/lib/xp/auth'),
        portal: require('/lib/xp/portal')
    }
};

//──────────────────────────────────────────────────────────────────────────────
// Alias functions from libs
//──────────────────────────────────────────────────────────────────────────────
var inFirstButNotInSecond = exports.array.inFirstButNotInSecond;
var createAndUpdateGroupsFromJwt = exports.auth.group.createAndUpdateGroupsFromJwt;
var createOrUpdateFromJwt = exports.auth.user.createOrUpdateFromJwt;
var modifyProfile = exports.auth.user.modifyProfile;
var jwtFromAccessToken = exports.jwt.fromAccessToken;
var requestAccessToken = exports.oauth2.requestAccessToken;
var isSet = exports.object.isSet;
var toStr = exports.object.toStr;
var valueFromFormat = exports.object.valueFromFormat;
var getIdProviderConfig = lib.xp.auth.getIdProviderConfig;
var login = lib.xp.auth.login;
var addOrReplaceToState = exports.auth.addOrReplaceToState;

//──────────────────────────────────────────────────────────────────────────────
// ADFS ID provider methods
//──────────────────────────────────────────────────────────────────────────────
/**
 * This method is called when the user is redirected back after logging into SSO.
 * It can create or update user, profile and group membership based on jwt data received in an accesstoken.
 * Then it will login the user and redirect the user back to the page that was requested before login.
 * @param {*} request
 * @returns {httpRedirectResponse}
 */
exports.handleIdProviderRequest = function (request) {
    log.debug('handleIdProviderRequest(' + toStr(request) + ')');

    var accessTokenResponse = requestAccessToken(request);
    log.debug('accessTokenResponse:' + toStr(accessTokenResponse));

    var json = JSON.parse(accessTokenResponse.body);
    log.debug('json:' + toStr(json));

    if (json.error) {
        log.error(toStr(json));
        throw new Error('Something went wrong when requesting access token.');
    }

    var jwt = jwtFromAccessToken({accessToken: json.access_token});

    var idProviderConfig = getIdProviderConfig();
    log.debug('idProviderConfig:' + toStr(idProviderConfig));
    log.debug('jwt payload:' + toStr(jwt.payload));

    var user = createOrUpdateFromJwt({jwt: jwt});

    if (json.expires_in) {
        var now = new Date();
        //json.expires_in = 2; // NOTE: TODO: DEBUGGING expire in 2 seconds (will autoLogin as not expired on SSO...)
        var expiresAt = new Date(now.getTime() + (1000 * json.expires_in));
        log.debug('expires_in:' + toStr(json.expires_in) + ' now:' + toStr(now) + ' expiresAt:' + toStr(expiresAt));
        modifyProfile({
            key: user.key,
            profile: {expiresAt: expiresAt},
            scope: 'accessToken',
            log: false
        });
    }

    createAndUpdateGroupsFromJwt({
        jwt: jwt,
        user: user
    });

    var loginResult = login({
        user: user.login,
        idProvider: user.idProvider,
        skipAuth: true
    });
    log.debug('loginResult:' + toStr(loginResult));

    var isAuthenticated = loginResult.authenticated;
    if(isAuthenticated){
        addOrReplaceToState(user.key, toStr(json));
    }

    var location = request.cookies && request.cookies.enonicXpReturnToUrl ? request.cookies.enonicXpReturnToUrl : '/';

    return { // redirect to origUrl
        status: 307,
        headers: {
            'Location': location
        },
        postProcess: false,
        applyFilters: false
    };

}; // function handleIdProviderRequest
