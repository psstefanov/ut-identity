var utUserHelpers = require('ut-user/helpers');
var errors = require('../errors');

function Helpers({importMethod, crypt}) {
    if (!(this instanceof Helpers)) {
        return new Helpers({importMethod, crypt});
    }

    this.importMethod = importMethod;
    this.crypt = crypt;
}

/**
 * Validates password against user Access policy. E.g. Passowrd lenght and required symbols (lower case, special symbol, etc.)
 * @param {newPasswordRaw} plain new password
 * @param {passwordCredentaislGetStoreProcedureParams} params that 'policy.passwordCredentials.get' Store procedure requires
 *  username: string
 *  type: one of forgottenPassword|registerPassword|password
 *  password: string. Could be plain or hashed. However, the store procedure requires hashed password therefore additional properties
 *     could be passed to this object to make this method to hash the password: requiresPassHash and hashParams
 *  requiresPassHash: boolen. If this property is true the method will require to pass hashParams as well
 *  hashParams: object having params property. Used to hash the password with the passed params
 * @param {$meta} object
 * @param {actorId} number|string. Required only if $meta object has no 'auth.actorId' propepry.
 *  Store procedure 'core.itemTranslation.fetch' requires actorId. This SP will be executed if the new password does not match the access policy
 *  and appropriate message need to be displayed to the user
 *
 * Return true or throws error
 */
Helpers.prototype.validateNewPasswordAgainstAccessPolicy = function(newPasswordRaw, passwordCredentaislGetStoreProcedureParams, $meta, actorId) {
    // There are cases iwhere we passes the current hashed password => no need to hash it
    var hashPassword = new Promise(function(resolve, reject) {
        if (passwordCredentaislGetStoreProcedureParams.requiresPassHash) {
            var hashParams = passwordCredentaislGetStoreProcedureParams.hashParams;
            var password = passwordCredentaislGetStoreProcedureParams.password;
            if (hashParams && password) {
                utUserHelpers.genHash(password, JSON.parse(hashParams.params))
                    .then(function(hashedPassword) {
                        resolve(hashedPassword);
                    });
            } else {
                throw errors['identity.hashParams']();
            }
        } else {
            resolve(passwordCredentaislGetStoreProcedureParams.password);
        }
    });

    var importMethod = this.importMethod;
    return hashPassword
    .then(function(hashedPassword) {
        var policyPasswordCredentalsGetParams = {
            username: passwordCredentaislGetStoreProcedureParams.username,
            type: passwordCredentaislGetStoreProcedureParams.type,
            password: hashedPassword,
            channel: passwordCredentaislGetStoreProcedureParams.channel
        };
        return importMethod('policy.passwordCredentials.get')(policyPasswordCredentalsGetParams)
        .then(function(policyResult) {
            // Validate password policy
            var passwordCredentials = policyResult['passwordCredentials'][0];
            var isPasswordValid = utUserHelpers.isParamValid(newPasswordRaw, passwordCredentials);
            if (isPasswordValid) {
                // Validate previous password
                var previousPasswords = policyResult['previousPasswords'] || [];

                var genHashPromises = [];
                var cachedHashPromises = {};
                var cachedHashPromisesPrevPassMap = {}; // stores index from genHash to which prevPassword index is, in order to avoid generating the same hash multiple times

                var prevPassMapIndex = -1;
                for (var i = 0; i < previousPasswords.length; i += 1) {
                    var currentPrevPasswordObj = previousPasswords[i];
                    var currentPassWillBeCached = cachedHashPromises[currentPrevPasswordObj.params];
                    if (!currentPassWillBeCached) {
                        genHashPromises.push(utUserHelpers.genHash(newPasswordRaw, JSON.parse(currentPrevPasswordObj.params)));
                        cachedHashPromises[currentPrevPasswordObj.params] = true;
                        prevPassMapIndex += 1;
                    }

                    cachedHashPromisesPrevPassMap[i] = prevPassMapIndex;
                }

                return Promise.all(genHashPromises).then((res) => {
                    var newPassMatchPrev = false;

                    for (var i = 0; i < previousPasswords.length && !newPassMatchPrev; i += 1) {
                        var currentPrevPassword = previousPasswords[i];
                        var currentHashIndex = cachedHashPromisesPrevPassMap[i];
                        var currentNewHashedPassword = res[currentHashIndex];
                        if (currentPrevPassword.value === currentNewHashedPassword) {
                            newPassMatchPrev = true;
                        }
                    }

                    if (newPassMatchPrev) {
                        throw errors['identity.term.matchingPrevPassword']();
                    } else {
                        return true;
                    }
                });
            } else {
                if (!($meta['auth.actorId'] || ($meta['auth'] && ($meta['auth']['actorId'])))) {
                    if (!actorId) {
                        throw errors['identity.actorId']();
                    }
                    $meta['auth.actorId'] = actorId;
                }
                return importMethod('core.itemTranslation.fetch')({
                    itemTypeName: 'regexInfo',
                    languageId: 1 // the languageId should be passed by the UI, it should NOT be the user default language becase the UI can be in english and the default user language might be france
                }, $meta).then(function(translationResult) {
                    var printMessage = utUserHelpers.buildPolicyErrorMessage(translationResult.itemTranslationFetch, passwordCredentials.regexInfo, passwordCredentials.charMin, passwordCredentials.charMax);
                    var invalidNewPasswordError = errors['identity.term.invalidNewPassword'](printMessage);
                    invalidNewPasswordError.message = printMessage;
                    throw invalidNewPasswordError;
                });
            }
        });
    });
};

/**
 * Parse response for mobile offline login factors and terms.
 * Used only when channel is mobile.
 *
 * @param {Object} msg
 * @returns {Object}
 */
Helpers.prototype.parseMobileOfflineResponse = function(msg) {
    var onlineLoginFactors = msg['loginFactors.online'];
    if (onlineLoginFactors) {
        msg.loginFactors = {};
        msg.loginFactors.online = {
            type: onlineLoginFactors[0].type,
            params: onlineLoginFactors[0].params
        };

        // Offline factors
        if (msg['loginFactors.offline']) {
            var factors = [];
            var factorsOrderToIndexMapped = {};
            var crypt = this.crypt;
            // As discussed with the Mobile team only factor with higher priority will be returned
            var lowestFactorOrder = Number.MAX_SAFE_INTEGER;
            var lowestFactorOrderIndex = -1; // store the index in factors

            msg['loginFactors.offline'].forEach(function(term) {
                if (term.factorOrder) {
                    var factorIndex = factorsOrderToIndexMapped[term.factorOrder];
                    var factor;

                    if (term.type === 'bio' && term.templates) {
                        term.params = {};
                        term.params.fingers = parseBioTemplates(term.templates, crypt);
                        delete term['templates'];
                    }

                    var termToPush = {
                        // name: term.name,
                        type: term.type,
                        allowedAttempts: term.allowedAttempts,
                        params: term.params
                        // termId: term.termId,
                        // termOrder: term.termOrder
                    };
                    if (factorIndex === undefined) {
                        factorsOrderToIndexMapped[term.factorOrder] = factors.length;
                        factor = {
                            id: term.factorId,
                            order: term.factorOrder,
                            fnOrder: term.fnOrder
                        };

                        factor.terms = [];
                        factor.terms.push(termToPush);

                        // update lowest factor order
                        if (term.factorOrder < lowestFactorOrder) {
                            lowestFactorOrder = term.factorOrder;
                            lowestFactorOrderIndex = factors.length;
                        }

                        factors.push(factor);
                    } else {
                        factor = factors[factorIndex];
                        factor.terms.push(termToPush);
                    }
                }
            });

            msg.loginFactors.offline = factors[lowestFactorOrderIndex]['terms'];
            delete msg['loginFactors.offline'];
        }

        delete msg['loginFactors.online'];
    }

    return msg;
};

/**
 * Parse (decrypt) fingers data
 *
 * @param {string} templates
 * @returns {Object[]}
 */
function parseBioTemplates(stringifyTemplates, crypt) {
    var result = [];

    var templates = JSON.parse(stringifyTemplates);
    for (var finger in templates) {
        var template = crypt.decrypt(templates[finger]);

        var currentObject = {
            id: finger,
            template: template
        };
        result.push(currentObject);
    }

    return result;
};

Helpers.prototype.buildPasswordCredentaislGetStoreProcedureParams = function(msg) {
    // The SP receives type param which determines which action should be taken
    var type;
    var password;

    if (msg.hasOwnProperty('forgottenPassword')) {
        type = 'forgottenPassword';
        password = msg.forgottenPassword;
    } else if (msg.hasOwnProperty('registerPassword')) {
        type = 'registerPassword';
        password = msg.registerPassword;
    } else {
        type = 'password';
        password = msg.password;
    }

    return {
        username: msg.username,
        type: type,
        password: password,
        channel: msg.channel
    };
};

/**
 * Returns function or hashMethods depending on propery method
 *
 * @param {string} method
 * @param {Object} params
 * @param {Object} hashParams
 * @returns {function|Object}
 */
Helpers.prototype.getHash = function(method, params, hashParams) {
    var getHash = function(password, hashData) {
        if (!hashData || !hashData.params) {
            return errors.MissingCredentials.reject();
        }
        hashData.params = typeof (hashData.params) === 'string' ? JSON.parse(hashData.params) : hashData.params;
        return this.importMethod('user.genHash')(password, hashData.params);
    };

    var hashMethods = {
        otp: getHash.bind(this),
        password: getHash.bind(this),
        registerPassword: getHash.bind(this),
        forgottenPassword: getHash.bind(this),
        newPassword: getHash.bind(this),
        bio: function(values, hashData) {
            // values - array like: [{finger: "L1", templates: ["RRMNDKSF...]}, {finger: "L2", templates: ["RRMNDKSF...]}].
            // where finger could be one of 'L1', 'L2', 'L3', 'L4', 'L5', 'R1', 'R2', 'R3', 'R4', 'R5'
            // Joi validations validates that
            var mappedBioData = {};
            var successDataResponse = [];
            values.forEach(function(val) {
                mappedBioData[val.finger] = val.templates;
                successDataResponse.push(val.finger);
            });

            // Validate output object
            if (Object.keys(mappedBioData).length === 0) {
                return new Promise(function(resolve, reject) {
                    resolve(['']);
                });
            }

            /*
                Bio server example request:
                id: params.id,
                departmentId: params.departmentId,
                data: {
                    UK: [value]
                }
            */

            // On this stage BIO server can check one finger at time.
            var bioCheckPromises = [];
            var params = JSON.parse(hashData.params);
            for (var finger in mappedBioData) {
                if (mappedBioData.hasOwnProperty(finger)) {
                    var currentData = {};
                    currentData[finger] = mappedBioData[finger];
                    bioCheckPromises.push(this.importMethod('bio.check')({
                        id: params.bio.id,
                        departmentId: params.bio.departmentId,
                        data: currentData
                    }));
                }
            }

            return Promise.all(bioCheckPromises)
                .then(function(r) {
                    return successDataResponse;
                })
                .catch(function(r) {
                    return [''];
                });
        }
    };

    if (method) {
        return hashMethods[method](params, hashParams);
    } else {
        return hashMethods;
    }
};

Helpers.prototype.handleError = function(err) {
    if (typeof err.type === 'string') {
        if (
            err.type === 'policy.term.checkBio' ||
            err.type === 'policy.term.checkOTP' ||
            err.type === 'identity.term.invalidNewPassword' ||
            err.type === 'identity.term.matchingPrevPassword' ||
            err.type === 'user.identity.registerPasswordValidate.expiredPassword' ||
            err.type === 'user.identity.registerPasswordChange.expiredPassword' ||
            err.type === 'user.identity.registerPasswordValidate.invalidCredentials' ||
            err.type === 'user.identity.registerPasswordChange.invalidCredentials' ||
            err.type === 'identity.invalidFingerprint' ||
            err.type === 'user.invalidLoginTime' ||
            err.type === 'policy.term.otpExpired' ||
            err.type.startsWith('policy.param.')
        ) {
            throw err;
        } else if (
            err.type === 'user.identity.forgottenPasswordValidate.invalidCredentials' ||
            err.type === 'user.identity.forgottenPasswordValidate.expiredPassword' ||
            err.type === 'user.identity.forgottenPasswordValidate.notFound' ||
            err.type === 'user.identity.check.userPassword.wrongPassword' ||
            err.type === 'user.identity.checkPolicy.notFound' ||
            err.type === 'user.identity.check.userPassword.notFound' ||
            err.type === 'user.identity.checkPolicy.disabledCredentials' ||
            err.type === 'user.disabledCredentials' ||
            err.type === 'user.identity.check.disabledUser' ||
            err.type === 'user.identity.check.disabledUserInactivity' ||
            err.type === 'user.invalidChannel' ||
            err.type === 'user.identity.checkPolicy.disabledUserInactivity' ||
            err.type === 'user.identity.checkPolicy.invalidChannel' ||
            err.type === 'identity.credentialsLocked' ||
            err.type === 'identity.notFound' ||
            err.type === 'identity.multipleResults' ||
            err.type.startsWith('policy.term.')
        ) {
            throw errors['identity.invalidCredentials'](err);
        } else if (err.type === 'PortSQL' && (err.message.startsWith('policy.param.bio.fingerprints')) || err.message.startsWith('policy.term.checkBio')) {
            err.type = err.message;
            throw err;
        }
    }
    if (err.type === 'core.throttle' || err.message === 'core.throttle') {
        throw errors['identity.throttleError'](err);
    }
    if (err.type === 'identity.throttleErrorForgotten' || err.message === 'identity.throttleErrorForgotten') {
        throw err;
    }
    throw errors['identity.systemError'](err);
};

module.exports = Helpers;
