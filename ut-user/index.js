var UtIdentityHelpers = require('./helpers');
var assign = require('lodash.assign');
var errors = require('../errors');
var UtCrypt = require('ut-core/crypt');

var helpers;
var crypt;
var importMethod;
var checkMethod;
var debug;

function getCrypt(cryptKey) {
    if (!crypt) {
        crypt = new UtCrypt({cryptParams: {password: cryptKey}});
    }
    return crypt;
}

module.exports = {
    init: function(b) {
        getCrypt(b.config.masterCryptKey);
        importMethod = b.importMethod.bind(b);
        checkMethod = b.config['identity.check'];
        debug = b.config.debug;
        helpers = new UtIdentityHelpers({
            importMethod,
            crypt: getCrypt()
        });
    },
    registerRequest: function(msg, $meta) {
        var password = Math.floor(1000 + Math.random() * 9000) + '';
        var data = {};
        var result = {};
        var promises = [];
        // We have following flows in registration request:
        // 1. Registration flow (independent) - Create a password, hash it, try find/create/replace user.hash
        // 2. Template flow (independent) - Load a template to send SMS/email to user.
        // 3. Message flow (depends on 1 and 2) - If registration is successful and we have template, enqueue message to customer.
        promises.push(importMethod('user.getHash')(
            {
                value: password,
                type: 'registerPassword',
                identifier: msg.username
            }
        ).then(function(passwordHash) {
            msg.hash = passwordHash;
            return importMethod('user.identity.registerClient')(msg);
        }).then(function(identity) {
            if (!identity.phone || !identity.phone.phoneNumber) {
                throw errors['identity.notFound']();
            }
            data.identity = identity;
            return;
        }));
        return Promise.all(promises).then(function() {
            var customerMessage = {
                // This data comes from flow 1
                port: data.identity.phone.mnoKey,
                recipient: data.identity.phone.phoneNumber,
                template: 'customer.self.registration.otp',
                data: {
                    firstName: data.identity.person.firstName,
                    hash: password
                },
                languageCode: msg.language,
                priority: 1
            };
            return importMethod('alert.message.send')(customerMessage, assign({}, $meta, {
                auth: {
                    actorId: data.identity.customer.actorId
                },
                method: 'alert.message.send'
            }));
        }).then(function() {
            if (debug) {
                result.otp = password;
            }
            return result;
        }).catch(helpers.handleError);
    },
    registerValidate: function(msg, $meta) {
        $meta.method = 'user.hash.return';
        return importMethod($meta.method)({
            identifier: msg.username,
            type: 'registerPassword'
        }, $meta).then(function(response) {
            if (!response.hashParams) {
                throw errors['identity.notFound']();
            }
            return helpers.getHash('registerPassword', msg.registerPassword, response.hashParams);
        }).then(function(registerPassword) {
            msg.registerPassword = registerPassword;
            $meta.method = 'user.identity.registerPasswordValidate';
            return importMethod($meta.method)(msg, $meta);
        }).catch(helpers.handleError);
    },
    check: function(msg, $meta) {
        delete msg.type;
        var creatingSession = false;
        var get;
        if (msg.sessionId) {
            get = Promise.resolve(msg);
        } else {
            creatingSession = true;
            $meta.method = 'user.identity.get'; // get hashes info
            get = importMethod($meta.method)(msg, $meta)
                .then(function(result) {
                    if (!result.hashParams) {
                        throw errors['identity.hashParams']();
                    }
                    var hashData = result.hashParams.reduce(function(all, record) {
                        all[record.type] = record;
                        msg.actorId = record.actorId;
                        return all;
                    }, {});
                    if (msg.newPassword && hashData.password) {
                        hashData.newPassword = hashData.password;
                    }

                    return Promise.all(
                        Object.keys(helpers.getHash())
                            .filter(function(method) {
                                return hashData[method] && msg[method];
                            })
                            .map(function(method) {
                                return helpers.getHash(method, msg[method], hashData[method])
                                    .then(function(value) {
                                        msg[method] = value;
                                        return;
                                    });
                            })
                    )
                    .then(function() {
                        return msg;
                    });
                });
        }
        if (msg.hasOwnProperty('newPassword')) {
            // Validate new password access policy
            var rawNewPassword = arguments[0]['newPassword'];
            var passwordCredentaislGetStoreProcedureParams;

            if (msg.hasOwnProperty('registerPassword')) {
                var hash = msg.newPassword == null ? Promise.resolve([]) : importMethod('user.getHash')({
                    identifier: msg.username,
                    value: msg.newPassword,
                    type: 'password'
                });
                get = Promise.all([get, hash,
                    new Promise(function(resolve, reject) {
                        return importMethod('core.throttle.perform')({
                            name: 'identity.check',
                            instance: `${msg.username}registerPassword`
                        }).then(function(res) {
                            resolve(true);
                        }).catch(function(err) {
                            reject(errors['identity.throttleError'](err));
                        });
                    })
                ])
                .then(function() {
                    var r = arguments[0][0];
                    var hash = arguments[0][1];

                    passwordCredentaislGetStoreProcedureParams = helpers.buildPasswordCredentaislGetStoreProcedureParams(msg);
                    return helpers.validateNewPasswordAgainstAccessPolicy(rawNewPassword, passwordCredentaislGetStoreProcedureParams, $meta, msg.actorId)
                    .then(function() {
                        $meta.method = 'user.identity.registerPasswordChange';
                        return importMethod($meta.method)({
                            username: r.username,
                            registerPassword: r.registerPassword,
                            hash: hash
                        });
                    })
                    .then(function() {
                        r.password = hash.value;
                        delete r.registerPassword;
                        delete r.newPassword;
                        return r;
                    });
                });
            } else if (msg.hasOwnProperty('forgottenPassword')) {
                get = Promise.all([
                    get,
                    new Promise(function(resolve, reject) {
                        return importMethod('core.throttle.perform')({
                            name: 'identity.check',
                            instance: `${msg.username}forgottenPassword`
                        }).then(function(res) {
                            resolve(true);
                        }).catch(function(err) {
                            reject(errors['identity.throttleErrorForgotten'](err));
                        });
                    })])
                    .then(function(r) {
                        passwordCredentaislGetStoreProcedureParams = helpers.buildPasswordCredentaislGetStoreProcedureParams(msg);
                        return helpers.validateNewPasswordAgainstAccessPolicy(rawNewPassword, passwordCredentaislGetStoreProcedureParams, $meta, msg.actorId)
                    .then(function() {
                        $meta.method = 'user.identity.forgottenPasswordChange';
                        return importMethod($meta.method)(r[0]).then(function() {
                            var resultToReturn = Object.assign({}, r[0]);
                            resultToReturn.password = r[0].newPassword;
                            delete resultToReturn.forgottenPassword;
                            delete resultToReturn.newPassword;
                            return resultToReturn;
                        });
                    });
                    });
            } else { // Case: change password when password is expired
                get = Promise.all([get])
                .then(function() {
                    var okReturn = arguments[0][0];
                    passwordCredentaislGetStoreProcedureParams = helpers.buildPasswordCredentaislGetStoreProcedureParams(msg);
                    return helpers.validateNewPasswordAgainstAccessPolicy(rawNewPassword, passwordCredentaislGetStoreProcedureParams, $meta, msg.actorId)
                    .then(function() {
                        return okReturn;
                    });
                });
            }
        }
        return get
            .then(function(r) {
                $meta.method = checkMethod || 'user.identity.checkPolicy';
                return importMethod($meta.method)(r, $meta)
                    .then(function(user) {
                        if ((!user.loginPolicy || !user.loginPolicy.length) && !user['permission.get']) { // in case user.identity.check did not return the permissions
                            $meta.method = 'permission.get';
                            return importMethod($meta.method)({actionId: msg.actionId},
                                {actorId: user['identity.check'].userId, actionId: 'identity.check'})
                                .then((permissions) => {
                                    user['permission.get'] = permissions && permissions[0];
                                    return user;
                                });
                        }
                        return user;
                    });
            }).then(function(response) {
                if (creatingSession && response.roles.some((role) => role.name === 'BaobabClientApplication')) {
                    return importMethod('customer.activityReport.add')({
                        activity: {
                            installationId: msg.username,
                            action: 'identity.login',
                            actionStatus: 'success',
                            operationDate: (new Date()).toISOString(),
                            channel: 'online'
                        }
                    }, {
                        auth: {
                            actorId: response['identity.check'].actorId
                        }
                    }).then(() => response);
                }

                // Parse mobile offline Access policy response
                if (response['loginFactors.offline']) {
                    response = helpers.parseMobileOfflineResponse(response);
                }
                return response;
            })
            .catch(helpers.handleError);
    },
    closeSession: function(msg, $meta) {
        $meta.method = 'user.session.delete';
        return importMethod($meta.method)({sessionId: $meta.auth.sessionId}, $meta);
    },
    changePassword: function(msg, $meta) {
        $meta.method = 'user.identity.get';
        return importMethod($meta.method)({
            userId: $meta.auth.actorId,
            type: 'password'
        }, $meta)
            .then((r) => {
                var passwordCredentaislGetStoreProcedureParams = {
                    username: msg.username,
                    type: 'password',
                    password: msg.password,
                    requiresPassHash: true,
                    hashParams: r.hashParams[0]
                };

                msg.hashParams = r.hashParams[0];
                return helpers.validateNewPasswordAgainstAccessPolicy(msg.newPassword, passwordCredentaislGetStoreProcedureParams, $meta);
            })
            .then(() => {
                $meta.method = 'user.changePassword';
                return importMethod($meta.method)(msg, $meta);
            })
            .catch(helpers.handleError);
    },
    forgottenPasswordRequest: function(msg, $meta) {
        // Use or to enum all possible channels here
        if (msg.channel !== 'sms' && msg.channel !== 'email') {
            throw errors['identity.notFound']();
        }
        $meta.method = 'user.identity.get';
        return importMethod($meta.method)({
            username: msg.username,
            type: 'password'
        }).then(function(hash) {
            if (!hash || !Array.isArray(hash.hashParams) || hash.hashParams.length < 1 || !hash.hashParams[0] || !hash.hashParams[0].actorId) {
                throw errors['identity.notFound']();
            }
            var actorId = hash.hashParams[0].actorId;
            $meta.method = 'user.sendNotification';
            return importMethod($meta.method)({
                channel: msg.channel,
                type: 'forgottenPassword',
                template: 'user.forgottenPassword.otp',
                actorId: actorId
            }).then(function(result) {
                return {
                    sent: true
                };
            });
        }).catch(function(err) {
            if (err.type === 'core.throttle') {
                throw errors['identity.throttleErrorForgotten'](err);
            }
            helpers.handleError(err);
        });
    },
    forgottenPasswordValidate: function(msg, $meta) {
        $meta.method = 'user.identity.get';
        return importMethod($meta.method)({
            username: msg.username,
            type: 'forgottenPassword'
        }, $meta).then(function(response) {
            var hashParams;
            response.hashParams.some(function(h) {
                if (h.type === 'forgottenPassword') {
                    hashParams = h;
                    return true;
                }
                return false;
            });
            if (!hashParams) {
                throw errors['identity.notFound']();
            }
            return helpers.getHash('forgottenPassword', msg.forgottenPassword, hashParams);
        }).then(function(forgottenPassword) {
            msg.forgottenPassword = forgottenPassword;
            $meta.method = 'user.identity.forgottenPasswordValidate';
            return importMethod($meta.method)(msg, $meta);
        }).catch(helpers.handleError);
    },
    forgottenPassword: function(msg, $meta) {
        $meta.method = 'user.identity.get';
        var hashType = function(key, type, ErrorWhenNotFound) {
            return importMethod($meta.method)({
                username: msg.username,
                type: type
            }, $meta).then(function(response) {
                var hashParams;
                response.hashParams.some(function(h) {
                    if (h.type === type) {
                        hashParams = h;
                        return true;
                    }
                    return false;
                });
                if (!hashParams) {
                    if (ErrorWhenNotFound) {
                        throw new ErrorWhenNotFound();
                    } else {
                        return null;
                    }
                }
                var rr = msg[key] ? helpers.getHash(type, msg[key], hashParams) : null;
                return rr;
            });
        };
        return Promise.all([
            hashType('forgottenPassword', 'forgottenPassword', errors['identity.notFound']()),
            hashType('newPassword', 'password', null)
        ]).then(function(p) {
            msg.forgottenPassword = p[0];
            msg.newPassword = p[1];
            $meta.method = 'user.identity.forgottenPasswordChange';
            return importMethod($meta.method)(msg, $meta);
        }).catch(helpers.handleError);
    }
};
