var path = require('path');
var errors = require('./errors');
var crypto = require('crypto');
var when = require('when');

function getHash(password, hashInfo) {
    if (!hashInfo || !hashInfo.params) {
        return false;
    }
    hashInfo.params = JSON.parse(hashInfo.params);
    return when.promise(function(resolve) {
        switch (hashInfo.algorithm) {
            case 'pbkdf2':
                crypto.pbkdf2(password, hashInfo.params.salt, hashInfo.params.iterations, hashInfo.params.keylen, hashInfo.params.digest, (err, key) => {
                    if (err) {
                        throw errors.crypt(err);
                    }
                    resolve(key.toString('hex'));
                });
                break;
        }
    });
}

module.exports = {
    schema: [
        {path: path.join(__dirname, 'schema'), linkSP: true}
    ],
    'check.request.send': function(msg, $meta) {
        msg.type = '';
        if (typeof (msg.username) !== 'undefined' && typeof (msg.password) !== 'undefined') {
            msg.type = 'user/pass';
        } else if (typeof (msg.fingerPrint) !== 'undefined') {
            msg.type = 'bio';
        } else if (typeof (msg.token) !== 'undefined') { // session
            msg.type = 'session';
        } else {
            throw errors.nothingForValidation({method: 'identity.check'});
        }

        return this.config['identity.getHashParams'](msg, $meta)
        .then(function(res) {
            if (res[0].length > 1) {
                throw errors.multipleResults({method: 'identity.getHashParams'});
            }

            return getHash(msg.password, res[0][0]);
        })
        .then(function(res) {
            msg.password = res;
            return msg;
        });
    }
};
