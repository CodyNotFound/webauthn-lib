const express = require('express');
const base64url = require('base64url');
const bodyParser = require('body-parser');
const cookieSession = require('cookie-session');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');

const app = express();
const webauthn = require('../index');
const db = require('./database');

app.use(bodyParser.urlencoded({ extended: false }))
app.use(bodyParser.json());
app.use(cookieSession({
    name: 'session',
    keys: [crypto.randomBytes(32).toString('hex')],
    maxAge: 24 * 60 * 60 * 1000
}))

app.use(cookieParser())
app.use(express.static('static'));
app.use('/front.js', express.static('../front.js'));

app.post('/register', (req, res) => {
    let username = req.body.username;
    let displayname = req.body.displayname;
    if (!username || !displayname) {
        res.json({
            status: 'error',
            info: 'Missing username or displayname'
        });
        return;
    }

    if (db[username] && db[username].authenticator) {
        res.json({
            status: 'error',
            info: 'Username already exists'
        });
        return;
    }

    let id = webauthn.randomBase64URLBuffer();
    db[username] = {
        id,
        username,
        displayname,
        authenticators: [],
    }

    let makeCredential = webauthn.generateServerMakeCredRequest(username, displayname, id);

    req.session.challenge = makeCredential.challenge;
    req.session.username = username;
    res.json(makeCredential);

});

app.post('/login', (req, res) => {
    let username = req.body.username;
    if (!username) {
        res.json({
            status: 'error',
            info: 'Missing username'
        })
        return;
    }

    if (!db[username] || !db[username].authenticators) {
        response.json({
            'status': 'error',
            'info': `User does not exist!`
        })
        return
    }

    let getAssertion = webauthn.generateServerGetAssertion(db[username].authenticators)
    getAssertion.status = 'success'

    req.session.challenge = getAssertion.challenge;
    req.session.username = username;

    res.json(getAssertion)
})

app.post('/response', (req, res) => {
    req.body = JSON.parse(req.body.data);
    if (!req.body ||
        !req.body.id ||
        !req.body.rawId ||
        !req.body.response ||
        !req.body.type ||
        req.body.type !== 'public-key') {
        res.json({
            'status': 'error',
            'info': 'Response missing'
        })
        return
    }

    let webauthnResp = req.body
    let clientData = JSON.parse(base64url.decode(webauthnResp.response.clientDataJSON));
    if (clientData.challenge !== req.session.challenge) {
        res.json({
            'status': 'error',
            'info': 'Challenges do not match'
        })
        return
    }

    if (clientData.origin !== "http://localhost:4000") {
        res.json({
            'status': 'error',
            'info': 'Origins do not match'
        })
        return
    }

    let result;
    if (webauthnResp.response.attestationObject !== undefined) {
        result = webauthn.verifyAuthenticatorAttestationResponse(webauthnResp);
        if (result.verified) {
            db[req.session.username].authenticators.push(result.authrInfo);
        }
    } else if (webauthnResp.response.authenticatorData !== undefined) {
        result = webauthn.verifyAuthenticatorAssertionResponse(webauthnResp, db[req.session.username].authenticators);
    } else {
        res.json({
            'status': 'failed',
            'info': 'Can not determine type of response!'
        })
        return;
    }

    if (result.verified) {
        req.session.loggedIn = true;
        res.json({ 'status': 'success' })

    } else {
        res.json({
            'status': 'error',
            'info': 'Can not authenticate signature!'
        })
    }
})

app.listen(4000);
console.log('Server started on http://localhost:4000');
