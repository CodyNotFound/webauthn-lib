# webauthn-lib
An easy way to use webauthn in your website

## Usage
1. Install the module
```bash
yarn add webauthn-lib
```

2. Import the module
```
const webauthn = require('webauthn-lib')
```

3. Import `front.js` at the front end
```html
<script src="front.js"></script>
```

### Registration (Backend)
> Generate a makeCredential request
```js
const webauthn = require('webauthn-lib');

let username = 'CodyNotFound';
let displayname = 'Cody';
let id = webauthn.randomBase64URLBuffer();
let request = webauthn.generateServerMakeCredRequest(username, displayname, id);

console.log(request);
```

### Authentication (Backend)
> Generate a makeCredential request
```js
const webauthn = require('webauthn-lib');

// Some code here to get user's authenticators
let username = 'CodyNotFound';
let authenticators = database[username].authenticators;
let request = webauthn.generateServerGetAssertion(authenticators);

console.log(request);
```

### Validation (Backend)
> Verify the response
```js
const webauthn = require('webauthn-lib');

// Some code here to get user's response and authenticators
let response;
let username = 'CodyNotFound';
let authenticators = database[username].authenticators;

// Session should contains the challengeID and username
let session;

let result;
if (response.response.attestationObject !== undefined) {
    // Register
    result = utils.verifyAuthenticatorAttestationResponse(response);
    if (result.verified) {
        // Register success
        // You can do something here
        authenticators.push(response.authrInfo);
    }
} else if (webauthnResp.response.authenticatorData !== undefined) {
    // Authenticate
    result = utils.verifyAuthenticatorAssertionResponse(webauthnResp, authenticators);
    if (result.verified) {
        // Authenticate success
        // You can do something here
        session.login = true;
    }
}
```

# GetResponse (Frontend)
> You should do it after getting the request from the server
```html
<script src="front.js"></script>
<script>
    // When login
    // data is the request from server
    let data;
    let publicKey = preformatGetAssertReq(data);
    navigator.credentials.get({ publicKey }).then((data) => {
        let response = publicKeyCredentialToJSON(data);
        // Send the response to server
    });

    // When Register
    let data;
    let publicKey = preformatMakeCredReq(data);
    navigator.credentials.get({ publicKey }).then((data) => {
        let response = publicKeyCredentialToJSON(data);
        // Send the response to server
    });
</script>
```

> **See more at the demo app**

## Demo App
```bash
git clone https://github.com/CodyNotFound/webauthn-lib
cd webauthn-lib
yarn
cd example
node index.js
```
Then you can see the demo app at [http://localhost:4000](http://localhost:4000)

## Other
This module is edited from [webauthn-demo](https://github.com/fido-alliance/webauthn-demo)
