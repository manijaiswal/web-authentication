const express = require('express');
const crypto = require('crypto');

const { 
    generateRegistrationOptions, 
    verifyRegistrationResponse,
    generateAuthenticationOptions,
    verifyAuthenticationResponse
} = require('@simplewebauthn/server')

const app = express();

if (!globalThis.crypto) {
    globalThis.crypto = crypto;
}

if (typeof globalThis.crypto.getRandomValues !== 'function') {
    console.log('ssswdff')
    globalThis.crypto.getRandomValues = getRandomValues
}

if (typeof global.crypto !== 'object') {
    global.crypto = crypto
  }
  
  if (typeof global.crypto.getRandomValues !== 'function') {
    global.crypto.getRandomValues = getRandomValues
  }

function getRandomValues(array) {
    return crypto.webcrypto.getRandomValues(array)
}

app.use(express.static('./public'));

app.use(express.json());

let userStore = {};
let userChallenge = {};


app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    // if (userStore[]) {
    //     return res.status(400).send({
    //         message: "user already register"
    //     })
    // }
    const id = `user_${Date.now()}`;

    const user = {
        username: username,
        password: password,
        id
    }
    userStore[id] = user;
    console.log(userStore);
    res.status(201).json({
        message: 'user registered',
        data: id
    })

});

app.post('/register-options', async (req, res) => {
    const { userId } = req.body;

    if (!userStore[userId]) {
        return res.status(400).send({
            message: "user not exists"
        })
    }
    const user = userStore[userId];
    const registorOptions = await generateRegistrationOptions({
        rpID: 'localhost',
        userName: user.username,
        rpName: 'Simple web authn example',
        attestationType: 'none',
        timeout: 30000
    })
    console.log('Register option', registorOptions);
    const challenge = registorOptions.challenge;
    userChallenge[userId] = challenge;
    return res.status(200).json({
        regOpts: registorOptions
    })
})

app.post('/verify-register', async (req, res) => {
    const { attResp, userId } = req.body;

    const challenge = userChallenge[userId];

    let verification;

    try {
        verification = await verifyRegistrationResponse({
            response: attResp,
            expectedChallenge: challenge,
            expectedOrigin: 'http://localhost:3000',
            expectedRPID: 'localhost'
        })
    } catch (error) {
        console.log('Error', error);
        return res.status(400).json({ error: error });
    }
    console.log('verification', verification);
    // store the pass key
    userStore[userId].passkey = verification.registrationInfo;
    return res.status(200).json({ verification });
})


app.post('/login-options', async(req, res)=> {

    console.log(JSON.stringify(req.body));
    const {userId} = req.body

    console.log(userStore[userId]);

    if (!userStore[userId]) {
        return res.status(400).send({
            message: "user not exists"
        })
    }

    const user = userStore[userId];

    const authOpts = await generateAuthenticationOptions({
        rpID: 'localhost'
    })

    userChallenge[userId] = authOpts.challenge;

    return res.status(200).json({
        options: authOpts
    })
})


app.post('/login-verify', async(req, res)=> {
    const {userId, creds} = req.body;
    if (!userStore[userId]) {
        return res.status(400).send({
            message: "user not exists"
        })
    }
    const user = userStore[userId];
    const userChallengeId = userChallenge[userId];
    console.log('User challenge', userChallengeId);

    let verification;

    try {
        verification = await verifyAuthenticationResponse({
            response: creds,
            expectedChallenge: userChallengeId,
            expectedOrigin: 'http://localhost:3000',
            expectedRPID: 'localhost',
            authenticator: user.passkey

        })
    } catch (error) {
        console.error(`Inside verify login`, error);
        return res.status(400).send({ error: error.message });
    }

    console.log(`Verification`, verification);
    
    return res.status(200).json({
        verification
    })
})




app.listen(3000, () => {
    console.log(`server is running on 3000`);
})
