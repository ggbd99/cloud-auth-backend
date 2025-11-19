const http = require('http');

const post = (path, data) => {
    return new Promise((resolve, reject) => {
        const options = {
            hostname: 'localhost',
            port: 3000,
            path: '/api/auth' + path,
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': data.length
            }
        };

        const req = http.request(options, (res) => {
            let body = '';
            res.on('data', (chunk) => body += chunk);
            res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(body) }));
        });

        req.on('error', (e) => reject(e));
        req.write(data);
        req.end();
    });
};

const fs = require('fs');
const logFile = 'verify_log.txt';

const log = (msg) => {
    fs.appendFileSync(logFile, msg + '\n');
    console.log(msg);
};

const runTests = async () => {
    try {
        log('--- Test 1: Register ---');
        const regData = JSON.stringify({ email: 'test3@example.com', password: 'password123', device_hash: 'device1' });
        const regRes = await post('/register', regData);
        log('Status: ' + regRes.status);
        log('Body: ' + JSON.stringify(regRes.body));

        log('\n--- Test 2: Login Success (Correct Device) ---');
        const loginData = JSON.stringify({ email: 'test3@example.com', password: 'password123', device_hash: 'device1' });
        const loginRes = await post('/login', loginData);
        log('Status: ' + loginRes.status);
        log('Body: ' + (loginRes.body.accessToken ? 'Token Received' : JSON.stringify(loginRes.body)));

        log('\n--- Test 3: Login Fail (Wrong Device) ---');
        const failData = JSON.stringify({ email: 'test3@example.com', password: 'password123', device_hash: 'device2' });
        const failRes = await post('/login', failData);
        log('Status: ' + failRes.status);
        log('Body: ' + JSON.stringify(failRes.body));

    } catch (err) {
        log('Test Error: ' + err.message);
    }
};

runTests();
