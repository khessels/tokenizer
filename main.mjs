// https://listings.pcisecuritystandards.org/pdfs/pci_fs_data_storage.pdf
// https://www.pcidssguide.com/how-can-you-make-unreadable-stored-pan-information/
// https://docs-prv.pcisecuritystandards.org/PCI%20DSS/Standard/PCI-DSS-v4_0.pdf
// https://github.com/lidonghao1116/sweet.security.rsa/blob/master/nodejs/security/rsa/keyWorker.js#L19

import express from 'express';
// import https from'https';
import http from'http';
import fs from 'fs'
import crypto from 'crypto'
import sqlite3 from 'sqlite3'
import { v1 as uuidv1 } from 'uuid';
import yaml from 'yaml'
import jwt from 'jsonwebtoken'

let configPath = 'config.yml'
let deployMode = 'development'
let dbLocation = '.dbs';


process.argv.forEach(function (val, index, array) {
    let exploded = val.split(('='))
    switch(exploded[0].toLowerCase()){
        case '--config':
            configPath  = exploded[1];
            break;
        case '--deploy-mode':
            deployMode = exploded[1];
            break;
        case '--db-location':
            dbLocation = exploded[1];
            break;

    }
});

let secret = fs.readFileSync('secrets/' + deployMode + '/tokenizer_jwt', 'utf8')
function chunkString(str, length) {
    return str.match(new RegExp('.{1,' + length + '}', 'g'));
}

function _base64encode(input){
    let buffer = new Buffer(input);
    return buffer.toString('base64');
}
function _base64decode(input){
    let buffer = new Buffer(input,'base64');
    return buffer.toString();
}
function _get_MAX_ENCRYPT_BLOCK(){
    return 2048 / 8 - 11;
}
function _get_MAX_DECRYPT_BLOCK(){
    return 2048 / 8;
}

const _config = fs.readFileSync(configPath, 'utf8')
let config = yaml.parse(_config)

// override variables specified in config
process.argv.forEach(function (val, index, array) {
    let exploded = val.split(('='))
    switch(exploded[0].toLowerCase()){
        case '--http_port':
            config.http.port = parseInt(exploded[1]);
            break;
        case '--https_port':
            config.https.port = exploded[1];
            break;
        case '--prepend':
            config.app.path.prepend = exploded[1];
            break;
    }
});

let dir = dbLocation + '/';
if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, 744);
    if (!fs.existsSync(dir)){
        console.error("Unable to create directory for database.")
        process.exit(-1)
    }
}

const HttpsCredentials = {
    key: fs.readFileSync( 'secrets/' + deployMode + '/ssl_private.pem', 'utf8'),
    cert: fs.readFileSync( 'secrets/' + deployMode + '/ssl_public.pem', 'utf8')
};


function generateAccessToken(username) {
    return jwt.sign(username, secret, { expiresIn: '120s' });
}

const app = express()
app.use(express.json());

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]

    if (token == null) return res.status(401).send("No token").end()

    jwt.verify(token, secret, (err, user) => {
        if (err) {
            return res.status(403).send("Invalid credentials").end()
        }else{
            req.user = user
            next()
        }
    })
}
function userEnabled(req, res, next){
    if(typeof req.user.enabled !== 'undefined'){
        if(req.user.enabled === true){
            next()
        }else{
            return res.send(JSON.stringify(req.user)).status(422).end()
        }
    }else{
        return res.send(JSON.stringify(req.user)).status(422).end()
    }
}
function admin(req, res, next){
    if(typeof req.user.admin !== 'undefined'){
        if(req.user.admin === true){
            next()
        }else{
            return res.status(422).send("admin only functionality").end()
        }
    }else{
        return res.status(422).send("admin only functionality").end()
    }
}

app.post('/authenticate', (req, res) => {
    console.log(req.body);
    let users = undefined;
    let user = undefined;
    let json = fs.readFileSync('secrets/' + deployMode + '/' + req.body.brand_id + '/users/users.json');
    users = JSON.parse(json)
    console.log(users)
    for(let x = 0; x < users.users.length; x++){
        console.log(x)
        if(users.users[x].username === req.body.email){
            console.log("Found name")
            if(users.users[x].password === req.body.password){
                console.log("Found user")
                user = users.users[x];
            }
        }
    }
    if(typeof user !== 'undefined') {
        const token = generateAccessToken({username: req.body.username, brand_id: req.body.brand_id, admin:user.admin, enabled:user.enabled });
        res.send(token).end();
    }else{
        res.send("Access denied").end();
    }
});

app.post('/', [authenticateToken, userEnabled], (req, res) => {
    if(typeof req.body === 'undefined'){
        res.status(400).send( 'A body is required').end();
    }
    let path =  dbLocation + '/' + req.user.brand_id + '.db';
    const db = new sqlite3.Database(path);
    let data = req.body.data;
    let encrypted = encrypt(data, req.user.brand_id);
    db.run(`CREATE TABLE IF NOT EXISTS tokens(uuid NVARCHAR(40) PRIMARY KEY, data TEXT NOT NULL)`, function(err){
        if(err){
            res.status(500).send(err.message).end();
        }else{
            let uuid = uuidv1();
            db.run("INSERT INTO tokens (uuid, data) VALUES(?,?)" ,
                [uuid, encrypted],
                function(error){
                    if(error) {
                        res.status(500).send(error.message).end();
                    }else{
                        res.send(uuid).end();
                    }
                }
            );
        }
    });
})
app.get('/:token', [authenticateToken, userEnabled], (req, res) => {
    let path =  dbLocation + '/' + req.user.brand_id + '.db';
    const db = new sqlite3.Database(path);
    db.get("SELECT * FROM tokens WHERE uuid=? LIMIT 1",
        [req.params.token],
        function(err, row) {
            if(!err){
                if(row){
                    let decrypted = decrypt(row.data, req.user.brand_id);
                    res.send(decrypted).end();
                }else{
                    res.status(204).end()
                }
            }else{
                res.status(500).send(err.message).end();
            }
        });
});
app.delete('/:token', [authenticateToken, userEnabled], (req, res) => {
    let path =  dbLocation + '/' + req.user.brand_id + '.db';
    const db = new sqlite3.Database(path);

    db.get("DELETE FROM tokens WHERE uuid=?",
        [req.params.token],
        function(err, row) {
            if(!err){
                res.send('OK').end();
            }else{
                res.status(500).send(err.message).end();
            }
        });
});
export function encrypt (plainText, brand_id, admin = false) {
    let result = '';
    let base64Text = Buffer.from(plainText).toString('base64')
    let chunkedBase64 = chunkString(base64Text, 214);

    for(let x = 0; x < chunkedBase64.length; x++){
        let encrypted = crypto.publicEncrypt({
                key: fs.readFileSync('secrets/' + deployMode + '/' + brand_id + '/keys/db_public', 'utf8'),
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: 'sha256'
            },
            Buffer.from(chunkedBase64[x])
        )
        if(result.length === 0){
            result = Buffer.from(encrypted).toString('base64');
        }else{
            result += ',' + Buffer.from(encrypted).toString('base64');
        }
    }
    return result;
}
export function decrypt (data, brand_id) {
    let result = '';

    let chunks = data.split(',')
    for(let x = 0; x < chunks.length; x++){
        let decrypted = crypto.privateDecrypt(
            {
                key: fs.readFileSync('secrets/' + deployMode + + '/' + brand_id + '/keys/db_private', 'utf8'),
                // In order to decrypt the data, we need to specify the
                // same hashing function and padding scheme that we used to
                // encrypt the data in the previous step
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: 'sha256'
            }, Buffer.from(chunks[x].trim(), 'base64'))
        result += decrypted;
    }
    result = Buffer.from(result, 'base64').toString('ascii');
    return result;
}

if(config.http.enabled) {
    let httpServer = http.createServer(app);
    httpServer.listen(config.http.port, () => {
        console.log(`Http server listening on port ${config.http.port}`)
    });
}

if(config.https.enabled) {
    let httpsServer = http.createServer(HttpsCredentials, app);
    httpsServer.listen(config.https.port, () =>{
        console.log(`Https server listening on port ${config.https.port}`)
    });
}