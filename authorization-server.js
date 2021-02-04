const fs = require("fs")
const express = require("express")
const bodyParser = require("body-parser")
const jwt = require("jsonwebtoken")
const {
    randomString,
    containsAll,
    decodeAuthCredentials,
    timeout,
} = require("./utils")

const config = {
    port: 9001,
    privateKey: fs.readFileSync("assets/private_key.pem"),

    clientId: "my-client",
    clientSecret: "zETqHgl0d7ThysUqPnaFuLOmG1E=",
    redirectUri: "http://localhost:9000/callback",

    authorizationEndpoint: "http://localhost:9001/authorize",
}

const clients = {
    "my-client": {
        name: "Sample Client",
        clientSecret: "zETqHgl0d7ThysUqPnaFuLOmG1E=",
        scopes: ["permission:name", "permission:date_of_birth"],
    },
    "test-client": {
        name: "Test Client",
        clientSecret: "TestSecret",
        scopes: ["permission:name"],
    },
}

const users = {
    user1: "password1",
    john: "appleseed",
}

const requests = {}
const authorizationCodes = {}

let state = ""

const app = express()
app.set("view engine", "ejs")
app.set("views", "assets/authorization-server")
app.use(timeout)
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({extended: true}))

/*
Your code here
*/
function authorized(req, res, client, scope) {
    const requestId = randomString();
    requests[requestId] = req.query;
    const params = {
        requestId: requestId,
        client: client,
        scope: scope,
    };
    res.render("login", params);
}

app.get('/authorize', (req, res) => {
    const client = clients[req.query.client_id];
    const scope = req.query.scope;
    client && scope && containsAll(client.scopes, scope.split(" "))
        ? authorized(req, res, client, scope)
        : res.status(401).end();
})

app.post('/approve', (req, res) => {
    const {userName, password, requestID} = req.body;
    const isUserValid = users[userName] === password;
    isUserValid
        ? res.end()
        : res.status(401).end();
});

const server = app.listen(config.port, "localhost", function () {
    var host = server.address().address
    var port = server.address().port
})

// for testing purposes

module.exports = {app, requests, authorizationCodes, server}
