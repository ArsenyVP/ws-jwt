const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const WebSocket = require('ws');
const http = require('http');
const jwt = require('jsonwebtoken');
const config = require('./app/config/auth.config');

const db = require('./app/models');
const Role = db.role;
const User = db.user;

const port = process.env.PORT || 8000;
const app = express()
const server = http.createServer(app);

app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const wss = new WebSocket.Server({
    server: server, 
    // verifyClient: function (info, cb) {
    //     let token = info.req.headers["x-access-token"]
    //     if (!token) {
    //         cb(false, 401, 'Unauthorized')
    //     }

    //     // const userId = decoded.id;


    //     jwt.verify(token, config.secret, function (err, decoded) {
    //         if (err) {
    //             cb(false, 401, 'Unauthorized')
    //         } else {
    //             info.req.user = decoded;
    //             const id = decoded.id;
    //             User.findById(id, (err, user) => {
    //                 if (err) {
    //                     cd.status(500).send({ message: err })
    //                     return;
    //                 }

    //                 if (!user) {
    //                     cd.status(500).send({ message: 'User not found by ID' })
    //                 }

    //                 cb(true);
    //             })
    //         }
    //     })


    // }
});

wss.on('connection', function connection(ws) {
    ws.on('message', function incoming(data) {
        wss.clients.forEach(function each(client) {
            if (client !== ws && client.readyState === WebSocket.OPEN) {
                client.send(JSON.parse(data));
            }
        })
    })
})

db.mongoose
    .connect(`mongodb+srv://vp:12345@cluster0.nhqdc.mongodb.net/myFirstDatabase?retryWrites=true&w=majority`, {
        useNewUrlParser: true,
        useUnifiedTopology: false
    })
    .then(() => {
        console.log('MongoDB has connected successfully')
        initial()
    })
    .catch((error) => {
        console.error('Connection error ', error);
        process.exit();
    })

function initial() {
    Role.estimatedDocumentCount((err, count) => {
        if (!err && count === 0) {
            new Role({
                name: "user"
            }).save(err => {
                if (err) {
                    console.log("error", err);
                }

                console.log("added 'user' to roles collection");
            });

            new Role({
                name: "admin"
            }).save(err => {
                if (err) {
                    console.log("error", err);
                }

                console.log("added 'admin' to roles collection");
            });
        }
    });
}

app.get('/', (req, res) => {
    res.json('Hello World')
})

require('./app/routes/auth.routes')(app)
require('./app/routes/user.routes')(app)

server.listen(port, () => {
    console.log(`Server is running on the port ${port}`)
})
