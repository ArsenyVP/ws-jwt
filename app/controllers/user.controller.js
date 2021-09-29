const db = require('../models');
const User = db.user;
const jwt = require("jsonwebtoken");
const config = require("../config/auth.config");
const bcrypt = require('bcryptjs');

exports.allAccess = (req, res) => {
    res.status(200).send("Public Content.");
};

exports.userBoard = (req, res) => {
    res.status(200).send("User Content.");
};

exports.adminBoard = (req, res) => {
    res.status(200).send("Admin Content.");
};

exports.getUsersAll = (req, res) => {
    User.find({}, (err, users) => {
        if (err) {
            res.status(500).send({ message: err })
            return;
        }

        res.send(users)
    })
}

exports.getUserById = (req, res) => {
    const id = req.params.id;

    User.findById(id, (err, user) => {
        if (err) {
            res.status(500).send({ message: err })
            return;
        }

        if (!user) {
            res.status(500).send({ message: 'User not found by ID' })
        }

        res.send(user)
    })
}

exports.deleteUserById = (req, res) => {
    const id = req.params.id;

    User.findByIdAndDelete(id, (err, user) => {
        if (err) {
            res.status(500).send({ message: err })
            return;
        }

        if (!user) {
            res.status(500).send({ message: `User Not found` })
            return
        }

        res.send(user);
    })
}

exports.updateUserById = (req, res) => {
    const id = req.params.id;

    let token = req.headers["x-access-token"];

    if (!token) {
        return res.status(403).send({ message: "No token provided!" });
    }

    jwt.verify(token, config.secret, (err, decoded) => {
        if (err) {
            return res.status(401).send({ message: "Unauthorized!" });
        }
        req.userId = decoded.id;

        const body = {
            username: req.body.username,
            email: req.body.email,
        }

        if (id === decoded.id) {
            User.findByIdAndUpdate(id, body,
                (err, user) => {
                    if (err) {
                        res.status(500).send({ message: err })
                    }

                    if (!user) {
                        res.status(500).send({ message: `User Not found` })
                        return
                    }

                    User.findById(id, (err, user) => {
                        if (err) {
                            res.status(500).send({ message: err })
                            return;
                        }

                        if (!user) {
                            res.status(500).send({ message: 'User not found by ID' })
                        }

                        res.send(user)
                    })
                })
        }
    });
}