const config = require('./../config/auth.config');
const db = require('./../models');
const jwt_decode = require('jwt-decode');
const { body, validationResult } = require('express-validator');
const User = db.user;
const Role = db.role;

const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

exports.signup = (req, res) => {
  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    return res.status(400).json({ error: errors.array() })
  }

  if (req.body.password <= 5) {
    return res.status(404).json({ error: "Password must be minimum 6 symbols" })
  }

  const user = new User({
    username: req.body.username,
    email: req.body.email,
    password: bcrypt.hashSync(req.body.password, 8)
  });

  user.save((err, user) => {
    if (err) {
      res.status(500).send({ message: err });
      return;
    }

    if (req.body.roles) {
      Role.find(
        {
          name: { $in: req.body.roles }
        },
        (err, roles) => {
          if (err) {
            res.status(500).send({ message: err });
            return;
          }

          user.roles = roles.map(role => role._id);
          user.save(err => {
            if (err) {
              res.status(500).send({ message: err });
              return;
            }
            res.send({ message: "User was registered successfully!" });
          })
        }
      )
    } else {
      const roles = ["user"];

      Role.find(
        {
          name: { $in: roles },
        },
        (err, roles) => {
          if (err) {
            res.status(500).send({ message: err });
            return;
          }

          user.roles = roles.map(role => role._id);
          user.save(err => {
            if (err) {
              res.status(500).send({ message: err });
              return;
            }
            res.send({ message: "User was registered successfully!" });
          })
        }
      )
    }
  })
}

exports.updatePassword = (req, res) => {
  let token = req.headers["x-access-token"];
  debugger;
  if (!token) {
    return res.status(403).send({ message: "No token provided!" });
  }

  jwt.verify(token, config.secret, (err, decoded) => {
    if (err) {
      return res.status(401).send({ message: "Unauthorized!" });
    }

    const userId = decoded.id;

    if (userId) {
      User.findById(userId, (err, user) => {
        if (err) {
          res.status(200).send({ message: "User not found" })
          return;
        }

        if (!user) {
          res.status(401).send({ message: 'User not found by ID' })
        }

        var passwordIsValid = bcrypt.compareSync(
          req.body.current_password,
          user.password
        );

        if (!passwordIsValid) {
          return res.status(401).send({
            message: "Invalid Password"
          });
        }

        if (req.body.new_password.length <= 5) {
          return res.status(401).send({ message: "Password must be minimum 6 symbols" })
        }

        if (req.body.new_password.length >= 5) {
          const body = {
            password: bcrypt.hashSync(req.body.new_password, 8)
          }

          User.findByIdAndUpdate(userId, body, (err, user) => {
            if (err) {
              res.status(401).send({ message: "Invalid Password" })
            }
            return res.status(200).send(user);
          })
        }
      })
    }
  });
}

exports.signin = (req, res) => {
  User.findOne({
    username: req.body.username
  })
    .populate("roles", "-__V")
    .exec((err, user) => {
      if (err) {
        res.status(500).send({ message: err });
        return;
      }

      if (!user) {
        return res.status(404).send({ message: "Invalid Username or Password" });
      }

      var passwordIsValid = bcrypt.compareSync(
        req.body.password,
        user.password
      );

      if (!passwordIsValid) {
        return res.status(401).send({
          accessToken: null,
          message: "Invalid Username or Password"
        });
      }

      var token = jwt.sign({ id: user.id }, config.secret, {
        expiresIn: 86400 // 24 hours
      });

      var authorities = [];

      for (let i = 0; i < user.roles.length; i++) {
        authorities.push("ROLE_" + user.roles[i].name.toUpperCase());
      }
      res.status(200).send({
        id: user._id,
        username: user.username,
        email: user.email,
        roles: authorities,
        accessToken: token
      });
    });
};
