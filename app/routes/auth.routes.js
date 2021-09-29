const { verifySignUp } = require("../middlewares");
const controller = require('./../controllers/auth.controller');
const {body } = require('express-validator')

module.exports = (app) => {
    app.use((req, res, next) => {
        res.header(
            "Access-Control-Allow-Headers",
            "x-access-token, Origin, Content-Type, Accept"
        );
        next()
    })

    app.post(
        "/api/auth/signup",
        body('username').isLength({ min: 2 }),
        body('password').isLength({ min: 5 }),
        [
            verifySignUp.checkDuplicateUsernameOrEmail,
            verifySignUp.checkRolesExisted
        ],
        controller.signup
    )

    app.post("/api/auth/signin", controller.signin);

    app.post('/api/auth/reset-password', controller.updatePassword);
}
