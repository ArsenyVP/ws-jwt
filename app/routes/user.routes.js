const { authJwt, verifySignUp } = require("./../middlewares");
const controller = require("./../controllers/user.controller");

module.exports = function (app) {
    app.use(function (req, res, next) {
        res.header(
            "Access-Control-Allow-Headers",
            "x-access-token, Origin, Content-Type, Accept"
        );
        next();
    });

    app.get("/api/test/all", controller.allAccess);

    app.get("/api/test/user", [authJwt.verifyToken], controller.userBoard);

    app.get(
        "/api/test/admin",
        [authJwt.verifyToken, authJwt.isAdmin],
        controller.adminBoard
    );

    app.get('/api/users', [authJwt.verifyToken, authJwt.isAdmin], controller.getUsersAll)

    app.get('/api/users/:id', [authJwt.verifyToken, authJwt.isAdmin], controller.getUserById);

    app.put('/api/users/:id', [verifySignUp.checkDuplicateUsernameOrEmail, authJwt.verifyToken,], controller.updateUserById)

    app.delete('/api/users/:id', [authJwt.verifyToken, authJwt.isAdmin], controller.deleteUserById);

};
