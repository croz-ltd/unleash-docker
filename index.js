'use strict';

const fs = require("fs");
const unleash = require('unleash-server');

const { User, AuthenticationRequired } = require('unleash-server');

const KeycloakStrategy = require('@exlinc/keycloak-passport');
const passport = require('passport');

const host = process.env.AUTH_HOST;
const realm = process.env.AUTH_REALM;
const clientID = process.env.AUTH_CLIENT_ID;
const clientSecret = process.env.AUTH_CLIENT_SECRET;
const contextPath = process.env.CONTEXT_PATH;
const sharedSecret = process.env.SHARED_CLIENT_SECRET;


passport.use(
    'keycloak',
    new KeycloakStrategy(
        {
            host,
            realm,
            clientID,
            clientSecret,
            callbackURL: `${contextPath}/api/auth/callback`,
            authorizationURL: `${host}/auth/realms/${realm}/protocol/openid-connect/auth`,
            tokenURL: `${host}/auth/realms/${realm}/protocol/openid-connect/token`,
            userInfoURL: `${host}/auth/realms/${realm}/protocol/openid-connect/userinfo`,
        },

        (accessToken, refreshToken, profile, done) => {
            done(
                null,
                new User({
                    name: profile.fullName,
                    email: profile.email,
                })
            );
        }
    )
);

function enableKeycloakOauth(app) {

    app.use('/api/client', (req, res, next) => {
        if (req.header('authorization') !== sharedSecret) {
            res.sendStatus(401);
        } else {
            next();
        }
    });

    app.use(passport.initialize());
    app.use(passport.session());

    passport.serializeUser((user, done) => done(null, user));
    passport.deserializeUser((user, done) => done(null, user));

    app.get('/api/admin/login', passport.authenticate('keycloak'));

    app.get(
        '/api/auth/callback',
        passport.authenticate('keycloak'),
        (req, res) => {
            res.redirect(`${contextPath}/`);
        }
    );

    app.use('/api/admin/', (req, res, next) => {
        if (req.user) {
            next();
        } else {
            // Instruct unleash-frontend to pop-up auth dialog
            return res
                .status('401')
                .json(
                    new AuthenticationRequired({
                        path: `${contextPath}/api/admin/login`,
                        type: 'custom',
                        message: `You have to identify yourself in order to use Unleash. 
                        Click the button and follow the instructions.`,
                    })
                )
                .end();
        }
    });
}

module.exports = enableKeycloakOauth;

const options = {
    enableLegacyRoutes: false,
    secret: 'super-duper-secret',
    adminAuthentication: 'custom',
    preRouterHook: enableKeycloakOauth
};

unleash.start(options).then(instance => {
    console.log(
        `Unleash started on http://localhost:${instance.app.get('port')}`,
    );
});
