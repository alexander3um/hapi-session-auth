const Boom = require(`boom`);

module.exports.plugin = {
    name: `hapi-auth`,
    dependencies: [`hapi-sessions`],
    register: async function (server, options) {
        server.auth.scheme(`sessions`, function (server, options) {
            server.decorate(`request`, `sAuth`, function (request) {
                return {
                    authenticate: async (credentials) => {
                        return request.session.addOrChange({
                            isAuthenticated: true,
                            credentials: credentials || {}
                        });
                    },
                    deauthenticate: async (credentials) => {
                        return request.session.addOrChange({
                            isAuthenticated: false,
                            credentials: credentials || {}
                        });
                    }
                };
            }, { apply: true });

            return {
                authenticate: async function (request, h) {
                    let session;

                    try {
                        session = await request.session.get();
                        
                        if (session.isAuthenticated === undefined && session.credentials === undefined) { // initialization
                            await request.session.addOrChange({
                                isAuthenticated: false,
                                credentials: {}
                            });
                            session = await request.session.get();
                        }
                    } catch (error) {
                        throw Boom.badImplementation(error);
                    }
                    
                    if (session.isAuthenticated === true) {
                        return h.authenticated({
                            credentials: session.credentials
                        });
                    }

                    return h.unauthenticated(Boom.unauthorized(), {
                        credentials: session.credentials
                    });
                }
            };
        });
    },
    once: true
};