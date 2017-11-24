# hapi-session-auth
Authentication plugin for hapi framework based on sessions. Depends on [hapi-sessions](https://github.com/alexander3um/hapi-sessions).
## API
* `request.sAuth.authenticate(credentials)`
* `request.sAuth.deauthenticate(credentials)`

Credentials is an optional argument. Must be an object.