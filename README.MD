# hapi-session-auth
Authentication plugin for hapi framework based on sessions. Depends on [hapi-sessions](https://github.com/alexander3um/hapi-sessions).
## API
* `await request.sAuth.authenticate(credentials)`
* `await request.sAuth.deauthenticate(credentials)`

Credentials is an optional argument. Must be an object.

The plugin has been made by a total rookie for personal purposes. Any critics are welcome.