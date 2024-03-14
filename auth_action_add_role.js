exports.onExecutePostLogin = async (event, api) => {
    const namespace = 'http://echo-with-sql.com';
    if (event.authorization) {
        api.idToken.setCustomClaim(`${namespace}/roles`, event.authorization.roles);
        api.accessToken.setCustomClaim(`${namespace}/roles`, event.authorization.roles);
    }
};