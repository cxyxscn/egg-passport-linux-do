const OAuth2Strategy = require('passport-oauth2').Strategy;

module.exports = app => {
  const config = app.config.passportLinuxDo;

  // 确保配置存在
  if (!config.key || !config.secret) {
    throw new Error('[egg-passport-linux-do key and secret are required');
  }

  // 配置 OAuth2 策略
  const strategy = new OAuth2Strategy({
    authorizationURL: config.authorizationURL,
    tokenURL: config.tokenURL,
    clientID: config.key,
    clientSecret: config.secret,
    callbackURL: config.callbackURL,
    passReqToCallback: true,
  }, async (req, accessToken, refreshToken, params, done) => {
    try {
      // 获取用户信息
      const result = await app.curl(config.userProfileURL, {
        method: 'GET',
        dataType: 'json',
        headers: {
          'Authorization': `Bearer ${accessToken}`,
        },
      });

      const profile = result.data;

      const user = {
        provider: 'linuxDo',
        id: profile.id,
        name: profile.name,
        avatarUrl: profile.avatar_url,
        trustLevel: profile.trust_level:
        accessToken,
        refreshToken,
        profile,
      };

      app.passport.doVerify(req, user, done);
    } catch (err) {
      done(err);
    }
  });

  app.passport.use('linuxDo', strategy);
}; 