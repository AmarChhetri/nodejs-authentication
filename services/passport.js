const passport = require('passport');
const User = require('../models/user');
const config = require('../config');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const LocalStrategy = require('passport-local');



//Create local strategy
const localOptions = { usernameField: 'email'} //by default it expects username and password field in 'request' object
const localLogin = new LocalStrategy(localOptions, function(email, password, done){
  //Verify this email and password
  User.findOne({email: email}, function(err, user){
    if (err) { return done(err);}
    if(!user) { return done(null, false);}  //(err, boolean), false => not found

    //compare passwords - is 'password' equal to user.password?
    user.comparePassword(password, function(err, isMatch){
      if(err) { return done(err);}
      if(!isMatch) { return done(null, false);}

      return done(null, user);
    });

  });
});

//Set up options for jwt strategy
const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromHeader('authorization'),
  secretOrKey: config.secret
};
//Create JWT strategy
const jwtLogin = new JwtStrategy(jwtOptions, function(payload, done){
  User.findById(payload.sub, function(err, user) {
    if(err) { return done(err, false); }
    
    if(user) { 
      done(null, user);  //assigns user to request.user which can be accessed in the handler function e.g. signin()
    } else {
      done(null, false);
    }
  });
});


//Tell passport to use this strategy
passport.use(jwtLogin);
passport.use(localLogin);




















