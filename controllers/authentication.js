const jwt = require('jwt-simple');
const User = require('../models/user');
const config = require('../config');


function tokenForUSer(user) {
  const timestamp = new Date().getTime();
  return jwt.encode({ sub: user.id, iat: timestamp }, config.secret);
}

exports.signin = function(req, res, next) {
  //User already had email and password authenticated, just need to give them a token
  res.send({token: tokenForUSer(req.user)}); // user is attached to req obj when authenticated in passport.js file 
};

exports.signup = function(req, res, next) {
  const email = req.body.email;
  const password = req.body.password;
  
  if(!email || !password) {
    return res.status(422).send({error: 'You must provide email and password'});
  }

  User.findOne({email: email}, function(err, existingUser) {
    if(err) { return next(err);}

    if(existingUser) {
      return res.status(422).send({error: 'Email is in use'});
    }

    //create user
    const user = new User({
      email: email,
      password: password
    });

    //save
    user.save(function(err){
      if(err) {
        return next(err);
      }

      res.json({token: tokenForUSer(user)});
    }); 
  });
}















