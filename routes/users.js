var express = require('express');
var router = express.Router();
var User = require('../models/user');
var passport=require('passport');
var LocalStrategy = require('passport-local').Strategy;
var async=require('async');
var crypto=require('crypto');
var nodemailer=require('nodemailer');
var dotenv = require('dotenv');
dotenv.load();
var nodemailer = require('nodemailer');

var sendgrid_username   = process.env.SENDGRID_USERNAME;
var sendgrid_password   = process.env.SENDGRID_PASSWORD;
var to                  = process.env.TO;

function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    req.flash('error_msg','You are logged in');
    res.redirect('/');
  }
  else
  {
return next();
  }
}

// Register
router.get('/register',ensureAuthenticated, function(req, res){
	res.render('register');
});
router.get('/login',ensureAuthenticated, function(req, res){
	res.render('login');
});

// Register User
router.post('/register', function(req, res){
	var firstName = req.body.firstName;
	var email = req.body.email;
	var lastName = req.body.lastName;
	var password = req.body.password;
	var password2 = req.body.password2;

	// Validation

	req.checkBody('lastName', 'First Name is required').notEmpty();
	req.checkBody('email', 'Email is required').notEmpty();
	req.checkBody('email', 'Email is not valid').isEmail();
	req.checkBody('lastName', 'Last Name is required').notEmpty();
	req.checkBody('password', 'Password is required').notEmpty();
	req.checkBody('password2', 'Passwords do not match').equals(req.body.password);

	var errors = req.validationErrors();

	if(errors){
		res.render('register',{
			errors:errors

		});
	} else {
		var newUser = new User({
			firstName: firstName,
			email:email,
			lastName: lastName,
			password: password
		});

    User.createUser(newUser, function(err, user){
    if (err) {
      req.flash('error','Email already in use.');
      res.redirect('/users/register')
    }else {
      req.flash('success_msg', 'You are registered and can now login');
  		res.redirect('/users/login');
    }
    });
	}
});
passport.use(new LocalStrategy(
  function(email, password, done) {
User.getUserByMail(email, function(err, user){
  if(err) throw err;
  if(!user){
    return done(null, false,  {message:'unknown User'});
  }
  User.comparePassword(password, user.password, function(err,isMatch){
    if(err) throw err;
    if(isMatch){
      return done(null, user);
    }else{
      return done(null, false, {message: 'Invalid password'});
    }
  })
})
  }
));
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.getUserById(id, function(err, user) {
    done(err, user);
  });
});
router.post('/login',
  passport.authenticate('local', {successRedirect:'/', failureRedirect:'/users/login',failureFlash:true}),
  function(req, res) {
    });
      router.get('/logout', function(req, res){
    	req.logout();
      req.flash('success_msg', 'You are logged out');
      res.redirect('/users/login')
    });

router.get('/forgot',ensureAuthenticated, function(req, res) {
  res.render('forgot', {
    user: req.user
  });
});
router.post('/forgot', function(req, res, next) {
  async.waterfall([
    function(done) {
      crypto.randomBytes(20, function(err, buf) {
        var token = buf.toString('hex');
        done(err, token);
      });
    },
    function(token, done) {
      User.findOne({ email: req.body.email }, function(err, user) {
        if (!user) {
          req.flash('error', 'No account with that email address exists.');
          return res.redirect('/users/forgot');
        }

        user.resetPasswordToken = token;
        user.resetPasswordExpires = Date.now() + 3600000; // 1 hour

        user.save(function(err) {
          done(err, token, user);
        });
      });
    },
    function(token, user, done) {
      var settings  = {
        host: "smtp.sendgrid.net",
        port: parseInt(587, 10),
        requiresAuth: true,
        auth: {
          user: sendgrid_username,
          pass: sendgrid_password
        }
      };
      var smtpTransport = nodemailer.createTransport(settings);
      var mailOptions = {
        to: user.email,
        from: to,
        subject: 'Node.js Password Reset',
        text: 'You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n' +
          'Please click on the following link, or paste this into your browser to complete the process:\n\n' +
          'http://' + req.headers.host + '/users/reset/' + token + '\n\n' +
          'If you did not request this, please ignore this email and your password will remain unchanged.\n'
      };
      smtpTransport.sendMail(mailOptions, function(err) {
        req.flash('success_msg', 'An e-mail has been sent to ' + user.email + ' with further instructions.');
        done(err, 'done');
      });
    }
  ], function(err) {
    if (err) return next(err);
    res.redirect('/users/forgot');
  });
});
router.get('/reset/:token', function(req, res) {
  User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function(err, user) {
    if (!user) {
      req.flash('error', 'Password reset token is invalid or has expired.');
      return res.redirect('/users/forgot');
    }
    res.render('reset', {
      user: req.user
    });
  });
});
router.post('/reset/:token', function(req, res) {
  async.waterfall([
    function(done) {
      User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function(err, user) {
        if (!user) {
          req.flash('error', 'Password reset token is invalid or has expired.');
          return res.redirect('/users/forgot');
        }

        user.password = req.body.password;
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;

        user.save(function(err) {
          req.logIn(user, function(err) {
            done(err, user);
          });
        });
      });
    },
    function(user, done){
      var settings  = {
        host: "smtp.sendgrid.net",
        port: parseInt(587, 10),
        requiresAuth: true,
        auth: {
          user: sendgrid_username,
          pass: sendgrid_password
        }
      };
      var smtpTransport = nodemailer.createTransport(settings);
      var mailOptions = {
        to: user.email,
        from: to,
        subject: 'Your password has been changed',
        text: 'Hello,\n\n' +
          'This is a confirmation that the password for your account ' + user.email + ' has just been changed.\n'
      };
      smtpTransport.sendMail(mailOptions, function(err) {
        req.flash('success_msg', 'Success! Your password has been changed.');
        done(err);
      });
    }
  ], function(err) {
    res.redirect('/');
  });
});

module.exports=router;
