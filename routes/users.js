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
var bcrypt = require('bcryptjs');
var sendgrid_username   = process.env.SENDGRID_USERNAME;
var sendgrid_password   = process.env.SENDGRID_PASSWORD;
var to                  = process.env.TO;
var answer1             = process.env.ANSWER1;
var answer2             = process.env.ANSWER2;
var answer3             = process.env.ANSWER3;
var answer4             = process.env.ANSWER4;
var answer5             = process.env.ANSWER5;
var answer6             = process.env.ANSWER6;
var answer7             = process.env.ANSWER7;
var answer8             = process.env.ANSWER8;
var answer9             = process.env.ANSWER9;
var answer10             = process.env.ANSWER10;
var answer11             = process.env.ANSWER11;
var answer12             = process.env.ANSWER12;
var answer13             = process.env.ANSWER13;
var answer14             = process.env.ANSWER14;
var answer15             = process.env.ANSWER15;
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
function ensureAuth(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  else
  {
  req.flash('error_msg','You must login to continue');
  res.redirect('/users/login')
  }
}
// Register
router.get('/register',ensureAuthenticated, function(req, res){
	res.render('register');
});
router.get('/events', function(req, res){
	res.render('events');
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
  var semester = req.body.semester;
  var college = req.body.college;
  var department = req.body.department;
  var phn = req.body.phn;
	// Validation

	req.checkBody('lastName', 'First Name is required').notEmpty();
  req.checkBody('college', 'College name is required').notEmpty();
  req.checkBody('phn', 'Phone number is required').notEmpty();
	req.checkBody('email', 'Email is not valid').isEmail();
	req.checkBody('lastName', 'Last Name is required').notEmpty();
  req.checkBody('password', 'Password should be minimum 6 characters long').isLength({ min: 5 })
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
			password: password,
      phn: phn,
      college: college,
      department: department,
      semester: semester
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
        subject: 'Prominence Password Reset',
        text: 'Hello\n\n'+'You are receiving this because you have requested the reset of the password for your account.Please click on the following link, or paste this into your browser to complete the process:\n\n' +
          'http://' + req.headers.host + '/users/reset/' + token + '\n\n' +
          'If you did not request this, please ignore this email.\n\n'+'Regards,\n\nProminence 2017'
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



        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;
        bcrypt.genSalt(10, function(err, salt) {
        bcrypt.hash(req.body.password, salt, function(err, hash) {
          req.body.password = hash;  user.password = req.body.password;
          user.password = req.body.password;
          user.save(function(err) {
            req.logIn(user, function(err) {
              done(err, user);
            });
          });
        })
          })
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
  router.get('/machine-learning', function(req, res){
	res.render('machine-learning');
});
router.get('/talk-session', function(req, res){
	res.render('sv');
});
router.get('/wearables', function(req, res){
	res.render('wearables');
});
router.get('/business_analytics', function(req, res){
	res.render('business_analytics');
});
router.get('/lan-gaming', function(req, res){
	res.render('lan-gaming');
});
router.get('/line-follower', function(req, res){
	res.render('line-follower');
});
router.get('/quiz', function(req, res){
	res.render('quiz');
});
router.get('/paper-presentation', function(req, res){
	res.render('paper-presentation');
});
router.get('/crime-scene', function(req, res){
	res.render('crime-scene');
});
router.get('/decrypt',ensureAuth, function(req, res){
	res.render('decrypt');
});

router.post('/events',ensureAuth, function(req, res){
  req.user.update(
  { $push : { events: req.body.foo}},
  function(err){
         if(err){
             res.send(err);
         }else{
           req.flash('success_msg','Congrats! Your seat has been reserved!');
           res.redirect('/users/events');
         }
});
    });
    router.post('/decrypt', function(req, res){
      if(req.body.answer1){
        if(req.body.answer1==answer1){
          res.render('success.handlebars', {root: './views'})
      }
      else{
            res.render('error.handlebars', {root: './views'})
        }
      }
      if(req.body.answer2){
        if(req.body.answer2==answer2){
            res.render('success.handlebars', {root: './views'})
        }
        else{
              res.render('error.handlebars', {root: './views'})
          }
      }
    if(req.body.answer3){
     if(req.body.answer3==answer3){
          res.render('success.handlebars', {root: './views'})
      }
      else{
            res.render('error.handlebars', {root: './views'})
        }
    }
    if(req.body.answer4){
    if(req.body.answer4==answer4){
          res.render('success.handlebars', {root: './views'})
      }
      else{
            res.render('error.handlebars', {root: './views'})
        }
    }
    if(req.body.answer5){
      if(req.body.answer5==answer5){
        res.render('success.handlebars', {root: './views'})
    }
    else{
          res.render('error.handlebars', {root: './views'})
      }
    }
    if(req.body.answer6){
      if(req.body.answer6==answer6){
          res.render('success.handlebars', {root: './views'})
      }
      else{
            res.render('error.handlebars', {root: './views'})
        }
    }
  if(req.body.answer7){
   if(req.body.answer7==answer7){
        res.render('success.handlebars', {root: './views'})
    }
    else{
          res.render('error.handlebars', {root: './views'})
      }
  }
  if(req.body.answer8){
  if(req.body.answer8==answer8){
        res.render('success.handlebars', {root: './views'})
    }
    else{
          res.render('error.handlebars', {root: './views'})
      }
  }
  if(req.body.answer9){
  if(req.body.answer9==answer9){
        res.render('success.handlebars', {root: './views'})
    }
    else{
          res.render('error.handlebars', {root: './views'})
      }
  }
  if(req.body.answer10){
    if(req.body.answer10==answer10){
      res.render('success.handlebars', {root: './views'})
  }
  else{
        res.render('error.handlebars', {root: './views'})
    }
  }
  if(req.body.answer11){
    if(req.body.answer11==answer11){
        res.render('success.handlebars', {root: './views'})
    }
    else{
          res.render('error.handlebars', {root: './views'})
      }
  }
if(req.body.answer12){
 if(req.body.answer12==answer12){
      res.render('success.handlebars', {root: './views'})
  }
  else{
        res.render('error.handlebars', {root: './views'})
    }
}
if(req.body.answer13){
if(req.body.answer13==answer13){
      res.render('success.handlebars', {root: './views'})
  }
  else{
        res.render('error.handlebars', {root: './views'})
    }
}
if(req.body.answer14){
if(req.body.answer14==answer14){
      res.render('success.handlebars', {root: './views'})
  }
  else{
        res.render('error.handlebars', {root: './views'})
    }
}
if(req.body.answer15){
if(req.body.answer15==answer15){
      res.render('success.handlebars', {root: './views'})
  }
  else{
        res.render('error.handlebars', {root: './views'})
    }
}
    });

module.exports=router;
