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
function getDateTime() {

    var date = new Date();

    var hour = date.getHours();
    hour = (hour < 10 ? "0" : "") + hour;

    var min  = date.getMinutes();
    min = (min < 10 ? "0" : "") + min;

    var sec  = date.getSeconds();
    sec = (sec < 10 ? "0" : "") + sec;

    var year = date.getFullYear();

    var month = date.getMonth() + 1;
    month = (month < 10 ? "0" : "") + month;

    var day  = date.getDate();
    day = (day < 10 ? "0" : "") + day;

    return year + ":" + month + ":" + day + ":" + hour + ":" + min + ":" + sec;

}
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
        port: parseInt(25, 587),
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
  if(req.user.events.indexOf('15')>-1){
    return res.render('Answer16');
  }
  else if(req.user.events.indexOf('14')>-1){
    return res.render('Answer15');
  }
  else if(req.user.events.indexOf('13')>-1){
    return res.render('Answer14');
  }
  else if(req.user.events.indexOf('12')>-1){
    return res.render('Answer13');
  }
  else if(req.user.events.indexOf('11')>-1){
    return res.render('Answer12');
  }
  else if(req.user.events.indexOf('10')>-1){
    return res.render('Answer11');
  }
  else if(req.user.events.indexOf('9')>-1){
    return res.render('Answer10');
  }
  else if(req.user.events.indexOf('8')>-1){
    return res.render('Answer9');
  }
  else if(req.user.events.indexOf('7')>-1){
    return res.render('Answer8');
  }
  else if(req.user.events.indexOf('6')>-1){
    return res.render('Answer7');
  }
  else if(req.user.events.indexOf('5')>-1){
    return res.render('Answer6');
  }
  else if(req.user.events.indexOf('4')>-1){
    return res.render('Answer5');
  }
  else if(req.user.events.indexOf('3')>-1){
    return res.render('Answer4');
  }
  else if(req.user.events.indexOf('2')>-1){
    return res.render('Answer3');
  }
  else if(req.user.events.indexOf('1')>-1){
    return res.render('Answer2');
  }
  else{
    return res.render('decrypt');
  }
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
      var eureka=getDateTime();
      if(req.body.answer1){
        if(req.body.answer1==answer1){
          req.user.update(
          { $pushAll : { events: ["cleared level 1 at "+eureka,"1"]}},
          function(err){
                 if(err){
                     res.send(err);
                 }else{
                  res.render('Answer2', {root: './views'});
                 }
        });
      }
      else{
            res.render('error.handlebars', {root: './views'})
        }
      }
      if(req.body.answer2){
        if(req.body.answer2==answer2){
          req.user.update(
          { $pushAll : { events: ["cleared level 2 at "+eureka,"2"]}},
          function(err){
                 if(err){
                     res.send(err);
                 }else{
                  res.render('Answer3', {root: './views'});
                 }
          });        }
        else{
              res.render('error2.handlebars', {root: './views'})
          }
      }
    if(req.body.answer3){
     if(req.body.answer3==answer3){
       req.user.update(
       { $pushAll : { events: ["cleared level 3 at "+eureka,"3"]}},
       function(err){
              if(err){
                  res.send(err);
              }else{
               res.render('Answer4', {root: './views'});
              }
       });      }
      else{
            res.render('error3.handlebars', {root: './views'})
        }
    }
    if(req.body.answer4){
    if(req.body.answer4==answer4){
      req.user.update(
      { $pushAll : { events: ["cleared level 4 at "+eureka,"4"]}},
      function(err){
             if(err){
                 res.send(err);
             }else{
              res.render('Answer5', {root: './views'});
             }
      });      }
      else{
            res.render('error4.handlebars', {root: './views'})
        }
    }
    if(req.body.answer5){
      if(req.body.answer5==answer5){
        req.user.update(
        { $pushAll : { events: ["cleared level 5 at "+eureka,"5"]}},
        function(err){
               if(err){
                   res.send(err);
               }else{
                res.render('Answer6', {root: './views'});
               }
        });    }
    else{
          res.render('error5.handlebars', {root: './views'})
      }
    }
    if(req.body.answer6){
      if(req.body.answer6==answer6){
        req.user.update(
        { $pushAll : { events: ["cleared level 6 at "+eureka,"6"]}},
        function(err){
               if(err){
                   res.send(err);
               }else{
                res.render('Answer7', {root: './views'});
               }
        });      }
      else{
            res.render('error6.handlebars', {root: './views'})
        }
    }
  if(req.body.answer7){
   if(req.body.answer7==answer7){
     req.user.update(
     { $pushAll : { events: ["cleared level 7 at "+eureka,"7"]}},
     function(err){
            if(err){
                res.send(err);
            }else{
             res.render('Answer8', {root: './views'});
            }
     });    }
    else{
          res.render('error7.handlebars', {root: './views'})
      }
  }
  if(req.body.answer8){
  if(req.body.answer8==answer8){
    req.user.update(
    { $pushAll : { events: ["cleared level 8 at "+eureka,"8"]}},
    function(err){
           if(err){
               res.send(err);
           }else{
            res.render('Answer9', {root: './views'});
           }
    });    }
    else{
          res.render('error8.handlebars', {root: './views'})
      }
  }
  if(req.body.answer9){
  if(req.body.answer9==answer9){
    req.user.update(
    { $pushAll : { events: ["cleared level 9 at "+eureka,"9"]}},
    function(err){
           if(err){
               res.send(err);
           }else{
            res.render('Answer10', {root: './views'});
           }
    });    }
    else{
          res.render('error9.handlebars', {root: './views'})
      }
  }
  if(req.body.answer10){
    if(req.body.answer10==answer10){
      req.user.update(
      { $pushAll : { events: ["cleared level 10 at "+eureka,"10"]}},
      function(err){
             if(err){
                 res.send(err);
             }else{
              res.render('Answer11', {root: './views'});
             }
      });  }
  else{
        res.render('error10.handlebars', {root: './views'})
    }
  }
  if(req.body.answer11){
    if(req.body.answer11==answer11){
      req.user.update(
      { $pushAll : { events: ["cleared level 11 at "+eureka,"11"]}},
      function(err){
             if(err){
                 res.send(err);
             }else{
              res.render('Answer12', {root: './views'});
             }
      });    }
    else{
          res.render('error11.handlebars', {root: './views'})
      }
  }
if(req.body.answer12){
 if(req.body.answer12==answer12){
   req.user.update(
   { $pushAll : { events: ["cleared level 12 at "+eureka,"12"]}},
   function(err){
          if(err){
              res.send(err);
          }else{
           res.render('Answer13', {root: './views'});
          }
   });  }
  else{
        res.render('error12.handlebars', {root: './views'})
    }
}
if(req.body.answer13){
if(req.body.answer13==answer13){
  req.user.update(
  { $pushAll : { events: ["cleared level 13 at "+eureka,"13"]}},
  function(err){
         if(err){
             res.send(err);
         }else{
          res.render('Answer14', {root: './views'});
         }
  });  }
  else{
        res.render('error13.handlebars', {root: './views'})
    }
}
if(req.body.answer14){
if(req.body.answer14==answer14){
  req.user.update(
  { $pushAll : { events: ["cleared level 14 at "+eureka,"14"]}},
  function(err){
         if(err){
             res.send(err);
         }else{
          res.render('Answer15', {root: './views'});
         }
  });  }
  else{
        res.render('error14.handlebars', {root: './views'})
    }
}
if(req.body.answer15){
if(req.body.answer15==answer15){
  req.user.update(
  { $pushAll : { events: ["cleared level 15 at "+eureka,"15"]}},
  function(err){
         if(err){
             res.send(err);
         }else{
          res.render('Answer16', {root: './views'});
         }
  });  }
  else{
        res.render('error15.handlebars', {root: './views'})
    }
}
    });

module.exports=router;
