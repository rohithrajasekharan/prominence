var express=require("express");
var path=require("path");
var cookieParse=require("cookie-parser");
var bodyParser=require("body-parser");
var exphbs=require('express-handlebars');
var flash=require("flash");
var session=require("express-session");
var passport=require("passport");
var localStrategy=require("passport-local").Strategy;
var mongo=require("mongodb");
var mongoose=require("mongoose");
mongoose.connect("mongodb://localhost/prominence");
var db = mongoose.connection;
var routes=require("./routes/index");
var users=require("./routes/users");
var app=express();
app.set('views', path.join(__dirname, "views"));
app.engine("handlebars",exphbs({defaultLayout:"layout"}));
app.set('view engine', 'handlebars');
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false}));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
	secret:"secret",
	saveUninitialized: true,
	resave: true
}));
app.use(passport.initialize());
app.use(passport.session());

//flash messages
app.use(flash());

app.use(function(req, res, next){
	res.locals.success_msg = req.flash('success_msg');
	res.locals.error_msg = req.flash('error_msg');
	res.locals.error = req.flash('error');
	next();
});
app.use('/', routes);
app.use('/users',users);

app.set('port', (process.env.PORT || 3000));
app.listen(app.get('port'), function(){
	console.log('Server started on port'+app.get('port'));
});
