var express = require('express')
    , path = require('path')
    , favicon = require('serve-favicon')
    , cookieParser = require('cookie-parser')
    , bodyParser = require('body-parser')
    , session = require('express-session')
    , passport = require('passport')
    , swig = require('swig')
    , Auth0Strategy = require('passport-auth0')
    , logger = require('./logger')
    , crypto = require('crypto')
    , base64url = require('base64url')
    , cryptiles = require('cryptiles');

var keys = {};

var provider_friendly_name = {
    'facebook': 'Facebook',
    'google-oauth2': 'Google',
    'windowslive': 'Microsoft Account',
    'twitter': 'Twitter',
    'github': 'GitHub',
    'yahoo': 'Yahoo'
};
	
// get ready to call Auth0 API for user profile
// var request = require("request");

// var options = {
// 	  method: 'GET',
// 	  url: 'https://dev-asqfrzuv.auth0.com/api/v2/users/google-oauth2|102715759101504372239',
// 	  headers: {authorization:'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Ik5EaEJOREV6TlVNMk1UTkVPRFJEUTBWRU1rVTBPVVZETkVNeFFqVTVSalE0TkRRMk4wVTROUSJ9.eyJpc3MiOiJodHRwczovL2Rldi1hc3Fmcnp1di5hdXRoMC5jb20vIiwic3ViIjoiUDFxWDcxR0ZESW1oVmNJQVhZY0t6MEM5TWVnTkFHN09AY2xpZW50cyIsImF1ZCI6Imh0dHBzOi8vZGV2LWFzcWZyenV2LmF1dGgwLmNvbS9hcGkvdjIvIiwiaWF0IjoxNTg1ODAyNDk4LCJleHAiOjE1ODU4ODg4OTgsImF6cCI6IlAxcVg3MUdGREltaFZjSUFYWWNLejBDOU1lZ05BRzdPIiwic2NvcGUiOiJyZWFkOmNsaWVudF9ncmFudHMgY3JlYXRlOmNsaWVudF9ncmFudHMgZGVsZXRlOmNsaWVudF9ncmFudHMgdXBkYXRlOmNsaWVudF9ncmFudHMgcmVhZDp1c2VycyB1cGRhdGU6dXNlcnMgZGVsZXRlOnVzZXJzIGNyZWF0ZTp1c2VycyByZWFkOnVzZXJzX2FwcF9tZXRhZGF0YSB1cGRhdGU6dXNlcnNfYXBwX21ldGFkYXRhIGRlbGV0ZTp1c2Vyc19hcHBfbWV0YWRhdGEgY3JlYXRlOnVzZXJzX2FwcF9tZXRhZGF0YSByZWFkOnVzZXJfY3VzdG9tX2Jsb2NrcyBjcmVhdGU6dXNlcl9jdXN0b21fYmxvY2tzIGRlbGV0ZTp1c2VyX2N1c3RvbV9ibG9ja3MgY3JlYXRlOnVzZXJfdGlja2V0cyByZWFkOmNsaWVudHMgdXBkYXRlOmNsaWVudHMgZGVsZXRlOmNsaWVudHMgY3JlYXRlOmNsaWVudHMgcmVhZDpjbGllbnRfa2V5cyB1cGRhdGU6Y2xpZW50X2tleXMgZGVsZXRlOmNsaWVudF9rZXlzIGNyZWF0ZTpjbGllbnRfa2V5cyByZWFkOmNvbm5lY3Rpb25zIHVwZGF0ZTpjb25uZWN0aW9ucyBkZWxldGU6Y29ubmVjdGlvbnMgY3JlYXRlOmNvbm5lY3Rpb25zIHJlYWQ6cmVzb3VyY2Vfc2VydmVycyB1cGRhdGU6cmVzb3VyY2Vfc2VydmVycyBkZWxldGU6cmVzb3VyY2Vfc2VydmVycyBjcmVhdGU6cmVzb3VyY2Vfc2VydmVycyByZWFkOmRldmljZV9jcmVkZW50aWFscyB1cGRhdGU6ZGV2aWNlX2NyZWRlbnRpYWxzIGRlbGV0ZTpkZXZpY2VfY3JlZGVudGlhbHMgY3JlYXRlOmRldmljZV9jcmVkZW50aWFscyByZWFkOnJ1bGVzIHVwZGF0ZTpydWxlcyBkZWxldGU6cnVsZXMgY3JlYXRlOnJ1bGVzIHJlYWQ6cnVsZXNfY29uZmlncyB1cGRhdGU6cnVsZXNfY29uZmlncyBkZWxldGU6cnVsZXNfY29uZmlncyByZWFkOmhvb2tzIHVwZGF0ZTpob29rcyBkZWxldGU6aG9va3MgY3JlYXRlOmhvb2tzIHJlYWQ6ZW1haWxfcHJvdmlkZXIgdXBkYXRlOmVtYWlsX3Byb3ZpZGVyIGRlbGV0ZTplbWFpbF9wcm92aWRlciBjcmVhdGU6ZW1haWxfcHJvdmlkZXIgYmxhY2tsaXN0OnRva2VucyByZWFkOnN0YXRzIHJlYWQ6dGVuYW50X3NldHRpbmdzIHVwZGF0ZTp0ZW5hbnRfc2V0dGluZ3MgcmVhZDpsb2dzIHJlYWQ6c2hpZWxkcyBjcmVhdGU6c2hpZWxkcyBkZWxldGU6c2hpZWxkcyByZWFkOmFub21hbHlfYmxvY2tzIGRlbGV0ZTphbm9tYWx5X2Jsb2NrcyB1cGRhdGU6dHJpZ2dlcnMgcmVhZDp0cmlnZ2VycyByZWFkOmdyYW50cyBkZWxldGU6Z3JhbnRzIHJlYWQ6Z3VhcmRpYW5fZmFjdG9ycyB1cGRhdGU6Z3VhcmRpYW5fZmFjdG9ycyByZWFkOmd1YXJkaWFuX2Vucm9sbG1lbnRzIGRlbGV0ZTpndWFyZGlhbl9lbnJvbGxtZW50cyBjcmVhdGU6Z3VhcmRpYW5fZW5yb2xsbWVudF90aWNrZXRzIHJlYWQ6dXNlcl9pZHBfdG9rZW5zIGNyZWF0ZTpwYXNzd29yZHNfY2hlY2tpbmdfam9iIGRlbGV0ZTpwYXNzd29yZHNfY2hlY2tpbmdfam9iIHJlYWQ6Y3VzdG9tX2RvbWFpbnMgZGVsZXRlOmN1c3RvbV9kb21haW5zIGNyZWF0ZTpjdXN0b21fZG9tYWlucyByZWFkOmVtYWlsX3RlbXBsYXRlcyBjcmVhdGU6ZW1haWxfdGVtcGxhdGVzIHVwZGF0ZTplbWFpbF90ZW1wbGF0ZXMgcmVhZDptZmFfcG9saWNpZXMgdXBkYXRlOm1mYV9wb2xpY2llcyByZWFkOnJvbGVzIGNyZWF0ZTpyb2xlcyBkZWxldGU6cm9sZXMgdXBkYXRlOnJvbGVzIHJlYWQ6cHJvbXB0cyB1cGRhdGU6cHJvbXB0cyByZWFkOmJyYW5kaW5nIHVwZGF0ZTpicmFuZGluZyByZWFkOmxvZ19zdHJlYW1zIGNyZWF0ZTpsb2dfc3RyZWFtcyBkZWxldGU6bG9nX3N0cmVhbXMgdXBkYXRlOmxvZ19zdHJlYW1zIGNyZWF0ZTpzaWduaW5nX2tleXMgcmVhZDpzaWduaW5nX2tleXMgdXBkYXRlOnNpZ25pbmdfa2V5cyIsImd0eSI6ImNsaWVudC1jcmVkZW50aWFscyJ9.MgfNy9r84KzxSNb5wtNHSL6a_jUWlILy6zNbzNXrvlnONMrGkqQrrPbiQ3Z9PDboDbxiqZcKL03EGqpPd0NiBuQhQy0G0_bNLuRgsknJkMtgI2tkTW3sfUqhHQRfSHSgTT44tZkmKMXKzERrGfjbPivexsONyykLBZE9szjw0A7t1p7b3XMmfGMw_Ah-_d2GkEV6PiSbmzm7i1E3AEXXzdM94j3_5tND10cGMeNP0UQ-1v1OZGdYKphKa7-flt4uEr7dtOTn7HczYuMuXiGt77k6aDUddSBzVYgT_iw7RzWkorRWb-kfb_aZTcyQw7TC4ACuBezQ9EzUM1PtiiS1RA'}
// 	};

// 	//get user profile
// request(options, function (error, response, body) {
// 	  if (error) throw new Error(error);
	//   console.log("User Profile: ", body);
	//   console.log("done");
	// });

var request = require("https");

var options = {
  method: 'POST',
  url: 'https://dev-asqfrzuv.auth0.com/oauth/token',
  headers: {'content-type': 'application/x-www-form-urlencoded'},
  form: {
    grant_type: 'client_credentials',
    client_id: 'k61aR57GKAVqrTlLWWtGb12ktuGXwqjq',
    client_secret: 'z-9gUMMRQ_-ZQmWUYYyTJiLyJt8-XOeLlrs0evi3d-ukahMksK3uXFwINJzHqUZf',
    audience: 'https://dev-asqfrzuv.auth0.com/api/v2/'
  }
};

var access_token;

access_token=request.request(options, function (error, response, body) {
  if (error) throw new Error(error);

  console.log("get access token: body.access_token", body.access_token);
  access_token=body.access_token;
});

console.log("returned access_token",access_token);
console.log("done");

var strategy = new Auth0Strategy({
    domain: process.env.AUTH0_DOMAIN,
    clientID: process.env.AUTH0_CLIENT_ID,
    clientSecret: process.env.AUTH0_CLIENT_SECRET,
    callbackURL: process.env.AUTH0_CALLBACK,
    scope: 'openid email profile'
}, function(accessToken, refreshToken, extraParams, profile, done) {
    // accessToken is the token to call Auth0 API (not needed in the most cases)
    // extraParams.id_token has the JSON Web Token
    // profile has all the information from the user
    console.log("hello - accessToken: ",accessToken);
    console.log("done"); 
 //    console.log("hello -- profile: ",profile);
 //    console.log("done");
 //    console.log("domain: ",process.env.AUTH0_DOMAIN,"clientID: ",process.env.AUTH0_CLIENT_ID, "callbackURL: ", process.env.AUTH0_CALLBACK);
	// console.log("done");

// 	//got the user profile
// done with setting up Auth0 APi vars

    return done(null, profile);
});


passport.use(strategy);

// This is not a best practice, but we want to keep things simple for now
passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(user, done) {
  done(null, user);
});

console.log("passport object: ", passport);
console.log("done");


var app = express();

// console.log("hello xyz");

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'html');
app.engine('html', swig.renderFile);

if ('development' === app.get('env')) {
    app.set('view cache', false);
    swig.setDefaults({ cache: false });
}

app.set('trust proxy', true);

// uncomment after placing your favicon in /public
//app.use(favicon(__dirname + '/public/favicon.ico'));
app.use(function (req, res, next) {
    req.start_time = Date.now();
    res.on('finish', function () {
        var meta = {
            code: res.statusCode,
            time: new Date(),
            duration: Date.now() - req.start_time,
            path: req.path,
            method: req.method
        };
        if (res.statusCode >= 400)
            logger.warn(meta, res.statusCode);
        else
            logger.info(meta, res.statusCode);
    });
    next();
});

if (process.env.FORCE_HTTPS === '1') {
    logger.info('turning on HTTPS enforcement');
    app.use(function (req, res, next) {
        if (req.protocol === 'https' || req.headers['x-arr-ssl'] || req.headers['x-forwarded-proto'] === 'https')
            next();
        else
            return res.redirect('https://' + req.host + req.url);
    });
}

app.use(cookieParser());
app.use(session({ secret: process.env.COOKIE_SECRET, resave: false, saveUninitialized: true }));
app.use(passport.initialize());
app.use(passport.session());
app.use(express.static(path.join(__dirname, 'public'), { index: false, redirect: false }));
app.use(contextualLocals);

// console.log("hello -- passport from Auth0 strategy: ", passport);


app.get('/', function (req, res, next) {
    res.render('home.html');
});

app.get('/home', function(req,res,next){
    res.redirect('/');
})

app.get('/download', function(req,res,next){
    res.render('download.html');
})

app.get('/tos', function(req,res,next){
    res.render('tos.html');
})

app.get('/about', function(req,res,next){
    res.render('about.html');
})

app.get('/security', function(req,res,next){
    res.render('security.html');
})

app.get('/privacy', function(req,res,next){
    res.render('privacy.html');
})

app.get('/cookies', function(req,res,next){
    res.render('cookies.html');
})

app.get('/callback',
    passport.authenticate('auth0', { failureRedirect: '/unauthorized' }),
    function (req, res, next) {
        if (!req.user)
            res.send(403);
        else {
        	console.log("req.user: ",req.user);
			console.log("done");
			// console.log("res");
			// console.log("done"); 
            var url = req.session.bookmark || '/';
            delete req.session.bookmark;
            res.redirect(url);
        }
    }
);

app.get('/logout',
    function (req, res, next) {
        req.session.destroy();
        res.redirect(req.query.r || '/');
    });

app.get('/new', function (req, res, next) {
    res.render('new');
});

app.post('/create',
    bodyParser.json(),
    bodyParser.urlencoded({ extended: false }),
    current_create());

// app.get('/test/500', function(req, res, next) {
//     if (app.get('env') === 'development') {
//         throw new Error('Internal Server Error');
//     }
//     next();
// });



app.get(/^\/(\w{1,10})\/(.+)$/,
    v1_get());



// catch 404 and forward to error handler
app.use(function(req, res, next) {
    res.status(404);
    res.render('404');
});

// error handlers

// development error handler
// will print stacktrace
if (app.get('env') === 'development') {
    app.use(function(err, req, res, next) {
        console.error(err);
        res.status(err.status || 500);
        res.render('500', {
            message: err.message,
            error: err
        });
    });
}

// production error handler
// no stacktraces leaked to user
app.use(function(err, req, res, next) {
    res.status(err.status || 500);
    res.render('500', {
        message: err.message,
        error: {}
    });
});

function normalize_gmail(email) {
    // Gmail emails don't allow @'s in name, so only one will be present
    var split = email.split('@');
    var name = split[0];
    var domain = split[1];
    return name.toLowerCase().replace(/\./g, '') + '@' + domain;
}

function current_create() {

    // current signature, encryption keys, and version
    var current_keys = ensure_key(process.env.CURRENT_KEY);
    var version_prefix = '/' + process.env.CURRENT_KEY + '/';

    return function (req, res, next) {
        if (!req.body.d)
            req.body.d = req.query.d;
        if (!req.body.a)
            req.body.a = req.query.a;
        if (typeof req.body.d !== 'string' || req.body.d.length === 0)
            return res.status(400).send('Missing data to secure. Use `d` parameter.');
        if (req.body.d.length > 500)
            return res.status(400).send('Data too large. Max 500 characters.');
        if (typeof req.body.a !== 'string' || req.body.a.length === 0)
            return res.status(400).send('Missing ACLs. Use `a` parameter.');
        if (req.body.a.length > 200)
            return res.status(400).send('ACLs too long. Max 200 characters.');

        var resource = {
            d: req.body.d,
            a: []
        };

        var tokens = req.body.a.split(/[\ \n\,\r]/);
        for (var i in tokens) {
            var token = tokens[i].trim();

            if (token.length === 0)
                continue;

            var match = token.match(/^\@([^\.]+)$/);
            if (match) {
                // twitter
                resource.a.push({
                    k: 't',
                    v: match[1]
                });
                continue;
            }

            match = token.match(/^\@([^\.]+\..+)$/);
            if (match) {
                // email domain
                resource.a.push({
                    k: 'd',
                    v: token
                });
                continue;
            }

            gmail_token = normalize_gmail(token);
            match = gmail_token.match('^[a-z0-9](\.?[a-z0-9]){5,}@g(oogle)?mail\.com$');
            if (match) {
                // gmail
                resource.a.push({
                    k: 'g',
                    v: gmail_token
                });
                continue;
            }

            match = token.match(/^[^\@]+\@[^\.]+\..+$/);
            if (match) {
                // email
                resource.a.push({
                    k: 'e',
                    v: token
                });
                continue;
            }

            return res.status(400).send('I don\'t understand what `' + token + '` means. You can say `@johnexample` for Twitter handle, `john@example.com` for e-mail address, or `@example.com` for e-mail domain.');
        }

        if (resource.a.length === 0)
            return res.status(400).send('At least one person allowed to access the secret must be specified.');

        var plaintext = JSON.stringify(resource);
        var iv = crypto.randomBytes(16);
        var cipher = crypto.createCipheriv('aes-256-ctr', current_keys.encryption_key, iv);
        var encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
        var signature = crypto.createHmac('sha256', current_keys.signature_key).update(encrypted).update(iv).digest('base64');
        resource =
            base64url.fromBase64(signature)
            + '.' + base64url.fromBase64(encrypted.toString('base64'))
            + '.' + base64url.fromBase64(iv.toString('base64'));

        var split_resource = version_prefix;
        for (var i = 0; i < resource.length; i++) {
            split_resource += resource[i];
            if (((i + 1) % 50) === 0)
                split_resource += '/';
        }

        res.status(200).send(split_resource);
    };
}

function v1_get() {
    return function (req, res, next) {
        res.set('Cache-Control', 'no-cache');

        logger.info({ user: req.user ? req.user._json : undefined }, 'sharelock access request');


        if (req.user && req.user.provider !== 'twitter' && !req.user._json.email_verified) {
        	console.log("hello -- req.user ", req.user);
        	console.log("done");
            return res.render('invalid', { details: 'Your e-mail has not been verified xxyyyz'});
        }

        var request_keys;
        try {
            request_keys = ensure_key(req.params[0]);
        }
        catch (e) {
            return res.render('invalid', { details: 'For security reasons this sharelock is no longer supported.'});
        }

        var resource = req.params[1].replace(/\//g, '');
        var tokens = resource.split('.');
        if (tokens.length !== 3 || tokens[0].length === 0 || tokens[1].length === 0 || tokens[2].length === 0)
            return res.render('invalid', { details: 'The URL is malformed and cannot be processed.'});

        try {
            tokens[0] = base64url.toBase64(tokens[0]); // signature
            tokens[1] = new Buffer(base64url.toBase64(tokens[1]), 'base64'); // encrypted data
            tokens[2] = new Buffer(base64url.toBase64(tokens[2]), 'base64'); // iv
            var signature = crypto.createHmac('sha256', request_keys.signature_key).update(tokens[1]).update(tokens[2]).digest('base64');
            if (!cryptiles.fixedTimeComparison(signature, tokens[0]))
                throw null;
        }
        catch (e) {
            return res.render('invalid', { details: 'Signature verification failed: the data could have been tampered with.'});
        }

        try {
            var cipher = crypto.createDecipheriv('aes-256-ctr', request_keys.encryption_key, tokens[2]);
            var plaintext = cipher.update(tokens[1], 'base64', 'utf8') + cipher.final('utf8');
            resource = JSON.parse(plaintext);
            if (!resource || typeof resource !== 'object' || typeof resource.d !== 'string'
                || !Array.isArray(resource.a))
                throw null;
        }
        catch (e) {
            return res.render('invalid', { details: 'Encrypted data is malformed.' });
        }

        var allowed;
        var email = get_email(req.user);
        var aliases = get_aliases(req.user);
        var twitter;
        var email_domains = {};
        for (var i in resource.a) {
            var acl = resource.a[i];
            if (acl.k === 'g') {
                if (email && normalize_gmail(email) === acl.v) {
                    allowed = true;
                } else {
                    email_domains[acl.v.substring(acl.v.indexOf('@'))] = 1;
                }
            }
            else if (acl.k === 'e') {
                if (email === acl.v || aliases.indexOf(acl.v) >= 0) {
                    allowed = true;
                }
                else {
                    email_domains[acl.v.substring(acl.v.indexOf('@'))] = 1;
                }
            }
            else if (acl.k === 'd') {
                if (email && email.indexOf(acl.v, email.length - acl.v.length) !== -1) {
                    allowed = true;
                }
                else {
                    email_domains[acl.v] = 1;
                }
            }
            else if (acl.k === 't') {
                if (req.user && req.user.provider === 'twitter' && req.user._json.screen_name.toLowerCase() === acl.v) {
                    allowed = true;
                }
                else {
                    twitter = true;
                }
            }

            if (allowed) break;
        }

        if (allowed) {
            var model = {
                data: resource.d,
                user: req.user,
                provider: provider_friendly_name[req.user.provider] || req.user.provider,
                logout_url: '/logout'
            };
            res.render('data', model);
        }
        else {
            email_domains = Object.getOwnPropertyNames(email_domains);
            var model = {
                auth0_client_id: process.env.AUTH0_CLIENT_ID,
                auth0_domain: process.env.AUTH0_DOMAIN,
                auth0_callback: process.env.AUTH0_CALLBACK,
                user: req.user,
                email: req.user ? get_email(req.user) : undefined,
                providers: get_provider_config(twitter, email_domains, req.user ? req.user.provider : undefined),
                allow_twitter: twitter,
                allow_domains: email_domains,
                provider: req.user ? (provider_friendly_name[req.user.provider] || req.user.provider) : undefined,
                logout_url: '/logout?r=' + req.originalUrl,
                provider_friendly_name: provider_friendly_name
            };

            req.session.bookmark = req.originalUrl;
            res.render('login', model);
        }
    };
}

var gmail_providers = ['google-oauth2', 'facebook', 'windowslive'];
var domain_provider_map = {
    '@googlemail.com': gmail_providers,
    '@gmail.com': gmail_providers,
    '@hotmail.com': ['windowslive', 'facebook'],
    '@live.com': ['windowslive', 'facebook'],
    '@outlook.com': ['windowslive', 'facebook'],
    '@msn.com': ['windowslive', 'facebook']
};

function get_provider_config(twitter, email_domains, provider) {
    var config = {
        preferred: []
    };

    if (twitter && provider !== 'twitter')
        config.preferred.push('twitter');

    email_domains.forEach(function (domain) {
        if (domain_provider_map[domain.toLowerCase()]) {
            config.preferred = config.preferred.concat(domain_provider_map[domain.toLowerCase()]);
        }
    });

    config.preferred = distinct(config.preferred);
    return config;
}

function get_aliases(user) {
    if (user && Array.isArray(user._json.aliases))
        return user._json.aliases;
    else
        return [];
}

function get_email(user) {
    if (user && (user._json.email_verified || user.provider === 'windowslive'))
        return user._json.email;
    else
        return undefined;
}

function ensure_key(key_name) {
    if (!keys[key_name]) {
        if (!process.env['SIGNATURE_KEY_' + key_name] || !process.env['ENCRYPTION_KEY_' + key_name])
            throw new Error('Cryptographic credentials are not available.');
        keys[key_name] = {
            signature_key: new Buffer(process.env['SIGNATURE_KEY_' + process.env.CURRENT_KEY], 'hex'),
            encryption_key: new Buffer(process.env['ENCRYPTION_KEY_' + process.env.CURRENT_KEY], 'hex')
        };
    }
    return keys[key_name];
}

function distinct(source) {
    var u = {}, a = [];
   for(var i = 0, l = source.length; i < l; ++i){
      if(u.hasOwnProperty(source[i])) {
         continue;
      }
      a.push(source[i]);
      u[source[i]] = 1;
   }

   return a;
}

function contextualLocals(req, res, next) {
    res.locals = res.locals || {};
    res.locals.context = res.locals.context || {};
    res.locals.context.protocol = req.protocol;
    res.locals.context.path = req.path;
    res.locals.context.url = req.url;
    res.locals.context.hostname = req.hostname;
    next();
}

module.exports = app;
