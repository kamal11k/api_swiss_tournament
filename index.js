const express = require("express");
const app = express();
const bodyParser = require("body-parser");
const morgan = require('morgan');
let port = process.env.PORT || 8000;
const mysql = require("mysql");
const passport = require('passport');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const jwt = require('jsonwebtoken');

// Router requires
const dbconfig = require('./config/dbconfig');
const player_route = require('./api/routes/player_routes');
const tour_route = require('./api/routes/tour_routes');

const connection = mysql.createConnection(dbconfig.connection);
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(morgan('dev'));

let jwtOpts = {};
jwtOpts.jwtFromRequest = ExtractJwt.fromAuthHeader();
jwtOpts.secretOrKey = 'Kamal-Rabindra';

//passport strategy for jwt
let strategy = new JwtStrategy(jwtOpts, (jwt_payload, cb)=>{
    let stmt = "select * from user where id = ?";
    let id = jwt_payload.id;
    connection.query(stmt, id, (error, result) => {
        if(error){
            throw error;
        }
        if(result){
            var userinfo = {
                email: result[0].email,
                id: result[0].id
            }
            cb(null, userinfo);
        }
        else{
            cb(null, false);
        }
    })
})


passport.use(strategy);
app.use(passport.initialize());


app.post('/login', (req, res)=>{

    let email = req.body.email;
    let password = req.body.password;
    if(!email){
        res.status(400).json('email required');
    }
    else if(!password){
        res.status(400).json("password required");
    }

    var stmt = "SELECT * from user where email = ? ";
    connection.query(stmt, [email], (error, results)=>{
        if(error){
            throw error;
        }
        if(!results.length){
            res.status(401).json("No user registered with this email");
        }
        else if(password !== results[0].password){
            res.status(400).json("Invalid password");
        }
        else{
            let payload = {
                email,
                id: results[0].id,
            };
            let token = jwt.sign(payload, jwtOpts.secretOrKey);
            res.status(200).json({message:"Success",token: token});
        }
    })

})

app.post('/signup',(req, res)=>{
    var stmt = "SELECT * from user where email = ? ";
     connection.query(stmt, [email], (error, results)=>{
        if(error){
            throw error;
        }
        if(results.length){
            res.json("User already exists");
        }
        else{
            var email = req.body.email;
            var password = req.body.password;
            var username = req.body.password;
            var insertQuery = "INSERT INTO user ( username,password,email) values (?,?,?)";
            connection.query(insertQuery,[username, password, email], (error, result)=>{
                res.status(200).json("Successfully registered");
            })
        }
     })
})

app.get('/', passport.authenticate('jwt', {session: false}), (req, res) => {
    res.json("hello");
})

// app.use('/tournament',passport.authenticate('jwt', {session: false}), tour_route);

// app.use('/player',passport.authenticate('jwt', {session: false}), player_route);
app.listen(port, ()=>{
    console.log("local host is running");
})
