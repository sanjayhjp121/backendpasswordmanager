require("dotenv").config();
const express = require("express");
const http = require("http");
const https = require("https");
const helmet = require("helmet");
const cors = require("cors");
const morgan = require("morgan");
const passport = require("passport");
const useragent = require('useragent');
const expressIp = require('express-ip');
const geoip = require('geoip-lite');var fileUpload = require('express-fileupload');
const initMongo = require("./app/config/mongo")
const userRoutes = require('./app/routes/user');
const adminRoutes = require('./app/routes/admin');
const memberRoutes = require('./app/routes/members')
var fs = require("fs");
const app = express();
 


let server = http.createServer(app);
app.use(helmet());


const corsOptions = {
    "origin": "*",
    "methods": "GET,HEAD,PUT,PATCH,POST,DELETE",
    "preflightContinue": false,
    "optionsSuccessStatus": 204,
    "allowedHeaders": 'Content-Type, Authorization'
}

app.use(cors());
app.options('*', cors(corsOptions)); 
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(
    morgan(":method :url :status :response-time ms - :res[content-length]")
);

app.use(passport.initialize());
app.use(fileUpload());
app.use(expressIp().getIpInfoMiddleware);

// Middleware to set request start time
app.use((req, res, next) => {
    req.startTime = Date.now();
    next();
});

app.set('trust proxy', true);

app.use('/user', userRoutes) // admin routes
app.use('/admin', adminRoutes) // superadmin routes
app.use('/member', memberRoutes) // user routes


app.use((req, res, next) => {
    const error = {
        message: "Route not found",
        status: 404,
        timestamp: new Date(),
    };
    res.status(404).json({ error });
});


app.use((err, req, res, next) => {
    console.error(err.stack);
    const status = err.status || 500;
    res.status(status).json({ error: err.message || "Internal Server Error" });
});

// app.use(cors());
// app.options('*', cors(corsOptions)); 

server.listen(process.env.PORT || 5002, () => {
    console.log("****************************");
    console.log(
        `*    Starting ${process.env.ENV === "local" ? "HTTP" : "HTTPS"
        } Server`
    );
    console.log(`*    Port: ${process.env.PORT || 5000}`);
    console.log(`*    NODE_ENV: ${process.env.NODE_ENV}`);
    console.log(`*    Database: MongoDB`);
    console.log(`*    DB Connection: OK\n****************************\n`);
});

initMongo()