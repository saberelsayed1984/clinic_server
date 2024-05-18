import express from 'express'
import morgan from 'morgan'
import cors from 'cors'
import bodyParser from 'body-parser' 
import { config } from 'dotenv'
import path from "path"
import router from './router/route.js'
import connect from './dataBase/connect.js'
import routerUser from './router/routerUser.js'
import passport from 'passport';
import * as passport_st from './controllers/passport.js'
import  Session  from 'express-session';
import ejs from "ejs";
const app = express()
app.set('viwe engine', 'ejs');
// app.use(fileUpload());
// app.use(
//     Session({
//         secret: "how are you ?",
//         resave: false,
//     saveUninitialized: true,
//     cookie: { secure: true }
//     })
// );
// app.use(morgan('tiny'))
app.use(cors({
    origin: "*",
    methods: "GET,POST,PUT,DELETE,",
    Credential: true,
}))
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.urlencoded({ extended: true }))

app.use(express.json())
config()
app.use('/api/users', routerUser)
app.use('/password', routerUser)
// app.use(passport.initialize())
// app.use(passport.session())
app.get('/', (req, res) => {
    app.use((error, req, res, next) => {
        res.status(error.statusCode || 500).json({status: error.statusText || httpStatusText.ERROR,
            message:error.message, code: error.statusCode || 500, data: null})
        });})
connect().then(() => {
    try {
        app.listen(port, () => {
            console.log(`server connected to http://localhost:${port}`)
        })
    }
    catch (error) {
        console.log("cannot connect to the server") 
    } }).catch(error => {
        console.log("Invalid Database connection")
    })
const port = process.env.PORT;
