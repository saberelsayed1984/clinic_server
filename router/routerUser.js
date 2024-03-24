import express from 'express';
import * as userControllr from '../controllers/userControllr.js';
import verifyToken from '../models/verifyToken.js';
import passport from 'passport';
import photoUplode from './photoUplode.js';

const router = express.Router();
router.route('/register')
        .post(userControllr.register);
router.post('/uplodePhoto/:id', photoUplode.single("image"), userControllr.uplodePhoto);
router.route('/login')
        .post( userControllr.login);
router.route('/forgotpassword')
        .post( userControllr.forgotPassword);
router.route('/resetpassword/:userId/:token')
        .get(userControllr.getResetPassword)
        .post(userControllr.resetPassword);        
router.route('/:userId')
        .put(userControllr.update);
router.route('/:userId')
        .delete(userControllr.deleteUser)    
router.get("/google",  passport.authenticate("google",{scope:["email","profile"]}))
router.get("/google/callback", passport.authenticate("google"), userControllr.callback)
export default router;


