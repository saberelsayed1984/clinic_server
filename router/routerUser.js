import express from 'express';
import * as userControllr from '../userControllr.js';
import verifyToken from '../models/verifyToken.js';
import passport from 'passport';
import photoUpload from './photoUplode.js';

const router = express.Router();
router.route('/forgot-password')
        .post(userControllr.forgotPassword)
router.route('/register')
        .post(userControllr.register);
router.route('/verifyEmail/:userId/:token')
        .get(userControllr.verifyEmail);
router.post('/uplodePhoto/:id', photoUpload.single('image'), userControllr.uplodePhoto);
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
        .post(userControllr.newPassword);
router.route('/:userId')
        .delete(userControllr.deleteUser)    
// router.get("/google",  passport.authenticate("google",{scope:["email","profile"]}))
// router.get("/google/callback", passport.authenticate("google"), userControllr.callback)
export default router;


