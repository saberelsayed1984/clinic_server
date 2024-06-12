import User from './models/userModel.js';
import httpStatusText from './utlits/httpStatus.js';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import genrateJwt from './utlits/genrateJwt.js';
import nodemailer from "nodemailer";
import Joi from "joi";
import emailValidator from 'email-validator';
import validator from 'validator';
import { token } from 'morgan';
import path from "path";
import multer from "multer";
import cloudinary from 'cloudinary';
import fs from "fs";
import {cloudinaryUploadImage,cloudinaryRemoveImage} from "./utlits/cloudinary.js";
import { error } from 'console';
import { create } from 'domain';
const __filename = path.basename(import.meta.url);
const __dirname = path.dirname(__filename);// console.log(__dirname);
export async function uplodePhoto(req, res) {
    const userId = req.params.id;
    const user = await User.findById(userId);

    if (!user) {
        return res.status(404).json({ msg: "User not found" });
    }


    if (!req.file) {
        return res.status(400).json({ msg: "File provided" });
    }

    const imagePath = path.join(__dirname, `./image/${req.file.filename}`);

    const result = await cloudinaryUploadImage(imagePath);
    if (user.profilePhoto && user.profilePhoto.publicId !== null) {
        await cloudinaryRemoveImage(user.profilePhoto.publicId);
    }

    user.profilePhoto = {
        url: result.secure_url,
        publicId: result.public_id,
    }; 

    await user.save(); 
    res.status(200).json({
        msg: "successfully Upload",
        profilePhoto: { url: result.secure_url, publicId: result.public_id },
    });

    fs.unlinkSync(imagePath);
}
export async function register(req, res, next)  {
    const { Name, email, password , confirmPassword } = req.body;
    const oldUser = await User.findOne({ email: email });
    
    if (oldUser) {
        return res.status(400).json({ msg: "User already exists" });

    }
    const userName = await User.findOne({Name: Name});
        if (userName) {
            return res.status(400).send( {msg:'The name is already in use.'});
        } 

{ 
    async function isconfirmPasswordValid(confirmPassword){
if (validator.isEmpty(confirmPassword)) {
    return { valid: false, msg: 'confirmPassword is required' };
    }

    if(password != confirmPassword )
    {
        return { valid: false, msg:'Your passwords donot match. please enter your password again to confirm it.'};
    }
    else{ return { valid: true }};
}
let { valid, msg } = await isconfirmPasswordValid(confirmPassword);    
        if (!valid) {return res.status(400).send({ msg })};
    }

    
{
async function isNameValid(Name)
{
if (validator.isEmpty(Name)) {
    return { valid: false, msg: 'Name is required' };
    }
    const length = validator.isLength(Name,3)
    if(!length){
    return { valid: false, msg: 'Name must be greater than 3 character ' };
    }
    else{ return { valid: true };
}} 
let { valid, msg } = await isNameValid(Name);    
    if (!valid) {return res.status(400).send({ msg })};

}  
{ async function isPasswordValid(password)
{
if (validator.isEmpty(password)) {
    return { valid: false, msg: 'Password is required' };
    }
    const length = validator.isLength(password,8)
    if(!length){
    return { valid: false, msg: 'Password must be greater than 8 character ' };
    }
    if (!validator.isStrongPassword(password))
    return {valid:false,msg:"Password must be a strong password..You should write:-(A combination of uppercase letters,lowercase letters,numbers,and symbols.)"};
    

    return { valid: true };
} 
let { valid, msg } = await isPasswordValid(password);    
    if (!valid) {return res.status(400).send({ msg })};
}
{ async function isEmailValid(email) {

    if (validator.isEmpty(email)) {
        return { valid: false, msg: 'Email is required' };
        }
    const isValid = emailValidator.validate(email);
    if (!isValid) {
        return { valid: false,msg: 'Enter a valid email address.' };
    }
    const emailParts = email.split('@');
    if (emailParts.length !== 2 || emailParts[1] !== 'gmail.com') {
        return { valid: false, msg: 'Only gmail addresses are allowed' };
    }
    return { valid: true };
    } 
    const { valid, msg } = await isEmailValid(email);    
if (!valid) {return res.status(400).send({msg })};
}
    

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({
        Name,
        email,
        password: hashedPassword,
        token : bcrypt
    }); 

    const token = await genrateJwt({email: newUser.email, id: newUser._id})
    newUser.token = token;
    await newUser.save();
    const mail = "saberelsayed1984@gmail.com" ;
    const pass ="izedhgpgnukwgpsn";
    const link = 
    `https://clinicserver-production.up.railway.app/api/users/verifyEmail/${newUser._id}/${token}`;
    const transporter = nodemailer.createTransport({
        service: "gmail",
        auth: {
            user: mail ,
            pass: pass
        }
    });
    const mailOption = {
        from: '"Medi Team"<team62024@outlook.com>',
        to: email,
        subject: "Verify email...",
        text: `Please click on the following link to verify email... : ${link}`
    }
    transporter.sendMail(mailOption, (error , success) =>{
        if (error){
            console.log(error);
        }else{
            console.log("Email was sent: " + success.response)
        }
    
    }); 
    res.send({msg : 'register sucessfully... please check your email to verify your account. '} )
};

export async function verifyEmail(req,res,next) {
    try{
        const user = await User.findById(req.params.userId);
        if (!user) {
            return res.status(404).send( {msg:'invalid link'});
        } 
        const Token = await genrateJwt({email: user.email, id: user._id})
        if(!Token){
            return res.status(404).send( {msg:'invalid link'});
        }
        await user.updateOne({ Verified : true });

    res.json({ status: httpStatusText.SUCCESS,msg: "email verified sucessfully"});
    }
    catch (error) {
    res.json(error.message).status(500);

    }
}
export async function login(req, res, next)  {
    
    const { email, password } = req.body;

    if (!email && !password) {
        return res.status(400).json({ msg: "Email or Password is required" });
        
    }

    const user = await User.findOne({ email: email });

    if (!user) {
        return res.status(400).json({  msg: "User Not Found" });

    }

{ async function isEmailValid(email) {

    if (validator.isEmpty(email)) {
        return { valid: false, msg: 'Email is required' };
        }
    const isValid = emailValidator.validate(email);
    if (!isValid) {
        return { valid: false,msg: 'Enter a valid email address.' };
    }
    const emailParts = email.split('@');
    if (emailParts.length !== 2 || emailParts[1] !== 'gmail.com') {
        return { valid: false, msg: 'Only gmail addresses are allowed' };
    }
    return { valid: true };
    } 
    const { valid, msg } = await isEmailValid(email);    
if (!valid) {return res.status(400).send({msg })};
}

if(!user.Verified){
    return res.status(400).json({  msg: " An Email was sent to your account please verify " });
}
    const matchedPassword = await bcrypt.compare(password, user.password);

    if (user && matchedPassword) {
        const token = await genrateJwt({email: user.email, id: user._id})
        await User.updateOne({_id:user._id }, {$set:{token}})
        user.token = token
        return res.json({ status: httpStatusText.SUCCESS,  msg: "The success of the login process" ,  _id: user._id, name: user.Name, email : user.email ,token : user.token,profilePhoto: user.profilePhoto.url
    });
    } else {
        
        return res.status(500).json({ msg: "The password is incorrect" });

    }
};
export async function update(req, res)  {
    const userId = req.params.userId; 
    const { Name } = req.body;
    {
        async function isNameValid(Name)
    {
        if (validator.isEmpty(Name)) {
            return { valid: false, msg: 'Name is required' };
        }
        const length = validator.isLength(Name,3)
        if(!length){
        return { valid: false, msg: 'Name must be greater than 3 character ' };
        }
        else{ return { valid: true };
    }} 
    let { valid, msg } = await isNameValid(Name);    
            if (!valid) {return res.status(400).send({ msg })};
    
        }  
    const userName = await User.findOne({Name: Name});
    if (userName) {
        return res.status(400).send( {msg:'The name is already in use.'});
    } 
    await User.updateOne({_id: userId}, {$set:{...req.body}});
    return res.status(200).json({status: httpStatusText.SUCCESS,  msg:"update succesfully" })
    };
export async function deleteUser(req, res) {
        await User.deleteOne ({_id: req.params.userId});
        res.status(200).json({status: httpStatusText.SUCCESS,  msg: null});
    };

export async function forgotPassword(req, res, next) {
        const { error } = Joi.object({
            email: Joi.string().email().required()
        }).validate(req.body);
        if (error) {
            return res.status(400).send({msg:'Enter a valid email address.'});
        }   
let email = req.body.email;
        { async function isEmailValid(email) {

        if (validator.isEmpty(email)) {
            return { valid: false, msg: 'Email is required' };
            }
        const isValid = emailValidator.validate(email);
        if (!isValid) {
            return { valid: false,msg: 'Enter a valid email address.' };
        }
        const emailParts = email.split('@');
        if (emailParts.length !== 2 || emailParts[1] !== 'gmail.com') {
            return { valid: false, msg: 'Only gmail addresses are allowed' };
        }
        return { valid: true };
        } 
        const { valid, msg } = await isEmailValid(email);    
    if (!valid) {return res.status(400).send({msg })};
    }const user = await User.findOne({email: req.body.email});
    if (!user) {
        return res.status(404).send( {msg:'User not found'});
        }
    const secret = '2c7907f7311afea77350f88292059910fbcd907f57c9d9c19d15fe37c4cc8e3b' + user.password;
    const token = jwt.sign({ email: user.email, id: user.id}, secret, {
        expiresIn: '60m'
    });
    const link = `https://clinicserver-production.up.railway.app/password/resetpassword/${user._id}/${token}`;

    const mail = "saberelsayed1984@gmail.com" ;
    const pass ="izedhgpgnukwgpsn";
    const transporter = nodemailer.createTransport({
        service: "gmail",
        auth: {
            user: mail,
            pass: pass,
        }
    });
    const mailOption = {
        from: '"Medi Team"<team62024@outlook.com>',
        to: user.email,
        subject: "Reset your password",
        text: `Please click on the following link to reset your password: ${link}`
    }
    transporter.sendMail(mailOption, (error , success) =>{
        if (error){
            console.log(error);
        }else{
            console.log("email was sent: " + success.response)
        }
    
    });

    res.send({msg : 'check mail... '} )
    }

export async function getResetPassword(req, res, next) {
    const user = await User.findById(req.params.userId);
    if (!user) {
        return res.status(404).send( {msg:'User not found'});

    }
const secret = '2c7907f7311afea77350f88292059910fbcd907f57c9d9c19d15fe37c4cc8e3b' + user.password;
try {
    jwt.verify(req.params.token, secret);
    res.render('reset-password.ejs',{email: user.email})
} catch (error) {
    res.json(error.message).status(403)
}
;}
export async function resetPassword(req, res, next) {
    const user = await User.findById(req.params.userId);
    const password = req.body.password;
    if (!user) {
        return res.status(404).send( {msg:'User not found'});

    }
    { async function isPasswordValid(password)
        {
            if (validator.isEmpty(password)) {
                return { valid: false, msg: 'Password is required' };
            }
            const length = validator.isLength(password,8)
            if(!length){
            return { valid: false, msg: '<h1>Password must be greater than 8 character</h1> ' };
            }
            if (!validator.isStrongPassword(password))
            return {valid:false,msg:"<h1>Password must be a strong password..You should write:-(A combination of uppercase letters,lowercase letters,numbers,and symbols.)</h1>"};
            
            
        
            return { valid: true };
        } 
        let { valid, msg } = await isPasswordValid(password);    
                if (!valid) {return res.status(400).render('error-pass.ejs')};
const secret = '2c7907f7311afea77350f88292059910fbcd907f57c9d9c19d15fe37c4cc8e3b' + user.password;
try {
    jwt.verify(req.params.token, secret);
    const salt = await bcrypt.genSalt(10);
    req.body.password = await bcrypt.hash(req.body.password, salt);
    user.password = req.body.password;
    await user.save();
    res.render('success-password.ejs');
} catch (error) {
    res.json(error.message).status(403)
}}}
export async function newPassword(req, res) {
    const user = await User.findById(req.params.userId);
    
    if (!user) {
        return res.status(404).json({ msg: 'User not found' });
    }
    
    const { oldPassword, password} = req.body;
    
    if (!oldPassword || !password ) {
        return res.status(400).json({ msg: 'Old password, new password is missing in the request body' });
    }

    const isPasswordMatch = await bcrypt.compare(oldPassword, user.password);
    
    if (!isPasswordMatch) {
        return res.status(401).json({ match: false, msg: 'Old password does not match ' });
    }

    function isPasswordValid(password) {
        if (validator.isEmpty(password)) {
            return { valid: false, msg: 'Password is required' };
        }
        if (!validator.isLength(password, { min: 8 })) {
            return { valid: false, msg: 'Password must be at least 8 characters long' };
        }
        if (!validator.isStrongPassword(password)) {
            return { valid: false, msg: 'Password must be a strong password (uppercase, lowercase, numbers, symbols)' };
        }
        return { valid: true };
    }

    const { valid, msg } = isPasswordValid(password);

    if (!valid) {
        return res.status(400).json({ msg: msg });
    }
// const secret = process.env.JWT_SECRET_KEY + user.password;
try {
    // jwt.verify(req.params.token, secret);
    const salt = await bcrypt.genSalt(10);
    req.body.password = await bcrypt.hash(req.body.password, salt);
    user.password = req.body.password;
    await user.save();
    res.json('success reset password');
} catch (error) {
    res.json(error.message).status(403)
}}