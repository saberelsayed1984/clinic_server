import passport from 'passport';
import User from '../models/userModel.js';
import httpStatusText from '../utlits/httpStatus.js';
import AppError from '../utlits/appError.js';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import genrateJwt from '../utlits/genrateJwt.js';
import nodemailer from "nodemailer";
import Joi from "joi";
import { token } from 'morgan';
import path from "path";
import multer from "multer";
import cloudinary from 'cloudinary';
import fs from "fs";
import {cloudinaryUploadImage,cloudinaryRemoveImage} from "../utlits/cloudinary.js";
const __filename = path.basename(import.meta.url);
const __dirname = path.dirname(__filename);

export async function uplodePhoto(req, res) {
    const userId = req.params.id;
    const user = await User.findById(userId);
    if (!user) {
        return res.status(404).json({ error: "User not found" });
    }

    if (!req.file) {
        return res.status(400).json({ error: "file provided" });
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

    await user.save(); // Save the user's changes first

    res.status(200).json({
        error: false,
        message: "successfully Upload",
        profilePhoto: { url: result.secure_url, publicId: result.public_id },
    });

    fs.unlinkSync(imagePath);
}
export async function register(req, res, next)  {
    const { Name, email, password } = req.body;
    const oldUser = await User.findOne({ email: email });
    
    if (oldUser) {
        const error = AppError.create('user Already exists', 400, httpStatusText.FAIL);
        return next(error);
    }
    
    // password hashing by bcrypt package
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const newUser = new User({
        Name,
        email,
        password: hashedPassword
    });
    const token = await genrateJwt({email: newUser.email, id: newUser._id})
    newUser.token = token;
    await newUser.save();
    
    res.json({ status: httpStatusText.SUCCESS, data: { user: newUser } });
};
export async function login(req, res, next)  {
    
    const { email, password } = req.body;

    if (!email && !password) {
        const error = AppError.create('email and password are required', 400, httpStatusText.FAIL);
        return next(error);
    }

    const user = await User.findOne({ email: email });

    if (!user) {
        const error = AppError.create('user not found', 400, httpStatusText.FAIL);
        return next(error);
    }

    const matchedPassword = await bcrypt.compare(password, user.password);

    if (user && matchedPassword) {
        const token = await genrateJwt({email: user.email, id: user._id})
        await User.updateOne({_id:user._id }, {$set:{token}})
        user.token = token
        return res.json({ status: httpStatusText.SUCCESS, data: {user} });
    } else {
        const error = AppError.create('something wrong', 500, httpStatusText.ERROR);
        return next(error);
    }
};
export async function update(req, res)  {
    const userId = req.params.userId; 
    const updateUser = await User.updateOne({_id: userId}, {$set:{...req.body}});
    return res.status(200).json({status: httpStatusText.SUCCESS, data:{updateUser}})};
export async function deleteUser(req, res) {
        await User.deleteOne ({_id: req.params.userId});
        res.status(200).json({status: httpStatusText.SUCCESS, data: null});
    };
export async function forgotPassword(req, res, next) {
        const { error } = Joi.object({
            email: Joi.string().email().required()
        }).validate(req.body);
        if (error) {
            return res.status(400).send(error.details[0].message);
        }   
        const user = await User.findOne({email: req.body.email});
        if (!user) {
            return res.status(404).send('User not found');
        }
    const secret = process.env.JWT_SECRET_KEY + user.password;
    const token = jwt.sign({ email: user.email, id: user.id}, secret, {
        expiresIn: '60m'
    });
    const link = 
    `http://localhost:5000/api/users/resetpassword/${user._id}/${token}`;
    
    const transporter = nodemailer.createTransport({
        service: "gmail",
        auth: {
            user: process.env.ADMIN_EMAIL,
            pass: process.env.USER_PASS
        }
    });
    const mailOption = {
        from: process.env.ADMIN_EMAIL,
        to: user.email,
        subject: "reset password",
        text: `Please click on the following link to reset your password: ${link}`
    }
    transporter.sendMail(mailOption, (error , success) =>{
        if (error){
            console.log(error);
        }else{
            console.log("email sent: " + success.response)
        }
    
    });
    res.send("link_sned")
    }
export async function getResetPassword(req, res, next) {
    const user = await User.findById(req.params.userId);
    if (!user) {
        const error = AppError.create('user not found', 400, httpStatusText.FAIL);
        return next(error);
    }
const secret = process.env.JWT_SECRET_KEY + user.password;
try {
    jwt.verify(req.params.token, secret);
    res.status(200).send({email: user.email, message: 'reset password'});
} catch (error) {
    console.log(error)
    res.json(error.message).status(403)
}
;}
export async function resetPassword(req, res, next) {
    const user = await User.findById(req.params.userId);
    if (!user) {
        const error = AppError.create('user not found', 400, httpStatusText.FAIL);
        return next(error);
    }
const secret = process.env.JWT_SECRET_KEY + user.password;
try {
    jwt.verify(req.params.token, secret);
    const salt = await bcrypt.genSalt(10);
    req.body.password = await bcrypt.hash(req.body.password, salt);
    user.password = req.body.password;
    await user.save();
    res.send('success new password');
} catch (error) {
    console.log(error)
    res.json(error.message).status(403)
}
}
export async function callback(req, res) {
        if (req.user) {
            console.log(req.user._json);
            res.status(200).json({
                error: false,
                message: "successfully loged in",
                user: req.user,
            });
        } else {
            res.status(403).json({ error: true, message: "not authorized" });
        }
        }