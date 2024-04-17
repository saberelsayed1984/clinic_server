import { Router } from "express";
import { body } from 'express-validator';
import verifyToken from '../models/verifyToken.js';

const router = Router();
import *  as controller from '../controllers/controller.js';
router.route('/medical-consultation/diabetes')
        .post( body() ,controller.postDiabetes);
router.route('/medical-consultation/heart')
        .post( body(), controller.postHeart);
router.route('/medical-consultation/cancer')
        .post( body(), controller.postCancer);
router.route('/medical-consultation/parkinson')
        .post( body(), controller.postParkinson);
export default router;
