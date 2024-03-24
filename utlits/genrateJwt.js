import jwt from "jsonwebtoken";
import path from "path";
import { fileURLToPath } from "url";
import dotenv from "dotenv";
const __dirname = path.dirname(fileURLToPath(import.meta.url));

dotenv.config({ path: path.join(__dirname, "../.env") });
console.log(process.env.JWT_SECRET_KEY);
export default (payload) => {
    const token =  jwt.sign(
        payload,
        process.env.JWT_SECRET_KEY,{expiresIn: '10h'} );
        return token;

}