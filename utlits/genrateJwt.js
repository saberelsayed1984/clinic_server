import jwt from "jsonwebtoken";
import path from "path";
import { fileURLToPath } from "url";
import dotenv from "dotenv";
const __dirname = path.dirname(fileURLToPath(import.meta.url));

dotenv.config({ path: path.join(__dirname, "../.env") });
export default (payload) => {
    const token =  jwt.sign(
        payload,
        '2c7907f7311afea77350f88292059910fbcd907f57c9d9c19d15fe37c4cc8e3b',{expiresIn: '60m'} );
        return token;

}