import jwt from 'jsonwebtoken';
import path from "path";
import { fileURLToPath } from "url";
import dotenv from "dotenv";
const __dirname = path.dirname(fileURLToPath(import.meta.url));

dotenv.config({ path: path.join(__dirname, "../.env") });
function verifyToken(req, res, next) {
  if (
    req.headers.authorization &&
    req.headers.authorization.split(' ')[0] === 'Bearer'
  ) {
    const decoded = 
    jwt.verify(
      req.headers.authorization.split(' ')[1],
      '2c7907f7311afea77350f88292059910fbcd907f57c9d9c19d15fe37c4cc8e3b',
    );
  } else {
    return res.status(401).json({
      error: true,
      status: 401,
      message: 'Please provide token',
    });
  }
}
export default verifyToken;