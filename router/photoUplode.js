import path from "path";
import multer from "multer";

const __filename = path.basename(import.meta.url);
const __dirname = path.dirname(__filename);
console.log(__dirname);

const photoStorage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, path.join(__dirname, "image"));
    },
    filename: function (req, file, cb) {
        if (file) {
            cb(null, new Date().toISOString().replace(/:/g, "-") + file.originalname);
        } else {
            cb(null, false);
        }
    },
});

const photoUpload = multer({
    storage: photoStorage,
    fileFilter: function (req, file, cb) {
        if (file.originalname.match(/\.(jpg|png|PNG|jpeg)$/)) {
            cb(null, true);
        } else {
            cb({ message: "unsupported file format" }, false);
        }
    },
    limits: { fileSize: 1024 * 1024 * 5 },
});

export default photoUpload;
