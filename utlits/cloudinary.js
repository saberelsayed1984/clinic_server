import cloudinary from 'cloudinary';
import dotenv from 'dotenv';

dotenv.config();

cloudinary.config({
    cloud_name: 'dqz8cwkra',
    api_key: '325158755357776',
    api_secret: 'kwvEOdrfzcjCKxhFmMgUak458A8',
    });

    const cloudinaryUploadImage = async (fileToUpload) => {
    try {
        const data = await cloudinary.uploader
        .upload(fileToUpload, {
        resource_type: 'auto',
        });
        return data;
    } catch (error) {
        return error;
    }
    };

    const cloudinaryRemoveImage = async (imagePublicId) => {
    try {
        const result = await cloudinary.uploader
        .destroy(imagePublicId);
        return result;
    } catch (error) {
        throw error;
    }
};

export { cloudinaryUploadImage as cloudinaryUploadImage, cloudinaryRemoveImage as cloudinaryRemoveImage };