export const { MONGODB_URI, AUTH_SECRET, BCRYPT_SALT: saltString } = process.env;

export const BCRYPT_SALT = Number(saltString);