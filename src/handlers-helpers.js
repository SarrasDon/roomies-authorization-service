import { sign } from "jsonwebtoken";
import { hash } from "bcryptjs";

import { AUTH_SECRET, BCRYPT_SALT } from "./config";

export const createSignedToken = (payload, sub, expiresIn = 3600) => {
  return sign({ payload, sub }, AUTH_SECRET, { expiresIn });
};

export const hashToken = async (token) => {
  return await hash(token, BCRYPT_SALT);
};

export const createRefreshTokenCookie = (refresh_token, domainName) => {
  return `refreshToken=${refresh_token}; SameSite=None; Secure; HttpOnly; Max-Age=${
    7 * 24 * 60 * 60 * 1000
  }; Domain=${domainName}; Path=/`;
};
