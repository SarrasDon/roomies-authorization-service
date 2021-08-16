import { compare } from "bcryptjs";
import createHttpError from "http-errors";
import { ObjectId } from "mongoDb";
import {
  createRefreshTokenCookie,
  createSignedToken,
  hashToken,
} from "../handlers-helpers";
import { commonMiddleware } from "../middlewares";

async function refresh(event, context) {
  context.callbackWaitsForEmptyEventLoop = false;
  const { body, requestContext, headers } = event;

  const { user } = body;
  const { domainName } = requestContext;
  const { cookie } = headers;

  const tokens = cookie ? cookie.split("refreshToken=") : [];
  for (let token of tokens) {
    if (token.endsWith(";")) {
      token = token.slice(0, -1);
    }
  }

  const refreshToken = tokens.slice(-1)[0];

  if (!user || !refreshToken) {
    throw new createHttpError.Unauthorized("No user or token found");
  }

  const { email, _id } = user;
  const { db } = context;

  let tokenDb = null;
  try {
    tokenDb = await db.collection("refreshtokens").findOne({
      person: ObjectId(_id),
    });
  } catch (error) {
    console.error(error);
    throw new createHttpError.InternalServerError(
      "Error while getting refresh token of user!"
    );
  }

  if (!tokenDb || !tokenDb.token) {
    throw new createHttpError.Unauthorized("No tokenDb or tokenDb.token!");
  }

  let result = null;
  try {
    result = await compare(refreshToken, tokenDb.token.toString());
  } catch (error) {
    console.error(error);
    throw new createHttpError.InternalServerError("Comparison error!");
  }

  if (!result) {
    throw new createHttpError.Unauthorized("Tokens dont match");
  }

  const access_token = createSignedToken(email, _id);
  const refresh_token = createSignedToken(user, _id, 7 * 24 * 60 * 60);

  const hashed = await hashToken(refresh_token);

  try {
    await db
      .collection("refreshtokens")
      .updateOne(
        { person: ObjectId(_id) },
        { $set: { token: hashed, person: ObjectId(_id) } },
        { new: true, upsert: true }
      );
  } catch (error) {
    console.error(error);
    throw new createHttpError.InternalServerError(
      "Error while updating token of user!"
    );
  }

  const cookieString = createRefreshTokenCookie(refresh_token, domainName);

  return {
    statusCode: 201,
    headers: {
      "Set-Cookie": cookieString,
    },
    body: JSON.stringify({ user, access_token }),
  };
}

export const handler = commonMiddleware(refresh);
