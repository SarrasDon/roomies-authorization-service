import { compare } from "bcryptjs";
import createHttpError from "http-errors";
import { ObjectId } from "mongoDb";
import {
  createRefreshTokenCookie,
  createSignedToken,
  hashToken,
} from "../handlers-helpers";
import { commonMiddleware } from "../middlewares";

async function login(event, context) {
  context.callbackWaitsForEmptyEventLoop = false;
  const { body, requestContext } = event;
  const { email, password } = body;

  const { domainName } = requestContext;

  if (!email) {
    throw new createHttpError.BadRequest("No email provided!");
  }

  if (!password) {
    throw new createHttpError.BadRequest("No password provided!");
  }

  const { db } = context;

  let user = null;
  try {
    user = await db.collection("users").findOne({ email });
  } catch (error) {
    console.error(error);
    throw new createHttpError[500]("Error while getting user!");
  }

  if (!user || !user.password) {
    console.error("No such user!", email, password);
    throw new createHttpError.Unauthorized("No such user!");
  }

  let result = null;
  try {
    result = await compare(password, user.password.toString());
  } catch (error) {
    console.error(error);
    throw new createHttpError.InternalServerError("Compare failed!");
  }

  if (!result) {
    throw new createHttpError.Unauthorized("No user for that password!");
  }

  const { _id } = user;
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
  delete user.password;

  return {
    statusCode: 201,
    headers: {
      "Set-Cookie": cookieString,
    },
    body: JSON.stringify({ user, access_token }),
  };
}

export const handler = commonMiddleware(login);
