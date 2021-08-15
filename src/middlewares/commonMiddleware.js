import middy from '@middy/core';
import cors from '@middy/http-cors';
import httpErrorHandler from '@middy/http-error-handler';
import httpHeaderNormalizer from '@middy/http-header-normalizer';
import jsonBodyParser from '@middy/http-json-body-parser';
import withDbConnection from './withDbConnection';

const commonMiddleware = (handler) => {
  return middy(handler)
    .use(jsonBodyParser())
    .use(httpHeaderNormalizer())
    .use(withDbConnection())
    .use(cors(
      {
        origins: [
          'https://roomies.netlify.app',
          'https://roomies.netlify.com',
          'https://roomies.netlify.app/',
          'https://roomies.netlify.com/',
          'http://localhost:4200',
        ],
        credentials: true,
      }
    ))
    .use(httpErrorHandler());
};

export default commonMiddleware;