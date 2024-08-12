const jwt = require('jsonwebtoken');
const httpStatus = require('http-status');
const userModel = require('../modules/users/user.model');

const decodeToken = (authorization) => {
  try {
    const token = authorization.split(' ')[1];
    return jwt.verify(token, process.env.JWT_SECRET);
  } catch (error) {
    return null;
  }
};

const getUser = async (userId) => {
  try {
    return await userModel.findById(userId).lean();
  } catch (error) {
    return null;
  }
};

const handleUnauthorizedAccess = (res) => {
  return res
    .status(httpStatus.UNAUTHORIZED)
    .json({ success: false, message: 'Unauthorized access' });
};

const verifyUser = async (req, res, next) => {
  if (req.headers.authorization === undefined) {
    return handleUnauthorizedAccess(res);
  }
  let decodedResult = decodeToken(req.headers.authorization);
  if (decodedResult == null || decodedResult == undefined)
    return handleUnauthorizedAccess(res);

  let userData = await getUser(decodedResult.userId);
  if (userData == null) return handleUnauthorizedAccess(res);
  req.user = userData;
  next();
};

const verifyAuthorization = (req, res, next) => {
  const role = req.user.role
  if (role.includes('admin') || role.includes('superadmin')) {
    next();
  }else{
    return handleUnauthorizedAccess(res);
  }
};


const rateLimit = require('express-rate-limit');

// Define rate limiter middleware
const loginRateLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 5, 
    message: {
        success: false,
        msg: 'Too many login attempts from this IP, please try again after 15 minutes'
    },
    headers: true, 
});
module.exports = { verifyUser, verifyAuthorization,loginRateLimiter };
