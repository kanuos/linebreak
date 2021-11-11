import { Router } from "express";
import ProfileController from "../_Contoller/profileController";
import { needsAuthorization, preventAuthorizedUsers } from "../_Middlewares/AuthMiddleware";

const apiRouter = Router();

apiRouter.get("/profile", needsAuthorization, ProfileController.profile)


/**
 * @description
 * - Reset password for logged in user.
 * - Receives old password, new password in request body and user info will be added to body
 * - by auth middleware.
 * - on success send success msg
 * - on failure send error msg
 * @method post
 * @access private
 */
apiRouter.post("/change-password", needsAuthorization, ProfileController.reset)


export default apiRouter;