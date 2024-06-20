import { Router } from "express";
import { register , me, login } from "../controller/auth.controller.js";

const router = Router()

router.get('/me', me)
router.post('/register', register)
router.post('/login', login)

export default router