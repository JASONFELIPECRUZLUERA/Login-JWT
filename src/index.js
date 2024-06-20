import express from 'express'
import { PORT } from './config/config.js'
import authRoutes from './routes/auth.routes.js'

const app = express()
app.use(express.json())

app.use('/api/auth', authRoutes)

app.listen(PORT,()=>console.log(`http://localhost:${PORT}`))