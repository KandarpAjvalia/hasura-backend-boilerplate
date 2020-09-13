import express from 'express'
import bodyParser from 'body-parser'
import userController from './controllers/user'
import cookieParser from 'cookie-parser'
import dotenv from 'dotenv'

dotenv.config()

const app = express()
app.use(bodyParser.json())

app.use(cookieParser(process.env.COOKIR_PARSER_SECRET))

const port = 3000

app.post('/register', userController.register)

app.post('/login', userController.login)

app.post('/refresh-token', userController.refreshToken)

app.listen(port, () => {
	return console.log(`server is listening on ${port}`)
})
