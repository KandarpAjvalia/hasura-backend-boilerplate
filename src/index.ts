import express from 'express'
import bodyParser from 'body-parser'
import userController from './controllers/user'
import cookieParser from 'cookie-parser'
import dotenv from 'dotenv'

dotenv.config()

const app = express()
app.use(bodyParser.json())

app.use(cookieParser(process.env.COOKIE_PARSER_SECRET))

const port = process.env.AUTH_SERVER_PORT || 4000

app.get('/', (req, res) => {
	res.json({
		message: 'HomePage'
	})
})

app.post('/register', userController.register)

app.post('/login', userController.login)

app.post('/refresh-token', userController.refreshToken)

app.post('/logout', userController.logout)

app.listen(port, () => {
	return console.log(`server is listening on ${port}`)
})
