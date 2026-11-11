require('dotenv').config();
const Koa = require('koa');
const Router = require('@koa/router');
const bodyParser = require('koa-bodyparser');
const cors = require('@koa/cors');
const oracledb = require('oracledb');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const { initializeDbPool } = require('./config/db');
const { verifyToken, requireRole } = require('./auth/authweb');

const app = new Koa();
const router = new Router();

app.use(cors());
app.use(bodyParser());

const JWT_SECRET = process.env.JWT_SECRET;

// Реєстрація нового користувача 
router.post('/api/register', async (ctx) => {
    const { email, password } = ctx.request.body;

    if (!email || !password) {
        ctx.status = 400;
        ctx.body = { error: 'Електронна пошта та пароль обов\'язкові' };
        return;
    }

    let connection;
    try {
        connection = await oracledb.getConnection();
        
        // Хешування пароля
        const salt = await bcrypt.genSalt(10);
        const passwordHash = await bcrypt.hash(password, salt);

        // Отримуємо role_id для звичайного користувача ('user')
        const roleResult = await connection.execute(
            `SELECT role_id FROM roles WHERE role_name = 'user'`
        );
        const roleId = roleResult.rows[0].ROLE_ID;

        // Записує користувача в БД
        await connection.execute(
            `INSERT INTO users (email, password_hash, role_id) VALUES (:email, :password_hash, :role_id)`,
            { email: email, password_hash: passwordHash, role_id: roleId },
            { autoCommit: true } // Обов'язково для збереження змін!
        );

        ctx.status = 201;
        ctx.body = { status: 'success', message: 'Користувача успішно зареєстровано' };
    } catch (err) {
        ctx.status = 500;
        // Помилка ORA-00001 означає, що такий email вже є
        if (err.errorNum === 1) {
            ctx.body = { error: 'Користувач з таким email вже існує' };
        } else {
            ctx.body = { error: err.message };
        }
    } finally {
        if (connection) await connection.close();
    }
});

// Вхід та отримання токена
router.post('/api/login', async (ctx) => {
    const { email, password } = ctx.request.body;
    let connection;

    try {
        connection = await oracledb.getConnection();
        
        // Шукаємо користувача та його роль у БД
        const result = await connection.execute(
            `SELECT u.user_id, u.email, u.password_hash, r.role_name 
             FROM users u 
             JOIN roles r ON u.role_id = r.role_id 
             WHERE u.email = :email`,
            { email: email }
        );

        const user = result.rows[0];

        if (!user) {
            ctx.status = 401;
            ctx.body = { error: 'Невірний email або пароль' };
            return;
        }

        // Перевіряє пароль
        const validPassword = await bcrypt.compare(password, user.PASSWORD_HASH);
        if (!validPassword) {
            ctx.status = 401;
            ctx.body = { error: 'Невірний email або пароль' };
            return;
        }

        // Генерує JWT токен
        const token = jwt.sign(
            { user_id: user.USER_ID, role_name: user.ROLE_NAME },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        ctx.body = {
            status: 'success',
            message: 'Успішний вхід',
            token: token,
            role: user.ROLE_NAME
        };
    } catch (err) {
        ctx.status = 500;
        ctx.body = { error: err.message };
    } finally {
        if (connection) await connection.close();
    }
});

router.get('/api/health', (ctx) => {
    ctx.body = { status: 'success', message: 'Сервер працює!' };
});

router.get('/api/rooms', (ctx) => {
    ctx.body = { message: 'Список доступних номерів (відкрито для всіх)' };
});

router.post('/api/reservations', verifyToken, (ctx) => {
    const user = ctx.state.user;
    ctx.body = { message: 'Бронювання успішно створено', userId: user.user_id };
});

router.get('/api/users', verifyToken, requireRole('admin'), async (ctx) => {
    let connection;
    try {
        connection = await oracledb.getConnection();
        const result = await connection.execute(`SELECT user_id, email, role_id FROM users`);
        ctx.body = { status: 'success', data: result.rows };
    } catch (err) {
        ctx.status = 500;
        ctx.body = { error: err.message };
    } finally {
        if (connection) await connection.close();
    }
});

app.use(router.routes());
app.use(router.allowedMethods());

const PORT = process.env.PORT || 3000;

initializeDbPool().then(() => {
    app.listen(PORT, () => {
        console.log(`Server is running on http://localhost:${PORT}`);
    });
});