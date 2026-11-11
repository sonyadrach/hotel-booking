
const jwt = require('jsonwebtoken');

// Секретний ключ для підпису токенів 
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
    console.error(' ERROR: No JWT_SECRET in .env!');
    process.exit(1);
}
//  Перевірка наявності та валідності токена (Чи це Авторизований користувач?)
const verifyToken = async (ctx, next) => {
    const authHeader = ctx.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        ctx.status = 401;
        ctx.body = { error: 'Немає доступу. Токен відсутній.' };
        return;
    }

    const token = authHeader.split(' ')[1];

    try {
        // Розшифровує токен. У ньому буде зберігати user_id та role_name
        const decoded = jwt.verify(token, JWT_SECRET);
        ctx.state.user = decoded; // Зберігає дані користувача для наступних функцій
        await next(); // Передає керування далі
    } catch (err) {
        ctx.status = 401;
        ctx.body = { error: 'Недійсний або протермінований токен.' };
    }
};

// Перевірка ролі (Чи це Адміністратор?)
const requireRole = (requiredRole) => {
    return async (ctx, next) => {
        // ctx.state.user встановлюється попереднім middleware (verifyToken)
        const user = ctx.state.user;

        if (!user || user.role_name !== requiredRole) {
            ctx.status = 403; // 403 Forbidden
            ctx.body = { error: `Доступ заборонено. Необхідна роль: ${requiredRole}` };
            return;
        }

        await next();
    };
};

module.exports = {
    verifyToken,
    requireRole
};