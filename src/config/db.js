const oracledb = require('oracledb');

oracledb.outFormat = oracledb.OUT_FORMAT_OBJECT;

async function initializeDbPool() {
    try {
        await oracledb.createPool({
            user: process.env.DB_USER,
            password: process.env.DB_PASSWORD,
            connectString: process.env.DB_CONNECTION_STRING,
            poolMin: 2,
            poolMax: 10, // Максимальна кількість одночасних з'єднань
            poolIncrement: 1
        });
        console.log('Oracle Database connection pool started successfully.');
    } catch (err) {
        console.error('Error initializing connection pool:', err);
        process.exit(1);
    }
}

async function closeDbPool() {
    try {
        await oracledb.getPool().close(10);
        console.log('Oracle Database connection pool closed.');
    } catch (err) {
        console.error('Error closing connection pool:', err);
    }
}

module.exports = {
    initializeDbPool,
    closeDbPool
};