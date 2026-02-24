import mysql from 'mysql2/promise';

// Create the connection to database
export const connection = await mysql.createConnection({
    host: 'localhost',
    user: 'root',
    database: 'auth_db',
    password: 'rohit@032',
});