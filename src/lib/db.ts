// C:\Users\salvaCastro\Desktop\arenaapp-admin\src\lib\db.ts
import mysql from 'mysql2/promise'

let pool: mysql.Pool

export function getDb () {
  if (!pool) {
    pool = mysql.createPool({
      host: process.env.DB_HOST,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_NAME,
      connectionLimit: 10
    })
  }
  return pool
}
