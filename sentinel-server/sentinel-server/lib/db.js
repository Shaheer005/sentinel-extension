// lib/db.js — PostgreSQL connection + schema
import pg from "pg";
const { Pool } = pg;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

export async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS tokens (
      id             SERIAL PRIMARY KEY,
      token          TEXT UNIQUE NOT NULL,
      email          TEXT NOT NULL,
      stripe_sub     TEXT,
      active         BOOLEAN DEFAULT true,
      created_at     TIMESTAMPTZ DEFAULT NOW(),
      requests_today INT DEFAULT 0,
      last_reset     DATE DEFAULT CURRENT_DATE
    );
  `);
  console.log("[DB] Schema ready.");
}

export async function createToken(token, email, stripeSubId) {
  const res = await pool.query(
    `INSERT INTO tokens (token, email, stripe_sub) VALUES ($1,$2,$3) RETURNING *`,
    [token, email, stripeSubId]
  );
  return res.rows[0];
}

export async function validateToken(token) {
  // Reset daily count if new day
  await pool.query(
    `UPDATE tokens SET requests_today=0, last_reset=CURRENT_DATE
     WHERE token=$1 AND last_reset < CURRENT_DATE`,
    [token]
  );
  const res = await pool.query(
    `SELECT * FROM tokens WHERE token=$1 AND active=true`,
    [token]
  );
  return res.rows[0] || null;
}

export async function incrementRequests(token) {
  await pool.query(
    `UPDATE tokens SET requests_today=requests_today+1 WHERE token=$1`,
    [token]
  );
}

export async function deactivateByStripe(stripeSubId) {
  await pool.query(`UPDATE tokens SET active=false WHERE stripe_sub=$1`, [stripeSubId]);
}

export async function reactivateByStripe(stripeSubId) {
  await pool.query(`UPDATE tokens SET active=true WHERE stripe_sub=$1`,  [stripeSubId]);
}

export default pool;
