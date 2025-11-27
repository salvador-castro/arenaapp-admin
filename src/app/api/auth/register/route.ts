import { NextRequest, NextResponse } from 'next/server'
import bcrypt from 'bcryptjs'
import mysql from 'mysql2/promise'

const FRONT_ORIGIN = process.env.FRONT_ORIGIN || 'http://localhost:3000'

const pool = mysql.createPool({
  host: '198.27.88.204',
  user: 'jungleco_arenaAppUser',
  password: 'Puntadeleste-3',
  database: 'jungleco_arenaAppBBDD'
})

function corsHeaders(extra: Record<string, string> = {}) {
  return {
    'Access-Control-Allow-Origin': FRONT_ORIGIN,
    'Access-Control-Allow-Methods': 'POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Credentials': 'true',
    ...extra
  }
}

export function OPTIONS() {
  return new NextResponse(null, {
    status: 204,
    headers: corsHeaders()
  })
}

export async function POST(req: NextRequest) {
  try {
    const body = await req.json()
    const { nombre, apellido, email, telefono, password } = body

    if (!nombre || !apellido || !email || !password) {
      return NextResponse.json(
        { error: 'Faltan campos' },
        { status: 400, headers: corsHeaders() }
      )
    }

    const [exists]: any = await pool.query(
      'SELECT id FROM usuarios WHERE email = ? LIMIT 1',
      [email]
    )

    if (exists.length > 0) {
      return NextResponse.json(
        { error: 'El email ya está registrado' },
        { status: 409, headers: corsHeaders() }
      )
    }

    const password_hash = await bcrypt.hash(password, 10)

    await pool.query(
      `INSERT INTO usuarios 
        (nombre, apellido, email, telefono, password_hash, rol, activo, email_verificado, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, 'USER', 1, 0, NOW(), NOW())`,
      [nombre, apellido, email, telefono ?? null, password_hash]
    )

    return NextResponse.json(
      { message: 'Usuario registrado correctamente' },
      { status: 201, headers: corsHeaders() }
    )
  } catch (err) {
    console.error('Error en register:', err)
    return NextResponse.json(
      { error: 'Error interno del servidor' },
      { status: 500, headers: corsHeaders() }
    )
  }
}
