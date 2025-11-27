import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import { DateTime } from 'luxon'
import { getDb } from '@/lib/db'

const JWT_SECRET = process.env.JWT_SECRET || 'supersecretkey123'
const SESSION_MINUTES = parseInt(process.env.SESSION_MINUTES ?? '1', 10)
const FRONT_ORIGIN = process.env.FRONT_ORIGIN || 'http://localhost:3000'

function corsBaseHeaders () {
  return {
    'Access-Control-Allow-Origin': FRONT_ORIGIN,
    'Access-Control-Allow-Credentials': 'true'
  }
}

export function OPTIONS () {
  return new NextResponse(null, {
    status: 204,
    headers: {
      ...corsBaseHeaders(),
      'Access-Control-Allow-Methods': 'POST,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type'
    }
  })
}

export async function POST (req: NextRequest) {
  console.log('ADMIN: entró al endpoint /api/auth/login')

  try {
    const { email, password } = await req.json()
    console.log('ADMIN: login con', email)
    console.log('ADMIN: SESSION_MINUTES =', SESSION_MINUTES)

    if (!email || !password) {
      return NextResponse.json(
        { error: 'Email y contraseña son obligatorios' },
        { status: 400, headers: corsBaseHeaders() }
      )
    }

    const db = getDb()

    const [rows] = await db.execute(
      'SELECT id, nombre, email, password_hash, rol FROM usuarios WHERE email = ? LIMIT 1',
      [email]
    )

    const users = rows as Array<{
      id: number
      nombre: string
      email: string
      password_hash: string
      rol: string
    }>

    if (!users.length) {
      return NextResponse.json(
        { error: 'Credenciales inválidas' },
        { status: 401, headers: corsBaseHeaders() }
      )
    }

    const user = users[0]

    const isValid = await bcrypt.compare(password, user.password_hash)
    if (!isValid) {
      return NextResponse.json(
        { error: 'Credenciales inválidas' },
        { status: 401, headers: corsBaseHeaders() }
      )
    }

    // Hora Buenos Aires
    const nowBA = DateTime.now().setZone('America/Argentina/Buenos_Aires')
    const iat = Math.floor(nowBA.toSeconds())
    const exp = Math.floor(nowBA.plus({ minutes: SESSION_MINUTES }).toSeconds())

    const payload = {
      userId: user.id,
      role: user.rol,
      iat,
      exp
    }

    const token = jwt.sign(payload, JWT_SECRET)

    const res = NextResponse.json(
      {
        message: 'Login exitoso',
        user: {
          id: user.id,
          nombre: user.nombre,
          email: user.email,
          role: user.rol
        }
      },
      { status: 200, headers: corsBaseHeaders() }
    )

    const maxAgeSeconds = SESSION_MINUTES * 60

    res.cookies.set('token', token, {
      httpOnly: true,
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production',
      maxAge: maxAgeSeconds,
      path: '/'
    })

    console.log(
      `[LOGIN] Usuario ${user.email} - iat BA: ${nowBA.toISO()} - exp BA: ${nowBA
        .plus({ minutes: SESSION_MINUTES })
        .toISO()}`
    )

    return res
  } catch (error) {
    console.error('Error en /api/auth/login:', error)
    return NextResponse.json(
      { error: 'Error en el servidor' },
      { status: 500, headers: corsBaseHeaders() }
    )
  }
}
